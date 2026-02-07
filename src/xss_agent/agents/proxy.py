"""
Proxy Agent for HTTP traffic capture using mitmproxy
"""
import json
import logging
import os
import signal
import subprocess
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import httpx

from ..models.verification import ProxyCaptureEntry


class ProxyAgent:
    """Agent responsible for capturing HTTP traffic using mitmproxy and providing replay functionality"""

    def __init__(self, bind_host="127.0.0.1", bind_port=8080, snapshot_dir="./proxy_captures", whitelist=None):
        """
        Initialize ProxyAgent

        Args:
            bind_host: Host to bind proxy server to
            bind_port: Port to bind proxy server to
            snapshot_dir: Directory to save capture files
            whitelist: List of allowed hosts (default: localhost only for safety)
        """
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.snapshot_dir = Path(snapshot_dir)
        self.snapshot_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(self.__class__.__name__)

        # Safety whitelist - default to localhost only
        self.whitelist = whitelist or ["127.0.0.1", "localhost"]
        if not self.whitelist:
            self.logger.warning("No whitelist specified - this could capture external traffic!")

        self.proxy_process = None
        self.capture_file = None
        self.captures = []
        self.running = False

        # Try to detect mitmproxy availability
        self.mitmdump_path = self._find_mitmdump()
        if not self.mitmdump_path:
            self.logger.warning("mitmdump not found - proxy functionality will be limited")

    def _find_mitmdump(self) -> Optional[str]:
        """Find mitmdump executable"""
        try:
            result = subprocess.run(['which', 'mitmdump'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Try common locations
        common_paths = [
            '/usr/local/bin/mitmdump',
            '/usr/bin/mitmdump',
            '~/.local/bin/mitmdump'
        ]

        for path in common_paths:
            expanded_path = Path(path).expanduser()
            if expanded_path.exists():
                return str(expanded_path)

        return None

    def start(self) -> None:
        """Start mitmproxy in background"""
        if self.running:
            self.logger.warning("Proxy already running")
            return

        if not self.mitmdump_path:
            raise Exception("mitmdump not available - cannot start proxy")

        # Generate unique capture file name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.capture_file = self.snapshot_dir / f"capture_{timestamp}.har"

        # Create mitmproxy command with proper HAR addon
        cmd = [
            self.mitmdump_path,
            '--listen-host', self.bind_host,
            '--listen-port', str(self.bind_port),
            '--set', f'hardump={self.capture_file}',
            '--set', 'confdir=/tmp/mitmproxy',
            '--quiet'
        ]

        # Add host filtering if whitelist is specified
        if self.whitelist:
            # Create host filter - allow only whitelisted hosts
            host_filter = ' or '.join([f'~d {host}' for host in self.whitelist])
            cmd.extend(['--set', f'view_filter={host_filter}'])

        self.logger.info(f"Starting mitmproxy on {self.bind_host}:{self.bind_port}")
        self.logger.info(f"Capture file: {self.capture_file}")
        self.logger.info(f"Whitelist: {self.whitelist}")

        try:
            # Start proxy in background
            self.proxy_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Create new process group
            )

            # Wait a moment for startup
            time.sleep(2)

            # Check if process is still running
            if self.proxy_process.poll() is not None:
                stdout, stderr = self.proxy_process.communicate()
                raise Exception(f"mitmproxy failed to start: {stderr.decode()}")

            self.running = True
            self.logger.info("Proxy started successfully")

        except Exception as e:
            self.logger.error(f"Failed to start proxy: {e}")
            if self.proxy_process:
                try:
                    os.killpg(os.getpgid(self.proxy_process.pid), signal.SIGTERM)
                except:
                    pass
                self.proxy_process = None
            raise

    def stop(self) -> None:
        """Stop mitmproxy and flush captures"""
        if not self.running or not self.proxy_process:
            self.logger.warning("Proxy not running")
            return

        self.logger.info("Stopping proxy...")

        try:
            # Send SIGTERM to process group
            os.killpg(os.getpgid(self.proxy_process.pid), signal.SIGTERM)

            # Wait for clean shutdown
            try:
                self.proxy_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.logger.warning("Proxy didn't stop cleanly, forcing termination")
                os.killpg(os.getpgid(self.proxy_process.pid), signal.SIGKILL)
                self.proxy_process.wait()

        except Exception as e:
            self.logger.error(f"Error stopping proxy: {e}")
        finally:
            self.proxy_process = None
            self.running = False
            self.logger.info("Proxy stopped")

    def capture_har(self, timeout: int = 30) -> str:
        """
        Trigger capture and return path to saved HAR file

        Args:
            timeout: Maximum time to wait for capture file

        Returns:
            Path to HAR file
        """
        if not self.running:
            raise Exception("Proxy not running - call start() first")

        if not self.capture_file:
            raise Exception("No capture file configured")

        # Wait for HAR file to appear and have content
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.capture_file.exists() and self.capture_file.stat().st_size > 0:
                # Give a moment for final writes
                time.sleep(1)
                return str(self.capture_file)
            time.sleep(0.5)

        # Return path even if file doesn't exist yet (might be created later)
        return str(self.capture_file)

    def get_captures(self) -> List[ProxyCaptureEntry]:
        """
        Parse latest HAR file(s) into ProxyCaptureEntry objects

        Returns:
            List of captured request/response pairs
        """
        if not self.capture_file:
            self.logger.warning("No capture file configured")
            return []

        # Check if file exists and has content
        if not self.capture_file.exists():
            self.logger.warning(f"Capture file does not exist: {self.capture_file}")
            return []

        if self.capture_file.stat().st_size == 0:
            self.logger.warning(f"Capture file is empty: {self.capture_file}")
            return []

        try:
            with open(self.capture_file, 'r') as f:
                har_data = json.load(f)

            entries = []
            har_entries = har_data.get('log', {}).get('entries', [])

            for har_entry in har_entries:
                try:
                    # Extract request data
                    request_data = {
                        'method': har_entry['request']['method'],
                        'url': har_entry['request']['url'],
                        'headers': {h['name']: h['value'] for h in har_entry['request']['headers']},
                        'body': har_entry['request'].get('postData', {}).get('text', '')
                    }

                    # Extract response data
                    response_data = {
                        'status': har_entry['response']['status'],
                        'headers': {h['name']: h['value'] for h in har_entry['response']['headers']},
                        'body': har_entry['response']['content'].get('text', '')
                    }

                    # Check whitelist
                    url_host = urlparse(request_data['url']).hostname
                    if self.whitelist and url_host not in self.whitelist:
                        self.logger.debug(f"Skipping non-whitelisted host: {url_host}")
                        continue

                    entry = ProxyCaptureEntry(
                        id=str(uuid.uuid4()),
                        timestamp=har_entry['startedDateTime'],
                        request=request_data,
                        response=response_data,
                        raw_har_entry=har_entry
                    )

                    entries.append(entry)

                except Exception as e:
                    self.logger.warning(f"Error parsing HAR entry: {e}")
                    continue

            self.captures = entries
            self.logger.info(f"Parsed {len(entries)} capture entries")
            return entries

        except Exception as e:
            self.logger.error(f"Error reading HAR file: {e}")
            return []

    def replay_request(self, entry_id: str, modified_request: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Replay a stored request with optional modifications

        Args:
            entry_id: ID of the capture entry to replay
            modified_request: Optional modifications to apply

        Returns:
            Response data or error information
        """
        # Find the entry
        target_entry = None
        for entry in self.captures:
            if entry.id == entry_id:
                target_entry = entry
                break

        if not target_entry:
            raise Exception(f"Capture entry {entry_id} not found")

        # Build request from stored entry
        request_data = target_entry.request.copy()

        # Apply modifications if provided
        if modified_request:
            request_data.update(modified_request)

        # Check whitelist for replay
        url_host = urlparse(request_data['url']).hostname
        if self.whitelist and url_host not in self.whitelist:
            raise Exception(f"Replay blocked: {url_host} not in whitelist {self.whitelist}")

        self.logger.info(f"Replaying request to {request_data['url']}")

        try:
            # Use httpx to replay the request
            with httpx.Client(timeout=30.0) as client:
                response = client.request(
                    method=request_data['method'],
                    url=request_data['url'],
                    headers=request_data.get('headers', {}),
                    content=request_data.get('body', '')
                )

                return {
                    'status': response.status_code,
                    'headers': dict(response.headers),
                    'body': response.text,
                    'timestamp': datetime.now().isoformat()
                }

        except Exception as e:
            self.logger.error(f"Error replaying request: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def clear_captures(self) -> None:
        """Remove old capture files from disk"""
        try:
            # Remove all .har files in snapshot directory
            for har_file in self.snapshot_dir.glob("*.har"):
                try:
                    har_file.unlink()
                    self.logger.debug(f"Removed {har_file}")
                except Exception as e:
                    self.logger.warning(f"Failed to remove {har_file}: {e}")

            # Clear in-memory captures
            self.captures = []
            self.logger.info("Cleared all captures")

        except Exception as e:
            self.logger.error(f"Error clearing captures: {e}")

    def get_proxy_url(self) -> str:
        """Get the proxy URL for configuring clients"""
        return f"http://{self.bind_host}:{self.bind_port}"

    def is_available(self) -> bool:
        """Check if mitmproxy is available"""
        return self.mitmdump_path is not None

    def __del__(self):
        """Cleanup on destruction"""
        if self.running:
            self.stop()