#!/usr/bin/env python3
"""
Forensic Logger Manager - Comprehensive logging for XSS testing with full audit trail

This module provides detailed logging capabilities for every aspect of the XSS testing process,
including LLM interactions, HTTP requests/responses, Playwright verifications, and failure analysis.
All sensitive data is properly handled with redaction and optional encryption.
"""

import asyncio
import json
import logging
import os
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import re
import fcntl
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class SecurityRedactor:
    """Handles redaction of sensitive information from logs and data"""
    
    SENSITIVE_HEADERS = {
        'authorization', 'cookie', 'set-cookie', 'api-key', 'x-api-key', 
        'bearer', 'token', 'x-auth-token', 'x-access-token', 'x-csrf-token'
    }
    
    SENSITIVE_PATTERNS = [
        # API Keys and tokens
        (r'[A-Za-z0-9]{20,}', '<REDACTED_TOKEN>'),
        # AWS-like keys
        (r'AKIA[0-9A-Z]{16}', '<REDACTED_AWS_KEY>'),
        # JWTs
        (r'ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', '<REDACTED_JWT>'),
        # Generic secrets (long base64/hex strings)
        (r'[A-Za-z0-9+/=]{32,}', '<REDACTED_SECRET>'),
        # Interactsh tokens or similar
        (r'[a-z0-9]{10,}\.(interact|burpcollaborator|oast)\.[a-z]{2,}', '<REDACTED_CALLBACK>'),
    ]
    
    @classmethod
    def redact_sensitive(cls, data: Union[str, Dict, List]) -> Union[str, Dict, List]:
        """Redact sensitive information from various data types"""
        if isinstance(data, str):
            return cls._redact_string(data)
        elif isinstance(data, dict):
            return cls._redact_dict(data)
        elif isinstance(data, list):
            return [cls.redact_sensitive(item) for item in data]
        else:
            return data
    
    @classmethod
    def _redact_string(cls, text: str) -> str:
        """Redact sensitive patterns from strings"""
        if not text:
            return text
        
        redacted = text
        for pattern, replacement in cls.SENSITIVE_PATTERNS:
            redacted = re.sub(pattern, replacement, redacted)
        
        return redacted
    
    @classmethod
    def _redact_dict(cls, data: Dict) -> Dict:
        """Redact sensitive information from dictionaries (headers, params, etc)"""
        redacted = {}
        
        for key, value in data.items():
            key_lower = key.lower()
            
            if key_lower in cls.SENSITIVE_HEADERS:
                redacted[key] = '<REDACTED>'
            elif isinstance(value, str) and any(header in key_lower for header in cls.SENSITIVE_HEADERS):
                redacted[key] = '<REDACTED>'
            else:
                redacted[key] = cls.redact_sensitive(value)
        
        return redacted


class EncryptionManager:
    """Manages encryption/decryption of sensitive logging data"""
    
    def __init__(self, key: Optional[str] = None):
        """Initialize encryption manager with optional key"""
        self.key = key
        self.fernet = None
        
        if key:
            self._initialize_encryption(key)
    
    def _initialize_encryption(self, key: str):
        """Initialize Fernet encryption with the provided key"""
        # Derive a proper key from the provided string
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'forensic_logger_salt',  # Fixed salt for consistency
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        self.fernet = Fernet(derived_key)
    
    def encrypt(self, data: str) -> bytes:
        """Encrypt string data, returns encrypted bytes"""
        if not self.fernet:
            raise ValueError("Encryption not initialized")
        
        return self.fernet.encrypt(data.encode('utf-8'))
    
    def decrypt(self, encrypted_data: bytes) -> str:
        """Decrypt encrypted bytes back to string"""
        if not self.fernet:
            raise ValueError("Encryption not initialized")
        
        return self.fernet.decrypt(encrypted_data).decode('utf-8')
    
    @property
    def is_enabled(self) -> bool:
        """Check if encryption is properly initialized"""
        return self.fernet is not None


class AtomicFileWriter:
    """Provides atomic file writing operations with proper locking"""
    
    @staticmethod
    def write_file(filepath: Union[str, Path], content: str, mode: str = 'w') -> None:
        """Atomically write content to file"""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        # Write to temporary file first
        with tempfile.NamedTemporaryFile(
            mode=mode, 
            dir=filepath.parent, 
            prefix=f'.{filepath.name}.tmp',
            delete=False,
            encoding='utf-8' if 'b' not in mode else None
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(content)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        
        # Atomic rename
        tmp_path.rename(filepath)
    
    @staticmethod
    def write_binary_file(filepath: Union[str, Path], content: bytes) -> None:
        """Atomically write binary content to file"""
        AtomicFileWriter.write_file(filepath, content, mode='wb')
    
    @staticmethod
    @contextmanager
    def append_with_lock(filepath: Union[str, Path]):
        """Context manager for thread-safe appending to files"""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'a', encoding='utf-8') as f:
            # Use file locking for concurrent access
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                yield f
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


class ForensicLoggerManager:
    """
    Comprehensive forensic logging manager for XSS testing with full audit trail
    
    Provides detailed logging of:
    - Every LLM prompt and response (raw + redacted)
    - Every HTTP request/response
    - Every Playwright verification
    - Every payload attempt and result
    - Failure analysis reports
    - Replay attempts
    """
    
    def __init__(
        self, 
        base_log_dir: str = "./logs",
        save_raw_llm: bool = False,
        retention_days: int = 30,
        redact_full_bodies: bool = False
    ):
        """
        Initialize forensic logging manager
        
        Args:
            base_log_dir: Base directory for all logs
            save_raw_llm: Whether to save raw LLM responses (requires LLM_RAW_KEY env var for encryption)
            retention_days: Number of days to retain logs
            redact_full_bodies: Whether to redact full HTTP request/response bodies
        """
        self.base_log_dir = Path(base_log_dir)
        self.save_raw_llm = save_raw_llm
        self.retention_days = retention_days
        self.redact_full_bodies = redact_full_bodies
        
        # Initialize encryption if key is provided
        raw_key = os.environ.get('LLM_RAW_KEY')
        self.encryption = EncryptionManager(raw_key) if raw_key else None
        
        # Setup logging
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Warn if raw LLM saving enabled without encryption
        if self.save_raw_llm and not self.encryption:
            self.logger.warning(
                "Raw LLM response saving enabled without LLM_RAW_KEY encryption! "
                "Raw responses will be stored unencrypted."
            )
        
        # Current correlation ID for the active scan
        self.current_cid: Optional[str] = None
        self.current_run_dir: Optional[Path] = None
        
        # Counters for unique IDs
        self._attempt_counter = 0
        self._llm_counter = 0
        self._request_counter = 0
        self._verification_counter = 0
        
        # Thread lock for counter operations
        self._lock = threading.Lock()
        
        # Ensure base directory exists
        self.base_log_dir.mkdir(parents=True, exist_ok=True)
    
    def start_run(self, target_url: str = None) -> str:
        """
        Start a new logging run with unique correlation ID
        
        Args:
            target_url: Optional target URL for context
            
        Returns:
            Correlation ID for this run
        """
        self.current_cid = str(uuid.uuid4())[:8]  # Short UUID for readability
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_id = f"{timestamp}_{self.current_cid}"
        
        self.current_run_dir = self.base_log_dir / run_id
        self.current_run_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        subdirs = [
            'nuclei', 'proxy', 'playwright', 'attempts', 'replay', 'results',
            'llm/raw', 'llm/redacted'
        ]
        for subdir in subdirs:
            (self.current_run_dir / subdir).mkdir(parents=True, exist_ok=True)
        
        # Set proper permissions on raw LLM directory
        if self.save_raw_llm:
            raw_dir = self.current_run_dir / 'llm/raw'
            os.chmod(raw_dir, 0o700)  # Only owner can read/write/execute
        
        # Initialize log files
        self._setup_run_logging()
        
        # Log run start
        self.log_event('run.started', {
            'correlation_id': self.current_cid,
            'run_id': run_id,
            'target_url': target_url,
            'timestamp': datetime.now().isoformat(),
            'config': {
                'save_raw_llm': self.save_raw_llm,
                'retention_days': self.retention_days,
                'redact_full_bodies': self.redact_full_bodies,
                'encryption_enabled': self.encryption.is_enabled if self.encryption else False
            }
        })
        
        self.logger.info(f"Started forensic logging run: {run_id}")
        return self.current_cid
    
    def _setup_run_logging(self):
        """Setup logging configuration for the current run"""
        if not self.current_run_dir:
            raise ValueError("No active run - call start_run() first")
        
        # Setup rotating file handler for human-readable logs
        log_file = self.current_run_dir / 'agent.log'
        
        # Remove existing handlers for this logger to avoid duplicates
        logger = logging.getLogger('forensic_audit')
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Add file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.setLevel(logging.DEBUG)
        
        # Store reference
        self.audit_logger = logger
    
    def finish_run(self, results: Dict[str, Any] = None):
        """
        Finish the current logging run
        
        Args:
            results: Optional final results summary
        """
        if not self.current_cid:
            return
        
        # Save final results
        if results:
            results_file = self.current_run_dir / 'results' / f'{self.current_cid}.json'
            AtomicFileWriter.write_file(
                results_file,
                json.dumps(results, indent=2, default=str)
            )
        
        # Log run completion
        self.log_event('run.finished', {
            'correlation_id': self.current_cid,
            'timestamp': datetime.now().isoformat(),
            'results_summary': results
        })
        
        self.logger.info(f"Finished forensic logging run: {self.current_cid}")
        
        # Clean up old logs if retention is set
        if self.retention_days > 0:
            self._cleanup_old_logs()
        
        # Reset state
        self.current_cid = None
        self.current_run_dir = None
        self._attempt_counter = 0
        self._llm_counter = 0
        self._request_counter = 0
        self._verification_counter = 0
    
    def log_attempt_started(self, attempt_id: str, vulnerability_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log the start of a payload attempt
        
        Args:
            attempt_id: Unique identifier for this attempt
            vulnerability_id: ID of the vulnerability being tested
            context: Context information for the attempt
            
        Returns:
            Attempt metadata for tracking
        """
        if not self.current_cid:
            raise ValueError("No active run - call start_run() first")
        
        with self._lock:
            self._attempt_counter += 1
            attempt_number = self._attempt_counter
        
        attempt_data = {
            'attempt_id': attempt_id,
            'attempt_number': attempt_number,
            'vulnerability_id': vulnerability_id,
            'correlation_id': self.current_cid,
            'context': SecurityRedactor.redact_sensitive(context),
            'status': 'started',
            'timestamp': datetime.now().isoformat()
        }
        
        # Log event
        self.log_event('attempt.started', attempt_data)
        
        return attempt_data
    
    def log_llm_interaction(
        self, 
        prompt: str, 
        response: str, 
        model: str = None,
        attempt_id: str = None,
        interaction_type: str = 'generation'
    ) -> Dict[str, str]:
        """
        Log LLM prompt and response with proper handling of sensitive data
        
        Args:
            prompt: The prompt sent to LLM
            response: The raw response from LLM
            model: Model name used
            attempt_id: Associated attempt ID
            interaction_type: Type of interaction (generation, improvement, analysis)
            
        Returns:
            Dictionary with file paths for prompt and response
        """
        if not self.current_cid:
            raise ValueError("No active run - call start_run() first")
        
        with self._lock:
            self._llm_counter += 1
            llm_id = self._llm_counter
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        base_name = f"llm_{llm_id}_{timestamp}"
        
        # File paths
        prompt_file = f"llm/redacted/prompt_{base_name}.txt"
        response_redacted_file = f"llm/redacted/resp_{base_name}.txt"
        response_raw_file = f"llm/raw/resp_{base_name}.txt" if self.save_raw_llm else None
        
        # Save redacted prompt (always saved)
        redacted_prompt = SecurityRedactor.redact_sensitive(prompt)
        AtomicFileWriter.write_file(
            self.current_run_dir / prompt_file,
            redacted_prompt
        )
        
        # Save redacted response (always saved)
        redacted_response = SecurityRedactor.redact_sensitive(response)
        AtomicFileWriter.write_file(
            self.current_run_dir / response_redacted_file,
            redacted_response
        )
        
        # Save raw response if enabled
        if self.save_raw_llm:
            raw_path = self.current_run_dir / response_raw_file
            
            if self.encryption and self.encryption.is_enabled:
                # Encrypt raw response
                encrypted_data = self.encryption.encrypt(response)
                AtomicFileWriter.write_binary_file(raw_path, encrypted_data)
                # Set secure permissions
                os.chmod(raw_path, 0o600)
            else:
                # Save unencrypted (with warning already issued in __init__)
                AtomicFileWriter.write_file(raw_path, response)
                # Set secure permissions anyway
                os.chmod(raw_path, 0o600)
        
        # Parse JSON from response if possible
        llm_parsed_json = None
        try:
            # Try to extract JSON from response
            cleaned_response = self._clean_json_response(redacted_response)
            if cleaned_response.strip():
                llm_parsed_json = json.loads(cleaned_response)
        except (json.JSONDecodeError, ValueError):
            pass  # Not JSON or invalid JSON
        
        # Log event
        event_data = {
            'interaction_id': llm_id,
            'attempt_id': attempt_id,
            'model': model,
            'interaction_type': interaction_type,
            'prompt_file': prompt_file,
            'response_redacted_file': response_redacted_file,
            'response_raw_file': response_raw_file if self.save_raw_llm else None,
            'response_encrypted': self.encryption.is_enabled if self.encryption else False,
            'llm_parsed_json': llm_parsed_json,
            'timestamp': datetime.now().isoformat()
        }
        
        self.log_event('llm.interaction', event_data)
        
        return {
            'prompt_file': prompt_file,
            'response_redacted_file': response_redacted_file,
            'response_raw_file': response_raw_file,
            'llm_parsed_json': llm_parsed_json
        }
    
    def log_http_request_response(
        self, 
        request: Dict[str, Any], 
        response: Dict[str, Any], 
        attempt_id: str = None
    ) -> str:
        """
        Log HTTP request and response data
        
        Args:
            request: Request data (method, url, headers, body)
            response: Response data (status, headers, body)
            attempt_id: Associated attempt ID
            
        Returns:
            File path where the request/response was saved
        """
        if not self.current_cid:
            raise ValueError("No active run - call start_run() first")
        
        with self._lock:
            self._request_counter += 1
            request_id = self._request_counter
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        
        # Prepare data for saving
        if self.redact_full_bodies:
            # Redact full bodies, keep only size info
            request_data = request.copy()
            response_data = response.copy()
            
            if 'body' in request_data:
                body_size = len(request_data['body']) if request_data['body'] else 0
                request_data['body'] = f"<REDACTED_BODY_SIZE_{body_size}>"
            
            if 'body' in response_data:
                body_size = len(response_data['body']) if response_data['body'] else 0
                response_data['body'] = f"<REDACTED_BODY_SIZE_{body_size}>"
        else:
            request_data = request.copy()
            response_data = response.copy()
        
        # Always redact sensitive headers
        if 'headers' in request_data:
            request_data['headers'] = SecurityRedactor.redact_sensitive(request_data['headers'])
        if 'headers' in response_data:
            response_data['headers'] = SecurityRedactor.redact_sensitive(response_data['headers'])
        
        # Save request
        request_file = f"replay/request_{request_id}_{timestamp}.json"
        AtomicFileWriter.write_file(
            self.current_run_dir / request_file,
            json.dumps(request_data, indent=2, default=str)
        )
        
        # Save response
        response_file = f"replay/response_{request_id}_{timestamp}.json"
        AtomicFileWriter.write_file(
            self.current_run_dir / response_file,
            json.dumps(response_data, indent=2, default=str)
        )
        
        # Log event
        event_data = {
            'request_id': request_id,
            'attempt_id': attempt_id,
            'request_file': request_file,
            'response_file': response_file,
            'method': request_data.get('method'),
            'url': request_data.get('url'),
            'status_code': response_data.get('status'),
            'timestamp': datetime.now().isoformat()
        }
        
        self.log_event('http.request_response', event_data)
        
        return request_file
    
    def log_playwright_verification(
        self, 
        verification_data: Dict[str, Any], 
        attempt_id: str = None
    ) -> Dict[str, str]:
        """
        Log Playwright verification results including screenshots and HTML captures
        
        Args:
            verification_data: Playwright verification result data
            attempt_id: Associated attempt ID
            
        Returns:
            Dictionary with paths to saved artifacts
        """
        if not self.current_cid:
            raise ValueError("No active run - call start_run() first")
        
        with self._lock:
            self._verification_counter += 1
            verification_id = self._verification_counter
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        base_name = f"verification_{verification_id}_{timestamp}"
        
        artifacts = {}
        
        # Save screenshot if provided
        if 'screenshot_path' in verification_data and verification_data['screenshot_path']:
            orig_screenshot = Path(verification_data['screenshot_path'])
            if orig_screenshot.exists():
                new_screenshot = f"playwright/screenshot_{base_name}.png"
                screenshot_path = self.current_run_dir / new_screenshot
                
                # Copy screenshot to our directory
                with open(orig_screenshot, 'rb') as src:
                    AtomicFileWriter.write_binary_file(screenshot_path, src.read())
                
                artifacts['screenshot'] = new_screenshot
        
        # Save HTML content if provided
        if 'page_content' in verification_data and verification_data['page_content']:
            html_file = f"playwright/html_{base_name}.html"
            AtomicFileWriter.write_file(
                self.current_run_dir / html_file,
                verification_data['page_content']
            )
            artifacts['html'] = html_file
        
        # Save console logs
        if 'console_logs' in verification_data and verification_data['console_logs']:
            console_file = f"playwright/console_{base_name}.json"
            AtomicFileWriter.write_file(
                self.current_run_dir / console_file,
                json.dumps(verification_data['console_logs'], indent=2, default=str)
            )
            artifacts['console'] = console_file
        
        # Extract key verification metrics
        verification_summary = {
            'verification_id': verification_id,
            'attempt_id': attempt_id,
            'url': verification_data.get('url'),
            'payload': verification_data.get('payload'),
            'executed': verification_data.get('executed', False),
            'reflection_found': verification_data.get('reflection_found', False),
            'execution_method': verification_data.get('execution_method'),
            'response_status': verification_data.get('response_status'),
            'error': verification_data.get('error'),
            'dialogs': verification_data.get('alerts_caught', []),
            'artifacts': artifacts,
            'timestamp': datetime.now().isoformat()
        }
        
        # Log event
        self.log_event('verification.completed', verification_summary)
        
        return artifacts
    
    def log_failure_analysis(
        self, 
        payload: str, 
        failure_report: Dict[str, Any], 
        attempt_id: str = None
    ):
        """
        Log failure analysis results
        
        Args:
            payload: The payload that failed
            failure_report: FailureAnalyzer report
            attempt_id: Associated attempt ID
        """
        if not self.current_cid:
            raise ValueError("No active run - call start_run() first")
        
        event_data = {
            'attempt_id': attempt_id,
            'payload': payload,
            'failure_reason': failure_report.get('reason'),
            'failure_details': failure_report.get('details'),
            'confidence': failure_report.get('confidence'),
            'timestamp': datetime.now().isoformat()
        }
        
        self.log_event('failure.analysis', event_data)
    
    def log_attempt_finished(
        self, 
        attempt_id: str, 
        payload: str, 
        result: str, 
        artifacts: Dict[str, Any] = None
    ):
        """
        Log completion of a payload attempt with all artifacts
        
        Args:
            attempt_id: Unique identifier for this attempt
            payload: The payload that was tested
            result: Result status (success/failure/error)
            artifacts: Dictionary of artifact paths and data
        """
        if not self.current_cid:
            raise ValueError("No active run - call start_run() first")
        
        # Create comprehensive attempt record
        attempt_record = {
            'attempt_id': attempt_id,
            'correlation_id': self.current_cid,
            'payload': payload,
            'result': result,
            'artifacts': artifacts or {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Save individual attempt file
        attempt_file = f"attempt_{self._attempt_counter}_{attempt_id}.json"
        AtomicFileWriter.write_file(
            self.current_run_dir / 'attempts' / attempt_file,
            json.dumps(attempt_record, indent=2, default=str)
        )
        
        # Log event
        event_data = attempt_record.copy()
        event_data['attempt_file'] = f"attempts/{attempt_file}"
        
        self.log_event('attempt.finished', event_data)
    
    def log_event(self, event_type: str, payload: Dict[str, Any]):
        """
        Log a structured event to events.jsonl
        
        Args:
            event_type: Type of event (e.g., 'attempt.started', 'llm.interaction')
            payload: Event data payload
        """
        if not self.current_cid:
            return  # Silently ignore if no active run
        
        event = {
            'event_type': event_type,
            'correlation_id': self.current_cid,
            'timestamp': datetime.now().isoformat(),
            'payload': payload
        }
        
        # Append to events.jsonl with thread safety
        events_file = self.current_run_dir / 'events.jsonl'
        with AtomicFileWriter.append_with_lock(events_file) as f:
            f.write(json.dumps(event, default=str) + '\n')
        
        # Also log to human-readable log
        if hasattr(self, 'audit_logger'):
            self.audit_logger.info(f"{event_type}: {json.dumps(payload, default=str)}")
    
    def _clean_json_response(self, response: str) -> str:
        """Clean LLM response to extract JSON content"""
        if not response:
            return ""
        
        cleaned = response.strip()
        
        # Remove markdown code blocks
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        
        # Find JSON boundaries
        start_idx = cleaned.find('{')
        end_idx = cleaned.rfind('}')
        
        if start_idx != -1 and end_idx != -1 and start_idx <= end_idx:
            cleaned = cleaned[start_idx:end_idx + 1]
        
        return cleaned.strip()
    
    def _cleanup_old_logs(self):
        """Clean up logs older than retention period"""
        if self.retention_days <= 0:
            return
        
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        
        try:
            for run_dir in self.base_log_dir.iterdir():
                if not run_dir.is_dir():
                    continue
                
                # Extract timestamp from directory name (format: YYYYMMDD_HHMMSS_cid)
                try:
                    date_part = run_dir.name.split('_')[0] + '_' + run_dir.name.split('_')[1]
                    run_date = datetime.strptime(date_part, "%Y%m%d_%H%M%S")
                    
                    if run_date < cutoff_date:
                        # Remove old run directory
                        import shutil
                        shutil.rmtree(run_dir)
                        self.logger.info(f"Cleaned up old log directory: {run_dir}")
                        
                except (ValueError, IndexError):
                    # Skip directories that don't match expected format
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error during log cleanup: {e}")
    
    def get_run_summary(self) -> Dict[str, Any]:
        """Get summary of current run"""
        if not self.current_cid or not self.current_run_dir:
            return {}
        
        summary = {
            'correlation_id': self.current_cid,
            'run_directory': str(self.current_run_dir),
            'counters': {
                'attempts': self._attempt_counter,
                'llm_interactions': self._llm_counter,
                'http_requests': self._request_counter,
                'verifications': self._verification_counter
            }
        }
        
        # Count files in each directory
        for subdir in ['attempts', 'llm/raw', 'llm/redacted', 'replay', 'playwright']:
            dir_path = self.current_run_dir / subdir
            if dir_path.exists():
                summary[f'{subdir.replace("/", "_")}_files'] = len(list(dir_path.glob('*')))
        
        return summary


# Convenience functions for backwards compatibility
def get_logger_manager(
    save_raw_llm: bool = False,
    retention_days: int = 30,
    redact_full_bodies: bool = False
) -> ForensicLoggerManager:
    """Get a configured ForensicLoggerManager instance"""
    return ForensicLoggerManager(
        save_raw_llm=save_raw_llm,
        retention_days=retention_days,
        redact_full_bodies=redact_full_bodies
    )


# Global instance for easy access
_global_logger_manager: Optional[ForensicLoggerManager] = None


def initialize_global_logger(
    save_raw_llm: bool = False,
    retention_days: int = 30,
    redact_full_bodies: bool = False
) -> ForensicLoggerManager:
    """Initialize and return global logger manager instance"""
    global _global_logger_manager
    _global_logger_manager = get_logger_manager(
        save_raw_llm=save_raw_llm,
        retention_days=retention_days,
        redact_full_bodies=redact_full_bodies
    )
    return _global_logger_manager


def get_global_logger() -> Optional[ForensicLoggerManager]:
    """Get the global logger manager instance"""
    return _global_logger_manager