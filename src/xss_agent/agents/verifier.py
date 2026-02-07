"""
Dynamic Verification Agent for testing XSS payloads with Playwright
"""
import asyncio
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from playwright.async_api import async_playwright, ConsoleMessage
from agno.agent import Agent

from ..models import VerificationResult
from ..utils.url_utils import inject_payload_into_url


class DynamicVerifierAgent(Agent):
    """Agent responsible for testing payloads with Playwright and providing detailed feedback"""

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.screenshot_dir = Path("screenshots")
        self.screenshot_dir.mkdir(exist_ok=True)

    async def run(self, target_url: str, payload: str, proxy_agent=None) -> VerificationResult:
        """Test a single payload using Playwright with detailed feedback"""
        test_url = inject_payload_into_url(target_url, payload)
        self.logger.info(f"Testing payload: {payload[:50]}...")

        # Create output directories
        os.makedirs("./screenshots", exist_ok=True)
        os.makedirs("./logs", exist_ok=True)
        os.makedirs("./html_captures", exist_ok=True)

        # Check if proxy is available and running
        if proxy_agent and not proxy_agent.running:
            self.logger.info("Proxy agent provided but not running - attempting to start")
            try:
                if proxy_agent.is_available():
                    proxy_agent.start()
                else:
                    self.logger.warning("mitmproxy not available - continuing without proxy")
                    proxy_agent = None
            except Exception as e:
                self.logger.error(f"Failed to start proxy: {e}")
                proxy_agent = None  # Disable proxy for this session
        elif proxy_agent and proxy_agent.running:
            self.logger.info("Using already running proxy for traffic capture")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)

            # Configure browser context with or without proxy
            context_options = {}
            if proxy_agent and proxy_agent.running:
                proxy_url = proxy_agent.get_proxy_url()
                context_options['proxy'] = {'server': proxy_url}
                self.logger.info(f"Browser configured to use proxy: {proxy_url}")

            context = await browser.new_context(**context_options)
            page = await context.new_page()

            # Set up monitoring
            alerts_caught = []
            console_logs = []
            response_status = None
            response_headers = {}

            # Monitor responses
            def handle_response(response):
                nonlocal response_status, response_headers
                if response.url == test_url:
                    response_status = response.status
                    response_headers = response.headers

            page.on("response", handle_response)

            # Monitor dialogs
            async def handle_dialog(dialog):
                alerts_caught.append(dialog.message)
                await dialog.accept()

            page.on("dialog", handle_dialog)

            # Monitor console
            def handle_console(msg: ConsoleMessage):
                console_logs.append({
                    'type': msg.type,
                    'text': msg.text,
                    'location': str(msg.location) if msg.location else None
                })

            page.on("console", handle_console)

            try:
                # Navigate to page with payload
                response = await page.goto(test_url, wait_until='networkidle', timeout=30000)
                if response:
                    response_status = response.status
                    response_headers = response.headers

                # Wait a bit for any delayed execution and proxy capture
                await page.wait_for_timeout(3000)  # Increased for proxy capture

                # Get page content
                page_content = await page.content()
                reflection_found = payload in page_content

                # Save HTML content to file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                html_filename = f"page_content_{timestamp}.html"
                html_file_path = f"./html_captures/{html_filename}"

                with open(html_file_path, 'w', encoding='utf-8') as f:
                    f.write(f"<!-- URL: {test_url} -->\n")
                    f.write(f"<!-- Payload: {payload} -->\n")
                    f.write(f"<!-- Timestamp: {timestamp} -->\n")
                    f.write(f"<!-- Response Status: {response_status} -->\n")
                    f.write("<!-- Response Headers:\n")
                    for key, value in response_headers.items():
                        f.write(f"{key}: {value}\n")
                    f.write("-->\n\n")
                    f.write(page_content)

                # Check if payload executed
                executed = False
                execution_method = None

                if alerts_caught:
                    executed = True
                    execution_method = "alert"
                elif any('XSS' in log.get('text', '') or 'xss' in log.get('text', '').lower() for log in console_logs):
                    executed = True
                    execution_method = "console"
                elif reflection_found and any(tag in payload.lower() for tag in ['<script>', '<svg', '<img', '<iframe']):
                    # Check if script-like elements were rendered
                    script_elements = await page.query_selector_all('script, svg, img[onerror]')
                    if script_elements:
                        executed = True
                        execution_method = "dom"

                # Take screenshot (always take screenshot for both success and failure)
                screenshot_name = f"xss_{timestamp}_{execution_method or 'failed'}.png"
                screenshot_path = f"./screenshots/{screenshot_name}"
                await page.screenshot(path=screenshot_path, full_page=True)

                # Capture proxy data if proxy was used
                proxy_captures = []
                if proxy_agent and proxy_agent.running:
                    try:
                        # Wait a moment for proxy to finalize HAR file
                        await asyncio.sleep(2)

                        # Trigger capture and get entries
                        har_path = proxy_agent.capture_har(timeout=5)
                        proxy_captures = proxy_agent.get_captures()
                        self.logger.info(f"Captured {len(proxy_captures)} proxy entries from {har_path}")
                    except Exception as proxy_error:
                        self.logger.warning(f"Failed to capture proxy data: {proxy_error}")

                result = VerificationResult(
                    url=test_url,
                    payload=payload,
                    executed=executed,
                    reflection_found=reflection_found,
                    execution_method=execution_method,
                    screenshot_path=screenshot_path,
                    timestamp=timestamp,
                    console_logs=console_logs,
                    alerts_caught=alerts_caught,
                    page_content=page_content[:1000] + "..." if len(page_content) > 1000 else page_content,  # Truncate for JSON
                    page_content_file=html_file_path,
                    response_status=response_status,
                    response_headers=response_headers,
                    proxy_captures=proxy_captures
                )

                self.logger.info(f"Verification complete: {'SUCCESS' if executed else 'FAILED'}")
                self.logger.info(f"HTML content saved to: {html_file_path}")
                self.logger.info(f"Screenshot saved to: {screenshot_path}")
                return result

            except Exception as e:
                self.logger.error(f"Verification error: {e}")

                # Still try to take screenshot and save content on error
                try:
                    error_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    error_screenshot = f"./screenshots/error_{error_timestamp}.png"
                    await page.screenshot(path=error_screenshot, full_page=True)

                    error_html = f"./html_captures/error_{error_timestamp}.html"
                    try:
                        page_content = await page.content()
                        with open(error_html, 'w', encoding='utf-8') as f:
                            f.write(f"<!-- ERROR CAPTURE -->\n")
                            f.write(f"<!-- URL: {test_url} -->\n")
                            f.write(f"<!-- Payload: {payload} -->\n")
                            f.write(f"<!-- Error: {e} -->\n")
                            f.write(f"<!-- Timestamp: {error_timestamp} -->\n\n")
                            f.write(page_content)
                    except:
                        page_content = f"Failed to capture content due to error: {e}"
                        with open(error_html, 'w', encoding='utf-8') as f:
                            f.write(page_content)

                except:
                    error_screenshot = None
                    error_html = None
                    page_content = f"Failed to capture due to error: {e}"

                # Try to capture proxy data even on error
                proxy_captures = []
                if proxy_agent and proxy_agent.running:
                    try:
                        await asyncio.sleep(2)
                        har_path = proxy_agent.capture_har(timeout=5)
                        proxy_captures = proxy_agent.get_captures()
                    except Exception as proxy_error:
                        self.logger.warning(f"Failed to capture proxy data on error: {proxy_error}")

                return VerificationResult(
                    url=test_url,
                    payload=payload,
                    executed=False,
                    reflection_found=False,
                    error=str(e),
                    timestamp=datetime.now().strftime("%Y%m%d_%H%M%S"),
                    console_logs=console_logs,
                    alerts_caught=alerts_caught,
                    page_content=page_content,
                    page_content_file=error_html,
                    screenshot_path=error_screenshot,
                    response_status=response_status,
                    response_headers=response_headers,
                    proxy_captures=proxy_captures
                )
            finally:
                await browser.close()