#!/usr/bin/env python3
"""
Utility functions for enhanced XSS detection pipeline
"""

import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from dataclasses import asdict


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Set up logging configuration"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    if not log_file:
        log_file = f"logs/xss_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)


def create_output_directories() -> Dict[str, Path]:
    """Create necessary output directories"""
    directories = {
        'screenshots': Path("screenshots"),
        'logs': Path("logs"),
        'results': Path("results"),
        'html_captures': Path("html_captures"),
        'mitm_logs': Path("mitm_logs"),
        'payloads': Path("payloads")
    }
    
    for name, path in directories.items():
        path.mkdir(exist_ok=True)
    
    return directories


def inject_payload_into_url(base_url: str, payload: str, param_name: Optional[str] = None) -> str:
    """Inject payload into URL query parameters"""
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query)
    
    if param_name and param_name in params:
        params[param_name] = [payload]
    elif params:
        # Use the first parameter
        first_param = list(params.keys())[0]
        params[first_param] = [payload]
    else:
        # Add a test parameter
        params['xss'] = [payload]
    
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def extract_forms_from_html(html_content: str, base_url: str) -> List[Dict[str, Any]]:
    """Extract form information from HTML content"""
    forms = []
    
    # Simple regex-based form extraction (could be enhanced with BeautifulSoup)
    form_pattern = r'<form[^>]*>(.*?)</form>'
    input_pattern = r'<input[^>]*>'
    textarea_pattern = r'<textarea[^>]*>.*?</textarea>'
    
    form_matches = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
    
    for i, form_content in enumerate(form_matches):
        form_info = {
            'form_id': i,
            'action': extract_form_action(form_content, base_url),
            'method': extract_form_method(form_content),
            'inputs': [],
            'textareas': []
        }
        
        # Extract inputs
        input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)
        for input_match in input_matches:
            input_info = extract_input_info(input_match)
            if input_info:
                form_info['inputs'].append(input_info)
        
        # Extract textareas
        textarea_matches = re.findall(textarea_pattern, form_content, re.IGNORECASE)
        for textarea_match in textarea_matches:
            textarea_info = extract_textarea_info(textarea_match)
            if textarea_info:
                form_info['textareas'].append(textarea_info)
        
        forms.append(form_info)
    
    return forms


def extract_form_action(form_content: str, base_url: str) -> str:
    """Extract form action URL"""
    action_match = re.search(r'action=["\']([^"\']+)["\']', form_content, re.IGNORECASE)
    if action_match:
        action = action_match.group(1)
        return urljoin(base_url, action)
    return base_url


def extract_form_method(form_content: str) -> str:
    """Extract form method"""
    method_match = re.search(r'method=["\']([^"\']+)["\']', form_content, re.IGNORECASE)
    return method_match.group(1).upper() if method_match else 'GET'


def extract_input_info(input_html: str) -> Optional[Dict[str, str]]:
    """Extract input field information"""
    name_match = re.search(r'name=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
    type_match = re.search(r'type=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
    
    if name_match:
        return {
            'name': name_match.group(1),
            'type': type_match.group(1) if type_match else 'text'
        }
    return None


def extract_textarea_info(textarea_html: str) -> Optional[Dict[str, str]]:
    """Extract textarea field information"""
    name_match = re.search(r'name=["\']([^"\']+)["\']', textarea_html, re.IGNORECASE)
    
    if name_match:
        return {
            'name': name_match.group(1),
            'type': 'textarea'
        }
    return None


def is_xss_payload(text: str) -> bool:
    """Check if text contains common XSS payload patterns"""
    xss_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<img[^>]*onerror',
        r'<svg[^>]*onload',
        r'<iframe[^>]*src',
        r'document\.write',
        r'innerHTML\s*=',
        r'eval\s*\(',
        r'setTimeout\s*\(',
        r'setInterval\s*\('
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    
    return False


def extract_urls_from_html(html_content: str, base_url: str) -> List[str]:
    """Extract URLs from HTML content"""
    urls = set()
    
    # Extract href attributes
    href_pattern = r'href=["\']([^"\']+)["\']'
    href_matches = re.findall(href_pattern, html_content, re.IGNORECASE)
    
    for href in href_matches:
        if not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            absolute_url = urljoin(base_url, href)
            urls.add(absolute_url)
    
    # Extract src attributes
    src_pattern = r'src=["\']([^"\']+)["\']'
    src_matches = re.findall(src_pattern, html_content, re.IGNORECASE)
    
    for src in src_matches:
        if not src.startswith(('data:', 'javascript:')):
            absolute_url = urljoin(base_url, src)
            urls.add(absolute_url)
    
    return list(urls)


def generate_xss_payloads() -> List[str]:
    """Generate common XSS test payloads"""
    return [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<iframe src=javascript:alert("XSS")>',
        '"><script>alert("XSS")</script>',
        '\';alert("XSS");//',
        '<body onload=alert("XSS")>',
        '<input onfocus=alert("XSS") autofocus>',
        '<select onfocus=alert("XSS") autofocus>',
        '<textarea onfocus=alert("XSS") autofocus>',
        '<keygen onfocus=alert("XSS") autofocus>',
        '<video><source onerror="alert(\'XSS\')">',
        '<audio src=x onerror=alert("XSS")>',
        '<details open ontoggle=alert("XSS")>'
    ]


def clean_json_response(response: str) -> str:
    """Clean LLM response to extract JSON from markdown code blocks"""
    cleaned = response.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    return cleaned.strip()


def save_json_results(data: Any, filepath: str, pretty: bool = True) -> None:
    """Save data to JSON file with proper formatting"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    # Convert dataclasses to dict if needed
    if hasattr(data, '__dict__'):
        data = asdict(data)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        if pretty:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        else:
            json.dump(data, f, ensure_ascii=False, default=str)


def load_json_results(filepath: str) -> Any:
    """Load JSON results from file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_timestamp(format_str: str = "%Y%m%d_%H%M%S") -> str:
    """Get current timestamp as string"""
    return datetime.now().strftime(format_str)


def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    return urlparse(url).netloc


def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs are from the same domain"""
    return extract_domain(url1) == extract_domain(url2)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for filesystem safety"""
    # Remove or replace problematic characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    sanitized = re.sub(r'[^\w\-_\.]', '_', sanitized)
    return sanitized[:255]  # Limit length


def get_file_size(filepath: str) -> int:
    """Get file size in bytes"""
    try:
        return os.path.getsize(filepath)
    except OSError:
        return 0


def ensure_directory_exists(directory: str) -> None:
    """Ensure directory exists, create if it doesn't"""
    Path(directory).mkdir(parents=True, exist_ok=True)


class Timer:
    """Context manager for timing operations"""
    
    def __init__(self, description: str = "Operation"):
        self.description = description
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.time()
    
    @property
    def elapsed(self) -> float:
        """Get elapsed time in seconds"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0
    
    def __str__(self) -> str:
        return f"{self.description}: {self.elapsed:.2f} seconds"