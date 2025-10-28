#!/usr/bin/env python3
"""
Traffic analyzer for identifying XSS vulnerabilities from intercepted data
"""

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict, Counter

from core.models import MITMInterceptionResult, XSSType, XSSFinding, DetectionMethod
from core.utils import is_xss_payload


class TrafficAnalyzer:
    """Analyzes intercepted traffic to identify XSS vulnerabilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Patterns for different types of XSS
        self.reflected_xss_indicators = [
            r'<script[^>]*>.*?alert.*?</script>',
            r'javascript:alert\(',
            r'on\w+\s*=\s*["\'].*?alert.*?["\']',
            r'<img[^>]*onerror\s*=.*?alert'
        ]
        
        self.stored_xss_indicators = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<svg[^>]*onload'
        ]
        
        self.dom_xss_indicators = [
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'location\.hash',
            r'location\.search'
        ]
    
    def analyze_traffic_session(self, intercepted_data: List[MITMInterceptionResult]) -> Dict[str, Any]:
        """Analyze a complete traffic session for XSS vulnerabilities"""
        
        analysis_results = {
            'session_summary': self._generate_session_summary(intercepted_data),
            'reflected_xss': self._detect_reflected_xss(intercepted_data),
            'stored_xss': self._detect_stored_xss(intercepted_data),
            'dom_xss': self._detect_dom_xss(intercepted_data),
            'vulnerability_timeline': self._create_vulnerability_timeline(intercepted_data),
            'attack_vectors': self._identify_attack_vectors(intercepted_data),
            'recommendations': self._generate_recommendations(intercepted_data)
        }
        
        return analysis_results
    
    def _generate_session_summary(self, data: List[MITMInterceptionResult]) -> Dict[str, Any]:
        """Generate summary statistics for the session"""
        
        if not data:
            return {'total_requests': 0}
        
        # Basic statistics
        total_requests = len(data)
        unique_urls = len(set(item.request_url for item in data))
        methods = Counter(item.request_method for item in data)
        status_codes = Counter(item.response_status for item in data if item.response_status)
        
        # Payload statistics
        requests_with_payloads = [item for item in data if item.injected_payload]
        reflected_payloads = [item for item in data if item.payload_reflected]
        stored_payload_candidates = [item for item in data if item.payload_stored]
        
        # Session information
        sessions = set(item.session_id for item in data if item.session_id)
        
        # Time analysis
        timestamps = [datetime.fromisoformat(item.timestamp) for item in data if item.timestamp]
        if timestamps:
            session_start = min(timestamps)
            session_end = max(timestamps)
            duration = (session_end - session_start).total_seconds()
        else:
            session_start = session_end = None
            duration = 0
        
        return {
            'total_requests': total_requests,
            'unique_urls': unique_urls,
            'http_methods': dict(methods),
            'status_codes': dict(status_codes),
            'requests_with_payloads': len(requests_with_payloads),
            'reflected_payloads': len(reflected_payloads),
            'stored_payload_candidates': len(stored_payload_candidates),
            'unique_sessions': len(sessions),
            'session_duration_seconds': duration,
            'session_start': session_start.isoformat() if session_start else None,
            'session_end': session_end.isoformat() if session_end else None
        }
    
    def _detect_reflected_xss(self, data: List[MITMInterceptionResult]) -> List[Dict[str, Any]]:
        """Detect reflected XSS vulnerabilities"""
        
        reflected_xss_findings = []
        
        for item in data:
            if not (item.injected_payload and item.response_body):
                continue
            
            # Check if payload is reflected and potentially executable
            if item.payload_reflected:
                severity = self._assess_xss_severity(item.injected_payload, item.response_body)
                context = self._analyze_injection_context(item.injected_payload, item.response_body)
                
                finding = {
                    'url': item.request_url,
                    'payload': item.injected_payload,
                    'injection_point': item.injection_point,
                    'method': item.request_method,
                    'severity': severity,
                    'context': context,
                    'timestamp': item.timestamp,
                    'response_status': item.response_status,
                    'session_id': item.session_id
                }
                
                reflected_xss_findings.append(finding)
        
        return reflected_xss_findings
    
    def _detect_stored_xss(self, data: List[MITMInterceptionResult]) -> List[Dict[str, Any]]:
        """Detect stored XSS vulnerabilities"""
        
        stored_xss_findings = []
        
        # Build payload injection timeline
        payload_injections = {}  # payload -> injection_info
        
        for item in data:
            if item.injected_payload:
                payload_injections[item.injected_payload] = {
                    'injection_url': item.request_url,
                    'injection_time': item.timestamp,
                    'injection_point': item.injection_point,
                    'session_id': item.session_id
                }
        
        # Look for payloads appearing in later responses
        for item in data:
            if not item.response_body:
                continue
            
            for payload, injection_info in payload_injections.items():
                # Skip if this is the immediate response to injection
                if item.request_url == injection_info['injection_url']:
                    continue
                
                if payload in item.response_body:
                    # Potential stored XSS
                    severity = self._assess_xss_severity(payload, item.response_body)
                    context = self._analyze_injection_context(payload, item.response_body)
                    
                    # Calculate time between injection and execution
                    try:
                        injection_time = datetime.fromisoformat(injection_info['injection_time'])
                        execution_time = datetime.fromisoformat(item.timestamp)
                        delay = (execution_time - injection_time).total_seconds()
                    except:
                        delay = None
                    
                    finding = {
                        'injection_url': injection_info['injection_url'],
                        'execution_url': item.request_url,
                        'payload': payload,
                        'injection_point': injection_info['injection_point'],
                        'severity': severity,
                        'context': context,
                        'injection_time': injection_info['injection_time'],
                        'execution_time': item.timestamp,
                        'delay_seconds': delay,
                        'session_id': injection_info['session_id']
                    }
                    
                    stored_xss_findings.append(finding)
        
        return stored_xss_findings
    
    def _detect_dom_xss(self, data: List[MITMInterceptionResult]) -> List[Dict[str, Any]]:
        """Detect DOM-based XSS patterns"""
        
        dom_xss_findings = []
        
        for item in data:
            if not item.response_body:
                continue
            
            # Look for dangerous DOM patterns
            dom_patterns = self._analyze_dom_sinks_and_sources(item.response_body)
            
            if dom_patterns['dangerous_combinations']:
                finding = {
                    'url': item.request_url,
                    'dom_sinks': dom_patterns['sinks'],
                    'dom_sources': dom_patterns['sources'],
                    'dangerous_combinations': dom_patterns['dangerous_combinations'],
                    'javascript_snippets': dom_patterns['js_snippets'],
                    'severity': self._assess_dom_xss_severity(dom_patterns),
                    'timestamp': item.timestamp
                }
                
                dom_xss_findings.append(finding)
        
        return dom_xss_findings
    
    def _analyze_dom_sinks_and_sources(self, html_content: str) -> Dict[str, Any]:
        """Analyze HTML content for DOM XSS sinks and sources"""
        
        sinks = []
        sources = []
        js_snippets = []
        dangerous_combinations = []
        
        # Extract JavaScript content
        js_pattern = r'<script[^>]*>(.*?)</script>'
        js_matches = re.findall(js_pattern, html_content, re.DOTALL | re.IGNORECASE)
        
        for js_content in js_matches:
            js_snippets.append(js_content[:200])  # Truncate for analysis
            
            # Check for sinks
            for pattern in self.dom_xss_indicators:
                if re.search(pattern, js_content, re.IGNORECASE):
                    sinks.append(pattern)
            
            # Check for sources
            source_patterns = [
                r'location\.hash', r'location\.search', r'location\.href',
                r'document\.URL', r'document\.referrer', r'window\.name'
            ]
            
            for pattern in source_patterns:
                if re.search(pattern, js_content, re.IGNORECASE):
                    sources.append(pattern)
            
            # Look for dangerous combinations (source -> sink)
            if sources and sinks:
                dangerous_combinations.append({
                    'sources': sources,
                    'sinks': sinks,
                    'js_snippet': js_content[:100]
                })
        
        return {
            'sinks': list(set(sinks)),
            'sources': list(set(sources)),
            'js_snippets': js_snippets,
            'dangerous_combinations': dangerous_combinations
        }
    
    def _assess_xss_severity(self, payload: str, response_body: str) -> str:
        """Assess the severity of an XSS vulnerability"""
        
        # High severity indicators
        if any(indicator in payload.lower() for indicator in ['alert', 'prompt', 'confirm']):
            return 'high'
        
        if any(indicator in payload.lower() for indicator in ['script', 'javascript:', 'onerror', 'onload']):
            return 'high'
        
        # Check if payload is properly escaped
        if self._is_payload_escaped(payload, response_body):
            return 'low'
        
        # Medium by default
        return 'medium'
    
    def _assess_dom_xss_severity(self, dom_patterns: Dict[str, Any]) -> str:
        """Assess severity of DOM XSS patterns"""
        
        dangerous_count = len(dom_patterns['dangerous_combinations'])
        
        if dangerous_count >= 3:
            return 'high'
        elif dangerous_count >= 1:
            return 'medium'
        else:
            return 'low'
    
    def _analyze_injection_context(self, payload: str, response_body: str) -> Dict[str, Any]:
        """Analyze the context where payload appears in response"""
        
        contexts = []
        
        # Find payload occurrences
        payload_positions = []
        start = 0
        while True:
            pos = response_body.find(payload, start)
            if pos == -1:
                break
            payload_positions.append(pos)
            start = pos + 1
        
        for pos in payload_positions:
            # Get surrounding context (100 chars before and after)
            context_start = max(0, pos - 100)
            context_end = min(len(response_body), pos + len(payload) + 100)
            context = response_body[context_start:context_end]
            
            # Determine context type
            context_type = self._determine_context_type(context, payload)
            
            contexts.append({
                'position': pos,
                'type': context_type,
                'context': context
            })
        
        return {
            'occurrences': len(payload_positions),
            'contexts': contexts
        }
    
    def _determine_context_type(self, context: str, payload: str) -> str:
        """Determine the type of context where payload appears"""
        
        context_lower = context.lower()
        
        if '<script' in context_lower and '</script>' in context_lower:
            return 'javascript'
        elif 'href=' in context_lower or 'src=' in context_lower:
            return 'attribute'
        elif '<style' in context_lower and '</style>' in context_lower:
            return 'css'
        elif any(tag in context_lower for tag in ['<div', '<span', '<p', '<h1', '<h2', '<h3']):
            return 'html_content'
        else:
            return 'unknown'
    
    def _is_payload_escaped(self, payload: str, response_body: str) -> bool:
        """Check if payload is properly escaped in response"""
        
        # Common escaping patterns
        escaped_patterns = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;').replace("'", '&#x27;'),
            payload.replace('<', '\\u003C').replace('>', '\\u003E')
        ]
        
        for escaped in escaped_patterns:
            if escaped in response_body:
                return True
        
        return False
    
    def _create_vulnerability_timeline(self, data: List[MITMInterceptionResult]) -> List[Dict[str, Any]]:
        """Create timeline of vulnerability events"""
        
        timeline = []
        
        for item in data:
            if item.injected_payload:
                event = {
                    'timestamp': item.timestamp,
                    'type': 'payload_injection',
                    'url': item.request_url,
                    'payload': item.injected_payload[:50] + '...' if len(item.injected_payload) > 50 else item.injected_payload,
                    'reflected': item.payload_reflected,
                    'stored': item.payload_stored
                }
                timeline.append(event)
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        
        return timeline
    
    def _identify_attack_vectors(self, data: List[MITMInterceptionResult]) -> Dict[str, Any]:
        """Identify different attack vectors used"""
        
        vectors = {
            'injection_points': Counter(),
            'http_methods': Counter(),
            'payload_types': Counter(),
            'successful_vectors': []
        }
        
        for item in data:
            if item.injected_payload:
                vectors['injection_points'][item.injection_point or 'unknown'] += 1
                vectors['http_methods'][item.request_method] += 1
                
                # Classify payload type
                payload_type = self._classify_payload_type(item.injected_payload)
                vectors['payload_types'][payload_type] += 1
                
                # Track successful vectors
                if item.payload_reflected or item.payload_stored:
                    vectors['successful_vectors'].append({
                        'injection_point': item.injection_point,
                        'method': item.request_method,
                        'payload_type': payload_type,
                        'url': item.request_url
                    })
        
        # Convert Counters to regular dicts for JSON serialization
        vectors['injection_points'] = dict(vectors['injection_points'])
        vectors['http_methods'] = dict(vectors['http_methods'])
        vectors['payload_types'] = dict(vectors['payload_types'])
        
        return vectors
    
    def _classify_payload_type(self, payload: str) -> str:
        """Classify the type of XSS payload"""
        
        payload_lower = payload.lower()
        
        if '<script' in payload_lower:
            return 'script_tag'
        elif 'javascript:' in payload_lower:
            return 'javascript_protocol'
        elif any(event in payload_lower for event in ['onerror', 'onload', 'onmouseover', 'onclick']):
            return 'event_handler'
        elif '<svg' in payload_lower or '<img' in payload_lower:
            return 'html_tag_with_event'
        elif 'alert(' in payload_lower or 'prompt(' in payload_lower:
            return 'dialog_function'
        else:
            return 'other'
    
    def _generate_recommendations(self, data: List[MITMInterceptionResult]) -> List[str]:
        """Generate security recommendations based on analysis"""
        
        recommendations = []
        
        # Check for common vulnerabilities
        has_reflected_xss = any(item.payload_reflected for item in data)
        has_stored_xss = any(item.payload_stored for item in data)
        has_dom_patterns = any(item.dom_modifications for item in data if item.dom_modifications)
        
        if has_reflected_xss:
            recommendations.append("Implement proper input validation and output encoding for all user inputs")
            recommendations.append("Use Content Security Policy (CSP) headers to prevent script injection")
        
        if has_stored_xss:
            recommendations.append("Sanitize and validate data before storing in database")
            recommendations.append("Encode output when displaying stored user content")
            recommendations.append("Implement proper session management to prevent cross-user attacks")
        
        if has_dom_patterns:
            recommendations.append("Avoid using dangerous DOM manipulation methods like innerHTML")
            recommendations.append("Validate and sanitize data from DOM sources like location.hash")
            recommendations.append("Use safe DOM methods like textContent instead of innerHTML")
        
        # Generic recommendations
        recommendations.extend([
            "Implement Web Application Firewall (WAF) rules for XSS protection",
            "Regular security testing and code reviews",
            "Keep frameworks and libraries updated to latest secure versions"
        ])
        
        return recommendations