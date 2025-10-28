"""
SQLi Agent Models and Data Structures

Defines data models for SQL injection detection and exploitation.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime


class SQLiType(Enum):
    """Types of SQL injection"""
    ERROR_BASED = "error_based"
    UNION_BASED = "union_based"
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BLIND = "time_blind"
    STACKED_QUERIES = "stacked_queries"
    OUT_OF_BAND = "out_of_band"
    SECOND_ORDER = "second_order"
    UNKNOWN = "unknown"


class DatabaseType(Enum):
    """Database management systems"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    MONGODB = "mongodb"
    UNKNOWN = "unknown"


class SQLContext(Enum):
    """SQL query context"""
    WHERE_CLAUSE = "where"
    ORDER_BY = "order_by"
    LIMIT = "limit"
    INSERT_VALUES = "insert_values"
    UPDATE_SET = "update_set"
    SELECT_COLUMN = "select_column"
    LIKE_PATTERN = "like_pattern"
    IN_CLAUSE = "in_clause"
    UNKNOWN = "unknown"


@dataclass
class SQLiTestAttempt:
    """Represents a single SQL injection test attempt"""
    attempt_number: int
    payload: str
    target_url: str
    target_parameter: str
    injection_type: SQLiType
    response_html: str
    response_headers: Dict[str, str]
    response_time: float
    response_status: int
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error_messages: List[str] = field(default_factory=list)

    # Comparison data for blind SQLi
    baseline_html: Optional[str] = None
    baseline_time: Optional[float] = None
    true_response: Optional[str] = None
    false_response: Optional[str] = None


@dataclass
class SQLiVerificationResult:
    """Results from SQL injection verification"""
    url: str
    parameter: str
    payload: str
    vulnerable: bool
    injection_type: SQLiType
    confidence: int  # 0-100
    database_type: DatabaseType = DatabaseType.UNKNOWN

    # Evidence
    error_messages: List[str] = field(default_factory=list)
    response_time: Optional[float] = None
    baseline_time: Optional[float] = None
    response_diff: Optional[Dict[str, Any]] = None

    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    screenshot_path: Optional[str] = None
    page_content: Optional[str] = None
    page_content_file: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None

    # Additional info
    sql_context: SQLContext = SQLContext.UNKNOWN
    bypassed_protections: List[str] = field(default_factory=list)
    exploitation_notes: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DatabaseFingerprint:
    """Database fingerprinting results"""
    database_type: DatabaseType
    confidence: int  # 0-100
    version: Optional[str] = None
    detected_functions: List[str] = field(default_factory=list)
    detected_syntax: List[str] = field(default_factory=list)
    error_signatures: List[str] = field(default_factory=list)
    reasoning: str = ""


@dataclass
class SQLContextInfo:
    """SQL context detection results"""
    context: SQLContext
    confidence: int  # 0-100
    column_count: Optional[int] = None  # For UNION-based
    injectable_position: Optional[int] = None
    quote_type: Optional[str] = None  # ' or " or none
    requires_closure: bool = False
    detected_query_type: Optional[str] = None  # SELECT, INSERT, UPDATE, etc.
    reasoning: str = ""


@dataclass
class SQLProtectionInfo:
    """SQL protection detection results"""
    waf_detected: bool = False
    waf_type: Optional[str] = None
    prepared_statements: bool = False
    escaping_detected: bool = False
    escaping_type: Optional[str] = None  # addslashes, mysql_real_escape_string, etc.
    blocked_keywords: List[str] = field(default_factory=list)
    blocked_characters: List[str] = field(default_factory=list)
    csp_detected: bool = False
    rate_limiting: bool = False
    confidence: int = 0


@dataclass
class SQLBypassStrategy:
    """SQL injection bypass strategy"""
    bypass_technique: str
    payload_template: str
    confidence: int  # 0-100
    reasoning: str
    target_protection: List[str] = field(default_factory=list)
    avoids_patterns: List[str] = field(default_factory=list)
    requires_encoding: bool = False
    encoding_type: Optional[str] = None
    alternative_payloads: List[str] = field(default_factory=list)


@dataclass
class InjectionPoint:
    """Represents a potentially injectable parameter"""
    parameter: str
    location: str  # query, post, cookie, header
    original_value: str
    parameter_type: str  # numeric, string, etc.
    confidence: int = 0
    notes: str = ""


@dataclass
class SQLiAnalysisResult:
    """Results from deep analysis stage"""
    stage_name: str
    insights: List[str]
    confidence: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class SQLiSessionResult:
    """Final results from SQLi detection session"""
    target_url: str
    vulnerable: bool
    injection_points: List[InjectionPoint]
    successful_payloads: List[Dict[str, Any]]

    # Detection details
    database_type: DatabaseType = DatabaseType.UNKNOWN
    injection_types: List[SQLiType] = field(default_factory=list)

    # Session metadata
    total_attempts: int = 0
    successful_attempts: int = 0
    time_elapsed: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Evidence
    screenshots: List[str] = field(default_factory=list)
    error_messages: List[str] = field(default_factory=list)

    # Analysis
    protection_info: Optional[SQLProtectionInfo] = None
    bypass_strategies: List[SQLBypassStrategy] = field(default_factory=list)

    # Exploitation data
    extractable_data: bool = False
    data_samples: List[str] = field(default_factory=list)

    notes: str = ""
