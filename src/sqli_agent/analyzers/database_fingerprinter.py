"""
Database Fingerprinting Analyzer

Identifies the database type and version through various techniques.
"""
import logging
import re
from typing import Optional, List
from ..models import DatabaseType, DatabaseFingerprint


class DatabaseFingerprinter:
    """Fingerprints database type and version"""

    # Database-specific function signatures
    DB_FUNCTIONS = {
        DatabaseType.MYSQL: [
            'VERSION()', 'DATABASE()', 'USER()', 'CURRENT_USER()',
            'SLEEP()', 'BENCHMARK()', 'LOAD_FILE()', '@@version',
            '@@datadir', 'SUBSTRING()', 'CONCAT()', 'GROUP_CONCAT()'
        ],
        DatabaseType.POSTGRESQL: [
            'version()', 'current_database()', 'current_user',
            'pg_sleep()', 'pg_database', 'pg_user', 'pg_tables',
            'SUBSTRING()', 'CONCAT()', 'CHR()', 'ASCII()'
        ],
        DatabaseType.MSSQL: [
            '@@VERSION', 'DB_NAME()', 'USER_NAME()', 'SYSTEM_USER',
            'WAITFOR DELAY', 'xp_cmdshell', 'sp_configure',
            'SUBSTRING()', 'CONCAT()', 'CHAR()', 'ASCII()'
        ],
        DatabaseType.ORACLE: [
            'banner FROM v$version', 'user FROM dual', 'SYS.DATABASE_NAME',
            'DBMS_LOCK.SLEEP()', 'UTL_INADDR', 'SUBSTR()', 'CHR()',
            'FROM dual', 'ROWNUM'
        ],
        DatabaseType.SQLITE: [
            'sqlite_version()', 'sqlite_master', 'sqlite_temp_master',
            'SUBSTR()', 'INSTR()', 'TYPEOF()', 'LENGTH()'
        ]
    }

    # Database-specific syntax patterns
    DB_SYNTAX = {
        DatabaseType.MYSQL: [
            r'#.*$',  # MySQL comment
            r'LIMIT \d+',
            r'`[\w]+`',  # Backtick identifiers
            r'@@[\w]+',  # System variables
            r'CONCAT\([^)]+\)',
            r'information_schema\.tables'
        ],
        DatabaseType.POSTGRESQL: [
            r'::text',  # Type casting
            r'::int',
            r'\$\d+',  # Parameter placeholders
            r'pg_[\w]+',  # pg_* functions
            r'FROM\s+dual',  # Not in PostgreSQL (helps eliminate)
        ],
        DatabaseType.MSSQL: [
            r'\[[\w]+\]',  # Square bracket identifiers
            r'@@[\w]+',  # System variables
            r'WAITFOR\s+DELAY',
            r'xp_[\w]+',  # Extended procedures
            r'sys\.[\w]+'
        ],
        DatabaseType.ORACLE: [
            r'FROM\s+dual',  # Oracle's dummy table
            r'ROWNUM',
            r'v\$[\w]+',  # V$ views
            r'DBMS_[\w]+',  # DBMS packages
            r'NVL\(',
            r'\.nextval'  # Sequences
        ],
        DatabaseType.SQLITE: [
            r'sqlite_[\w]+',
            r'AUTOINCREMENT',
            r'pragma\s+',
            r'TYPEOF\('
        ]
    }

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def fingerprint_from_error(self, error_message: str) -> DatabaseFingerprint:
        """Fingerprint database from error message"""
        error_lower = error_message.lower()

        # MySQL
        if any(sig in error_lower for sig in ['mysql', 'maria', 'percona']):
            version = self._extract_version(error_message, r'(MySQL|MariaDB) server version\s+[\d.]+')
            return DatabaseFingerprint(
                database_type=DatabaseType.MYSQL,
                confidence=95,
                version=version,
                error_signatures=['mysql' if 'mysql' in error_lower else 'mariadb'],
                reasoning="MySQL/MariaDB error signature detected"
            )

        # PostgreSQL
        if any(sig in error_lower for sig in ['postgresql', 'postgres', 'pg_']):
            version = self._extract_version(error_message, r'PostgreSQL\s+[\d.]+')
            return DatabaseFingerprint(
                database_type=DatabaseType.POSTGRESQL,
                confidence=95,
                version=version,
                error_signatures=['postgresql'],
                reasoning="PostgreSQL error signature detected"
            )

        # MSSQL
        if any(sig in error_lower for sig in ['sql server', 'microsoft', 'sqlserver', 'mssql']):
            version = self._extract_version(error_message, r'SQL Server\s+[\d.]+')
            return DatabaseFingerprint(
                database_type=DatabaseType.MSSQL,
                confidence=95,
                version=version,
                error_signatures=['mssql'],
                reasoning="Microsoft SQL Server error signature detected"
            )

        # Oracle
        if any(sig in error_lower for sig in ['oracle', 'ora-', 'oci']):
            version = self._extract_version(error_message, r'Oracle\s+[\d.]+')
            return DatabaseFingerprint(
                database_type=DatabaseType.ORACLE,
                confidence=95,
                version=version,
                error_signatures=['oracle'],
                reasoning="Oracle error signature detected"
            )

        # SQLite
        if any(sig in error_lower for sig in ['sqlite', 'sqlite3']):
            return DatabaseFingerprint(
                database_type=DatabaseType.SQLITE,
                confidence=90,
                error_signatures=['sqlite'],
                reasoning="SQLite error signature detected"
            )

        return DatabaseFingerprint(
            database_type=DatabaseType.UNKNOWN,
            confidence=0,
            reasoning="No database signature detected in error"
        )

    def fingerprint_from_response(self, response_html: str) -> DatabaseFingerprint:
        """Fingerprint database from response content"""
        response_lower = response_html.lower()
        scores = {db: 0 for db in DatabaseType}

        # Check for syntax patterns
        for db_type, patterns in self.DB_SYNTAX.items():
            for pattern in patterns:
                if re.search(pattern, response_html, re.IGNORECASE):
                    scores[db_type] += 1

        # Check for function names
        for db_type, functions in self.DB_FUNCTIONS.items():
            for func in functions:
                if func.lower() in response_lower:
                    scores[db_type] += 2

        # Find highest score
        max_score = max(scores.values())
        if max_score == 0:
            return DatabaseFingerprint(
                database_type=DatabaseType.UNKNOWN,
                confidence=0,
                reasoning="No database signatures found in response"
            )

        detected_db = max(scores, key=scores.get)
        confidence = min(85, max_score * 10)  # Cap at 85% for heuristic detection

        detected_syntax = [
            pattern for pattern in self.DB_SYNTAX.get(detected_db, [])
            if re.search(pattern, response_html, re.IGNORECASE)
        ]

        detected_funcs = [
            func for func in self.DB_FUNCTIONS.get(detected_db, [])
            if func.lower() in response_lower
        ]

        return DatabaseFingerprint(
            database_type=detected_db,
            confidence=confidence,
            detected_syntax=detected_syntax[:5],
            detected_functions=detected_funcs[:5],
            reasoning=f"Detected {len(detected_syntax)} syntax patterns and {len(detected_funcs)} functions"
        )

    def fingerprint_from_timing(
        self,
        mysql_time: Optional[float],
        postgresql_time: Optional[float],
        mssql_time: Optional[float]
    ) -> DatabaseFingerprint:
        """Fingerprint database from time-based payload responses"""
        delays = {}

        if mysql_time and mysql_time >= 4.5:
            delays[DatabaseType.MYSQL] = mysql_time
            self.logger.info(f"MySQL SLEEP detected: {mysql_time:.2f}s")

        if postgresql_time and postgresql_time >= 4.5:
            delays[DatabaseType.POSTGRESQL] = postgresql_time
            self.logger.info(f"PostgreSQL pg_sleep detected: {postgresql_time:.2f}s")

        if mssql_time and mssql_time >= 4.5:
            delays[DatabaseType.MSSQL] = mssql_time
            self.logger.info(f"MSSQL WAITFOR detected: {mssql_time:.2f}s")

        if not delays:
            return DatabaseFingerprint(
                database_type=DatabaseType.UNKNOWN,
                confidence=0,
                reasoning="No time-based signatures detected"
            )

        # Return database with longest delay (most confident)
        detected_db = max(delays, key=delays.get)
        delay_time = delays[detected_db]

        return DatabaseFingerprint(
            database_type=detected_db,
            confidence=90,
            reasoning=f"Time-based signature detected: {delay_time:.2f}s delay"
        )

    def combine_fingerprints(
        self,
        fingerprints: List[DatabaseFingerprint]
    ) -> DatabaseFingerprint:
        """Combine multiple fingerprints into one high-confidence result"""
        if not fingerprints:
            return DatabaseFingerprint(
                database_type=DatabaseType.UNKNOWN,
                confidence=0,
                reasoning="No fingerprints to combine"
            )

        # Count votes for each database type
        votes = {}
        for fp in fingerprints:
            if fp.database_type != DatabaseType.UNKNOWN:
                if fp.database_type not in votes:
                    votes[fp.database_type] = []
                votes[fp.database_type].append(fp.confidence)

        if not votes:
            return DatabaseFingerprint(
                database_type=DatabaseType.UNKNOWN,
                confidence=0,
                reasoning="All fingerprints returned UNKNOWN"
            )

        # Find database with most votes and highest average confidence
        best_db = max(votes, key=lambda db: (len(votes[db]), sum(votes[db]) / len(votes[db])))
        avg_confidence = int(sum(votes[best_db]) / len(votes[best_db]))

        # Boost confidence if multiple methods agree
        if len(votes[best_db]) > 1:
            avg_confidence = min(100, avg_confidence + 10)

        # Collect all evidence
        all_funcs = []
        all_syntax = []
        all_errors = []

        for fp in fingerprints:
            if fp.database_type == best_db:
                all_funcs.extend(fp.detected_functions)
                all_syntax.extend(fp.detected_syntax)
                all_errors.extend(fp.error_signatures)

        return DatabaseFingerprint(
            database_type=best_db,
            confidence=avg_confidence,
            detected_functions=list(set(all_funcs))[:5],
            detected_syntax=list(set(all_syntax))[:5],
            error_signatures=list(set(all_errors)),
            reasoning=f"Combined {len(fingerprints)} fingerprint(s), {len(votes[best_db])} agree on {best_db.value}"
        )

    def _extract_version(self, text: str, pattern: str) -> Optional[str]:
        """Extract version string from text"""
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(0)
        return None
