"""
Memory Storage Backend using SQLite

Provides persistent storage for agent memory with support for:
- Tested payloads and results
- Detected filters and bypasses
- Strategy effectiveness scores
- Cross-session learning
"""

import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from contextlib import contextmanager
import threading


class MemoryStorage:
    """
    SQLite-based persistent storage for agent memory
    Thread-safe and Docker-compatible
    """

    def __init__(self, db_path: str = "memory/agent_memory.db"):
        """
        Initialize memory storage

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_database()

    @contextmanager
    def _get_connection(self):
        """Get thread-local database connection"""
        if not hasattr(self._local, 'conn'):
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False
            )
            self._local.conn.row_factory = sqlite3.Row
        try:
            yield self._local.conn
        except Exception as e:
            self._local.conn.rollback()
            raise e

    def _init_database(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Payload attempts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS payload_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    target_domain TEXT,
                    target_url TEXT,
                    payload TEXT,
                    payload_type TEXT,
                    strategy TEXT,
                    success BOOLEAN,
                    transformation TEXT,
                    detected_filter TEXT,
                    confidence REAL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Detected filters table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detected_filters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_domain TEXT,
                    filter_type TEXT,
                    filter_signature TEXT,
                    detection_count INTEGER DEFAULT 1,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT
                )
            ''')

            # Successful bypasses table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS successful_bypasses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_domain TEXT,
                    filter_type TEXT,
                    bypass_technique TEXT,
                    payload_example TEXT,
                    success_count INTEGER DEFAULT 1,
                    total_attempts INTEGER DEFAULT 1,
                    effectiveness_score REAL,
                    last_success DATETIME DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
            ''')

            # Strategy effectiveness table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS strategy_effectiveness (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    strategy_name TEXT,
                    target_type TEXT,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    avg_time_to_success REAL,
                    effectiveness_score REAL,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Target intelligence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS target_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_domain TEXT UNIQUE,
                    technology_stack TEXT,
                    waf_detected TEXT,
                    vulnerability_count INTEGER DEFAULT 0,
                    last_scanned DATETIME DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT
                )
            ''')

            # Create indexes for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_payload_target
                ON payload_attempts(target_domain, payload)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_filter_domain
                ON detected_filters(target_domain, filter_type)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_bypass_filter
                ON successful_bypasses(filter_type, effectiveness_score DESC)
            ''')

            conn.commit()

    def record_payload_attempt(
        self,
        session_id: str,
        target_url: str,
        payload: str,
        payload_type: str,
        strategy: str,
        success: bool,
        transformation: Optional[str] = None,
        detected_filter: Optional[str] = None,
        confidence: float = 0.5
    ) -> int:
        """Record a payload attempt"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Extract domain from URL
            from urllib.parse import urlparse
            domain = urlparse(target_url).netloc

            cursor.execute('''
                INSERT INTO payload_attempts
                (session_id, target_domain, target_url, payload, payload_type,
                 strategy, success, transformation, detected_filter, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (session_id, domain, target_url, payload, payload_type,
                  strategy, success, transformation, detected_filter, confidence))

            conn.commit()
            return cursor.lastrowid

    def record_detected_filter(
        self,
        target_domain: str,
        filter_type: str,
        filter_signature: str,
        notes: Optional[str] = None
    ) -> None:
        """Record or update a detected filter"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if filter already exists
            cursor.execute('''
                SELECT id, detection_count FROM detected_filters
                WHERE target_domain = ? AND filter_type = ?
            ''', (target_domain, filter_type))

            existing = cursor.fetchone()

            if existing:
                # Update existing record
                cursor.execute('''
                    UPDATE detected_filters
                    SET detection_count = detection_count + 1,
                        last_seen = CURRENT_TIMESTAMP,
                        filter_signature = ?,
                        notes = ?
                    WHERE id = ?
                ''', (filter_signature, notes, existing['id']))
            else:
                # Insert new record
                cursor.execute('''
                    INSERT INTO detected_filters
                    (target_domain, filter_type, filter_signature, notes)
                    VALUES (?, ?, ?, ?)
                ''', (target_domain, filter_type, filter_signature, notes))

            conn.commit()

    def record_successful_bypass(
        self,
        target_domain: str,
        filter_type: str,
        bypass_technique: str,
        payload_example: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record a successful bypass technique"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            metadata_json = json.dumps(metadata) if metadata else None

            # Check if bypass already exists
            cursor.execute('''
                SELECT id, success_count, total_attempts FROM successful_bypasses
                WHERE target_domain = ? AND filter_type = ? AND bypass_technique = ?
            ''', (target_domain, filter_type, bypass_technique))

            existing = cursor.fetchone()

            if existing:
                # Update existing record
                new_success = existing['success_count'] + 1
                new_total = existing['total_attempts'] + 1
                effectiveness = new_success / new_total

                cursor.execute('''
                    UPDATE successful_bypasses
                    SET success_count = ?,
                        total_attempts = ?,
                        effectiveness_score = ?,
                        last_success = CURRENT_TIMESTAMP,
                        payload_example = ?,
                        metadata = ?
                    WHERE id = ?
                ''', (new_success, new_total, effectiveness,
                      payload_example, metadata_json, existing['id']))
            else:
                # Insert new record
                cursor.execute('''
                    INSERT INTO successful_bypasses
                    (target_domain, filter_type, bypass_technique,
                     payload_example, effectiveness_score, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (target_domain, filter_type, bypass_technique,
                      payload_example, 1.0, metadata_json))

            conn.commit()

    def update_strategy_effectiveness(
        self,
        strategy_name: str,
        target_type: str,
        success: bool,
        time_to_success: Optional[float] = None
    ) -> None:
        """Update strategy effectiveness metrics"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Get existing record
            cursor.execute('''
                SELECT id, success_count, failure_count, avg_time_to_success
                FROM strategy_effectiveness
                WHERE strategy_name = ? AND target_type = ?
            ''', (strategy_name, target_type))

            existing = cursor.fetchone()

            if existing:
                new_success = existing['success_count'] + (1 if success else 0)
                new_failure = existing['failure_count'] + (0 if success else 1)
                total = new_success + new_failure
                effectiveness = new_success / total if total > 0 else 0

                # Update average time to success
                avg_time = existing['avg_time_to_success'] or 0
                if success and time_to_success:
                    avg_time = (avg_time * existing['success_count'] + time_to_success) / new_success

                cursor.execute('''
                    UPDATE strategy_effectiveness
                    SET success_count = ?,
                        failure_count = ?,
                        effectiveness_score = ?,
                        avg_time_to_success = ?,
                        last_updated = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (new_success, new_failure, effectiveness, avg_time, existing['id']))
            else:
                # Insert new record
                effectiveness = 1.0 if success else 0.0
                cursor.execute('''
                    INSERT INTO strategy_effectiveness
                    (strategy_name, target_type, success_count, failure_count,
                     effectiveness_score, avg_time_to_success)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (strategy_name, target_type,
                      1 if success else 0, 0 if success else 1,
                      effectiveness, time_to_success))

            conn.commit()

    def get_similar_payloads(
        self,
        target_domain: str,
        payload_type: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get previously tested payloads for a target"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if payload_type:
                cursor.execute('''
                    SELECT payload, payload_type, strategy, success,
                           transformation, detected_filter, confidence, timestamp
                    FROM payload_attempts
                    WHERE target_domain = ? AND payload_type = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (target_domain, payload_type, limit))
            else:
                cursor.execute('''
                    SELECT payload, payload_type, strategy, success,
                           transformation, detected_filter, confidence, timestamp
                    FROM payload_attempts
                    WHERE target_domain = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (target_domain, limit))

            return [dict(row) for row in cursor.fetchall()]

    def get_detected_filters(self, target_domain: str) -> List[Dict[str, Any]]:
        """Get all detected filters for a target"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT filter_type, filter_signature, detection_count,
                       last_seen, notes
                FROM detected_filters
                WHERE target_domain = ?
                ORDER BY detection_count DESC
            ''', (target_domain,))

            return [dict(row) for row in cursor.fetchall()]

    def get_effective_bypasses(
        self,
        filter_type: str,
        min_effectiveness: float = 0.5,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Get most effective bypass techniques for a filter type"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT bypass_technique, payload_example, effectiveness_score,
                       success_count, total_attempts, metadata
                FROM successful_bypasses
                WHERE filter_type = ? AND effectiveness_score >= ?
                ORDER BY effectiveness_score DESC, success_count DESC
                LIMIT ?
            ''', (filter_type, min_effectiveness, limit))

            results = []
            for row in cursor.fetchall():
                data = dict(row)
                if data['metadata']:
                    data['metadata'] = json.loads(data['metadata'])
                results.append(data)

            return results

    def get_best_strategies(
        self,
        target_type: str,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Get best performing strategies for a target type"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT strategy_name, success_count, failure_count,
                       effectiveness_score, avg_time_to_success
                FROM strategy_effectiveness
                WHERE target_type = ?
                ORDER BY effectiveness_score DESC
                LIMIT ?
            ''', (target_type, limit))

            return [dict(row) for row in cursor.fetchall()]

    def check_payload_tested(
        self,
        target_domain: str,
        payload: str
    ) -> Optional[Dict[str, Any]]:
        """Check if a payload was previously tested on this target"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT success, transformation, detected_filter,
                       strategy, confidence, timestamp
                FROM payload_attempts
                WHERE target_domain = ? AND payload = ?
                ORDER BY timestamp DESC
                LIMIT 1
            ''', (target_domain, payload))

            row = cursor.fetchone()
            return dict(row) if row else None

    def get_target_intelligence(self, target_domain: str) -> Optional[Dict[str, Any]]:
        """Get intelligence about a target"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT technology_stack, waf_detected, vulnerability_count,
                       last_scanned, notes
                FROM target_intelligence
                WHERE target_domain = ?
            ''', (target_domain,))

            row = cursor.fetchone()
            return dict(row) if row else None

    def update_target_intelligence(
        self,
        target_domain: str,
        technology_stack: Optional[str] = None,
        waf_detected: Optional[str] = None,
        vulnerability_count: Optional[int] = None,
        notes: Optional[str] = None
    ) -> None:
        """Update or create target intelligence record"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if exists
            cursor.execute('''
                SELECT id FROM target_intelligence WHERE target_domain = ?
            ''', (target_domain,))

            existing = cursor.fetchone()

            if existing:
                # Update only non-None fields
                updates = []
                values = []
                if technology_stack is not None:
                    updates.append('technology_stack = ?')
                    values.append(technology_stack)
                if waf_detected is not None:
                    updates.append('waf_detected = ?')
                    values.append(waf_detected)
                if vulnerability_count is not None:
                    updates.append('vulnerability_count = ?')
                    values.append(vulnerability_count)
                if notes is not None:
                    updates.append('notes = ?')
                    values.append(notes)

                if updates:
                    updates.append('last_scanned = CURRENT_TIMESTAMP')
                    values.append(existing['id'])
                    cursor.execute(f'''
                        UPDATE target_intelligence
                        SET {', '.join(updates)}
                        WHERE id = ?
                    ''', values)
            else:
                # Insert new record
                cursor.execute('''
                    INSERT INTO target_intelligence
                    (target_domain, technology_stack, waf_detected,
                     vulnerability_count, notes)
                    VALUES (?, ?, ?, ?, ?)
                ''', (target_domain, technology_stack, waf_detected,
                      vulnerability_count, notes))

            conn.commit()

    def cleanup_old_memories(self, days: int = 90) -> int:
        """Remove memories older than specified days"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cutoff = datetime.now() - timedelta(days=days)

            # Clean old payload attempts
            cursor.execute('''
                DELETE FROM payload_attempts
                WHERE timestamp < ?
            ''', (cutoff,))

            deleted = cursor.rowcount
            conn.commit()

            return deleted

    def get_statistics(self) -> Dict[str, int]:
        """Get memory database statistics"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            stats = {}

            for table in ['payload_attempts', 'detected_filters',
                         'successful_bypasses', 'strategy_effectiveness',
                         'target_intelligence']:
                cursor.execute(f'SELECT COUNT(*) as count FROM {table}')
                stats[table] = cursor.fetchone()['count']

            return stats

    def export_memory(self, output_path: str) -> None:
        """Export memory database to JSON"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            export_data = {}

            for table in ['payload_attempts', 'detected_filters',
                         'successful_bypasses', 'strategy_effectiveness',
                         'target_intelligence']:
                cursor.execute(f'SELECT * FROM {table}')
                export_data[table] = [dict(row) for row in cursor.fetchall()]

            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)

    def close(self):
        """Close database connection"""
        if hasattr(self._local, 'conn'):
            self._local.conn.close()
            del self._local.conn
