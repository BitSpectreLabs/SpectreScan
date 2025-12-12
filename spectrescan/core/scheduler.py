"""
Scan Scheduling and Automation Engine for SpectreScan.

Provides cron-like scheduling, one-time scheduled scans, recurring patterns,
pre/post scan hooks, conditional execution, and scan chaining.

by BitSpectreLabs
"""

import asyncio
import hashlib
import json
import logging
import os
import signal
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import re

logger = logging.getLogger(__name__)


# =============================================================================
# Enums and Constants
# =============================================================================

class ScheduleType(str, Enum):
    """Type of schedule."""
    ONCE = "once"           # One-time scheduled scan
    CRON = "cron"           # Cron expression based
    INTERVAL = "interval"   # Fixed interval (every N minutes/hours/days)
    DAILY = "daily"         # Daily at specific time
    WEEKLY = "weekly"       # Weekly on specific day(s)
    MONTHLY = "monthly"     # Monthly on specific day(s)


class ScheduleStatus(str, Enum):
    """Status of a scheduled scan."""
    PENDING = "pending"       # Waiting for next run
    RUNNING = "running"       # Currently executing
    COMPLETED = "completed"   # Finished (for one-time scans)
    PAUSED = "paused"         # Temporarily disabled
    FAILED = "failed"         # Last run failed
    CANCELLED = "cancelled"   # Permanently cancelled


class HookType(str, Enum):
    """Type of scan hook."""
    PRE_SCAN = "pre_scan"     # Execute before scan starts
    POST_SCAN = "post_scan"   # Execute after scan completes
    ON_ERROR = "on_error"     # Execute on scan error
    ON_CHANGE = "on_change"   # Execute when results differ from previous


class ConditionType(str, Enum):
    """Type of execution condition."""
    HOST_UP = "host_up"             # Only run if host is up
    PORT_CHANGED = "port_changed"   # Only run if ports changed
    SERVICE_CHANGED = "service_changed"  # Only run if services changed
    TIME_WINDOW = "time_window"     # Only run within time window
    PREVIOUS_SUCCESS = "previous_success"  # Only run if previous succeeded
    CUSTOM = "custom"               # Custom condition function


# Days of week for scheduling
DAYS_OF_WEEK = {
    "mon": 0, "monday": 0,
    "tue": 1, "tuesday": 1,
    "wed": 2, "wednesday": 2,
    "thu": 3, "thursday": 3,
    "fri": 4, "friday": 4,
    "sat": 5, "saturday": 5,
    "sun": 6, "sunday": 6,
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class CronExpression:
    """Parsed cron expression."""
    minute: str = "*"      # 0-59
    hour: str = "*"        # 0-23
    day_of_month: str = "*"  # 1-31
    month: str = "*"       # 1-12
    day_of_week: str = "*"  # 0-6 (Sunday=0)
    
    @classmethod
    def parse(cls, expression: str) -> "CronExpression":
        """Parse a cron expression string."""
        parts = expression.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {expression}. Expected 5 fields.")
        
        return cls(
            minute=parts[0],
            hour=parts[1],
            day_of_month=parts[2],
            month=parts[3],
            day_of_week=parts[4],
        )
    
    def __str__(self) -> str:
        return f"{self.minute} {self.hour} {self.day_of_month} {self.month} {self.day_of_week}"
    
    def matches(self, dt: datetime) -> bool:
        """Check if datetime matches this cron expression."""
        return (
            self._field_matches(self.minute, dt.minute, 0, 59) and
            self._field_matches(self.hour, dt.hour, 0, 23) and
            self._field_matches(self.day_of_month, dt.day, 1, 31) and
            self._field_matches(self.month, dt.month, 1, 12) and
            self._field_matches(self.day_of_week, dt.weekday(), 0, 6)
        )
    
    def _field_matches(self, field: str, value: int, min_val: int, max_val: int) -> bool:
        """Check if a cron field matches a value."""
        if field == "*":
            return True
        
        # Handle lists (e.g., "1,2,3")
        if "," in field:
            return value in [int(x) for x in field.split(",")]
        
        # Handle ranges (e.g., "1-5")
        if "-" in field:
            start, end = field.split("-")
            return int(start) <= value <= int(end)
        
        # Handle step values (e.g., "*/5")
        if "/" in field:
            base, step = field.split("/")
            step = int(step)
            if base == "*":
                return value % step == 0
            else:
                start = int(base)
                return (value - start) % step == 0 and value >= start
        
        # Simple value
        return value == int(field)
    
    def next_run(self, after: Optional[datetime] = None) -> datetime:
        """Calculate the next run time after the given datetime."""
        if after is None:
            after = datetime.now()
        
        # Start from the next minute
        candidate = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
        
        # Search for next matching time (max 1 year)
        max_iterations = 525600  # Minutes in a year
        for _ in range(max_iterations):
            if self.matches(candidate):
                return candidate
            candidate += timedelta(minutes=1)
        
        raise ValueError("Could not find next run time within 1 year")


@dataclass
class ScanHook:
    """Hook to execute before/after scan."""
    hook_id: str
    hook_type: HookType
    action: str  # Command to execute or function name
    timeout: int = 60  # Timeout in seconds
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "hook_id": self.hook_id,
            "hook_type": self.hook_type.value,
            "action": self.action,
            "timeout": self.timeout,
            "enabled": self.enabled,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanHook":
        return cls(
            hook_id=data["hook_id"],
            hook_type=HookType(data["hook_type"]),
            action=data["action"],
            timeout=data.get("timeout", 60),
            enabled=data.get("enabled", True),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ExecutionCondition:
    """Condition that must be met for scan to execute."""
    condition_id: str
    condition_type: ConditionType
    parameters: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "condition_id": self.condition_id,
            "condition_type": self.condition_type.value,
            "parameters": self.parameters,
            "enabled": self.enabled,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionCondition":
        return cls(
            condition_id=data["condition_id"],
            condition_type=ConditionType(data["condition_type"]),
            parameters=data.get("parameters", {}),
            enabled=data.get("enabled", True),
        )


@dataclass
class ScheduledScan:
    """A scheduled scan job."""
    schedule_id: str
    name: str
    target: str
    ports: str = "1-1000"
    schedule_type: ScheduleType = ScheduleType.ONCE
    
    # Schedule configuration
    cron_expression: Optional[str] = None  # For CRON type
    interval_minutes: Optional[int] = None  # For INTERVAL type
    run_at: Optional[datetime] = None  # For ONCE type or specific time
    days_of_week: List[int] = field(default_factory=list)  # For WEEKLY type
    days_of_month: List[int] = field(default_factory=list)  # For MONTHLY type
    
    # Scan configuration
    scan_type: str = "tcp"
    profile_name: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)
    
    # Status and tracking
    status: ScheduleStatus = ScheduleStatus.PENDING
    created_at: Optional[datetime] = None
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    run_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    
    # Hooks and conditions
    hooks: List[ScanHook] = field(default_factory=list)
    conditions: List[ExecutionCondition] = field(default_factory=list)
    
    # Chain configuration
    chain_next: Optional[str] = None  # Schedule ID to run after this completes
    chain_on_success_only: bool = True
    
    # Metadata
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.schedule_id is None:
            self.schedule_id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique schedule ID."""
        data = f"{self.name}{self.target}{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def calculate_next_run(self, after: Optional[datetime] = None) -> Optional[datetime]:
        """Calculate the next run time."""
        if after is None:
            after = datetime.now()
        
        if self.status in (ScheduleStatus.COMPLETED, ScheduleStatus.CANCELLED):
            return None
        
        if self.schedule_type == ScheduleType.ONCE:
            if self.run_at and self.run_at > after:
                return self.run_at
            return None
        
        elif self.schedule_type == ScheduleType.CRON:
            if self.cron_expression:
                cron = CronExpression.parse(self.cron_expression)
                return cron.next_run(after)
        
        elif self.schedule_type == ScheduleType.INTERVAL:
            if self.interval_minutes:
                if self.last_run:
                    return self.last_run + timedelta(minutes=self.interval_minutes)
                return after + timedelta(minutes=self.interval_minutes)
        
        elif self.schedule_type == ScheduleType.DAILY:
            if self.run_at:
                target_time = after.replace(
                    hour=self.run_at.hour,
                    minute=self.run_at.minute,
                    second=0,
                    microsecond=0
                )
                if target_time <= after:
                    target_time += timedelta(days=1)
                return target_time
        
        elif self.schedule_type == ScheduleType.WEEKLY:
            if self.days_of_week and self.run_at:
                for days_ahead in range(8):
                    check_date = after + timedelta(days=days_ahead)
                    if check_date.weekday() in self.days_of_week:
                        target_time = check_date.replace(
                            hour=self.run_at.hour,
                            minute=self.run_at.minute,
                            second=0,
                            microsecond=0
                        )
                        if target_time > after:
                            return target_time
        
        elif self.schedule_type == ScheduleType.MONTHLY:
            if self.days_of_month and self.run_at:
                for months_ahead in range(13):
                    check_month = after.month + months_ahead
                    check_year = after.year + (check_month - 1) // 12
                    check_month = ((check_month - 1) % 12) + 1
                    
                    for day in sorted(self.days_of_month):
                        try:
                            target_time = datetime(
                                year=check_year,
                                month=check_month,
                                day=day,
                                hour=self.run_at.hour,
                                minute=self.run_at.minute,
                            )
                            if target_time > after:
                                return target_time
                        except ValueError:
                            continue  # Invalid date (e.g., Feb 30)
        
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "schedule_id": self.schedule_id,
            "name": self.name,
            "target": self.target,
            "ports": self.ports,
            "schedule_type": self.schedule_type.value,
            "cron_expression": self.cron_expression,
            "interval_minutes": self.interval_minutes,
            "run_at": self.run_at.isoformat() if self.run_at else None,
            "days_of_week": self.days_of_week,
            "days_of_month": self.days_of_month,
            "scan_type": self.scan_type,
            "profile_name": self.profile_name,
            "options": self.options,
            "status": self.status.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "hooks": [h.to_dict() for h in self.hooks],
            "conditions": [c.to_dict() for c in self.conditions],
            "chain_next": self.chain_next,
            "chain_on_success_only": self.chain_on_success_only,
            "description": self.description,
            "tags": self.tags,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScheduledScan":
        """Create from dictionary."""
        return cls(
            schedule_id=data["schedule_id"],
            name=data["name"],
            target=data["target"],
            ports=data.get("ports", "1-1000"),
            schedule_type=ScheduleType(data.get("schedule_type", "once")),
            cron_expression=data.get("cron_expression"),
            interval_minutes=data.get("interval_minutes"),
            run_at=datetime.fromisoformat(data["run_at"]) if data.get("run_at") else None,
            days_of_week=data.get("days_of_week", []),
            days_of_month=data.get("days_of_month", []),
            scan_type=data.get("scan_type", "tcp"),
            profile_name=data.get("profile_name"),
            options=data.get("options", {}),
            status=ScheduleStatus(data.get("status", "pending")),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            last_run=datetime.fromisoformat(data["last_run"]) if data.get("last_run") else None,
            next_run=datetime.fromisoformat(data["next_run"]) if data.get("next_run") else None,
            run_count=data.get("run_count", 0),
            success_count=data.get("success_count", 0),
            failure_count=data.get("failure_count", 0),
            hooks=[ScanHook.from_dict(h) for h in data.get("hooks", [])],
            conditions=[ExecutionCondition.from_dict(c) for c in data.get("conditions", [])],
            chain_next=data.get("chain_next"),
            chain_on_success_only=data.get("chain_on_success_only", True),
            description=data.get("description"),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ScheduleRunResult:
    """Result of a scheduled scan execution."""
    run_id: str
    schedule_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    success: bool = False
    error_message: Optional[str] = None
    open_ports: int = 0
    closed_ports: int = 0
    filtered_ports: int = 0
    results_file: Optional[str] = None
    duration_seconds: float = 0.0
    hooks_executed: List[str] = field(default_factory=list)
    conditions_checked: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "schedule_id": self.schedule_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "success": self.success,
            "error_message": self.error_message,
            "open_ports": self.open_ports,
            "closed_ports": self.closed_ports,
            "filtered_ports": self.filtered_ports,
            "results_file": self.results_file,
            "duration_seconds": self.duration_seconds,
            "hooks_executed": self.hooks_executed,
            "conditions_checked": self.conditions_checked,
        }


# =============================================================================
# Schedule Storage (SQLite)
# =============================================================================

class ScheduleStorage:
    """SQLite-based storage for scheduled scans."""
    
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = Path.home() / ".spectrescan" / "schedules.db"
        
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Schedules table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schedules (
                    schedule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    ports TEXT DEFAULT '1-1000',
                    schedule_type TEXT NOT NULL,
                    config_json TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at TEXT,
                    last_run TEXT,
                    next_run TEXT,
                    run_count INTEGER DEFAULT 0,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0
                )
            """)
            
            # Run history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS run_history (
                    run_id TEXT PRIMARY KEY,
                    schedule_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    success INTEGER DEFAULT 0,
                    error_message TEXT,
                    open_ports INTEGER DEFAULT 0,
                    closed_ports INTEGER DEFAULT 0,
                    filtered_ports INTEGER DEFAULT 0,
                    results_file TEXT,
                    duration_seconds REAL DEFAULT 0,
                    details_json TEXT,
                    FOREIGN KEY (schedule_id) REFERENCES schedules(schedule_id)
                )
            """)
            
            # Create indexes
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_schedules_status 
                ON schedules(status)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_schedules_next_run 
                ON schedules(next_run)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_run_history_schedule 
                ON run_history(schedule_id)
            """)
            
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Get database connection context manager."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def save_schedule(self, schedule: ScheduledScan) -> None:
        """Save or update a scheduled scan."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO schedules 
                (schedule_id, name, target, ports, schedule_type, config_json,
                 status, created_at, last_run, next_run, run_count, 
                 success_count, failure_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                schedule.schedule_id,
                schedule.name,
                schedule.target,
                schedule.ports,
                schedule.schedule_type.value,
                json.dumps(schedule.to_dict()),
                schedule.status.value,
                schedule.created_at.isoformat() if schedule.created_at else None,
                schedule.last_run.isoformat() if schedule.last_run else None,
                schedule.next_run.isoformat() if schedule.next_run else None,
                schedule.run_count,
                schedule.success_count,
                schedule.failure_count,
            ))
            
            conn.commit()
    
    def get_schedule(self, schedule_id: str) -> Optional[ScheduledScan]:
        """Get a scheduled scan by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT config_json FROM schedules WHERE schedule_id = ?",
                (schedule_id,)
            )
            row = cursor.fetchone()
            
            if row:
                return ScheduledScan.from_dict(json.loads(row["config_json"]))
            return None
    
    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a scheduled scan."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM schedules WHERE schedule_id = ?",
                (schedule_id,)
            )
            conn.commit()
            return cursor.rowcount > 0
    
    def list_schedules(
        self,
        status: Optional[ScheduleStatus] = None,
        limit: Optional[int] = None,
    ) -> List[ScheduledScan]:
        """List all scheduled scans."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT config_json FROM schedules"
            params = []
            
            if status:
                query += " WHERE status = ?"
                params.append(status.value)
            
            query += " ORDER BY next_run ASC"
            
            if limit:
                query += " LIMIT ?"
                params.append(limit)
            
            cursor.execute(query, params)
            
            return [
                ScheduledScan.from_dict(json.loads(row["config_json"]))
                for row in cursor.fetchall()
            ]
    
    def get_due_schedules(self, before: Optional[datetime] = None) -> List[ScheduledScan]:
        """Get schedules that are due to run."""
        if before is None:
            before = datetime.now()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT config_json FROM schedules 
                WHERE status = 'pending' 
                AND next_run IS NOT NULL 
                AND next_run <= ?
                ORDER BY next_run ASC
            """, (before.isoformat(),))
            
            return [
                ScheduledScan.from_dict(json.loads(row["config_json"]))
                for row in cursor.fetchall()
            ]
    
    def save_run_result(self, result: ScheduleRunResult) -> None:
        """Save a run result."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO run_history 
                (run_id, schedule_id, started_at, completed_at, success,
                 error_message, open_ports, closed_ports, filtered_ports,
                 results_file, duration_seconds, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.run_id,
                result.schedule_id,
                result.started_at.isoformat(),
                result.completed_at.isoformat() if result.completed_at else None,
                1 if result.success else 0,
                result.error_message,
                result.open_ports,
                result.closed_ports,
                result.filtered_ports,
                result.results_file,
                result.duration_seconds,
                json.dumps(result.to_dict()),
            ))
            
            conn.commit()
    
    def get_run_history(
        self,
        schedule_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[ScheduleRunResult]:
        """Get run history."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if schedule_id:
                cursor.execute("""
                    SELECT details_json FROM run_history 
                    WHERE schedule_id = ?
                    ORDER BY started_at DESC
                    LIMIT ?
                """, (schedule_id, limit))
            else:
                cursor.execute("""
                    SELECT details_json FROM run_history 
                    ORDER BY started_at DESC
                    LIMIT ?
                """, (limit,))
            
            results = []
            for row in cursor.fetchall():
                data = json.loads(row["details_json"])
                results.append(ScheduleRunResult(
                    run_id=data["run_id"],
                    schedule_id=data["schedule_id"],
                    started_at=datetime.fromisoformat(data["started_at"]),
                    completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
                    success=data.get("success", False),
                    error_message=data.get("error_message"),
                    open_ports=data.get("open_ports", 0),
                    closed_ports=data.get("closed_ports", 0),
                    filtered_ports=data.get("filtered_ports", 0),
                    results_file=data.get("results_file"),
                    duration_seconds=data.get("duration_seconds", 0),
                    hooks_executed=data.get("hooks_executed", []),
                    conditions_checked=data.get("conditions_checked", []),
                ))
            
            return results


# =============================================================================
# Condition Evaluator
# =============================================================================

class ConditionEvaluator:
    """Evaluates execution conditions."""
    
    def __init__(self):
        self._custom_conditions: Dict[str, Callable] = {}
    
    def register_custom_condition(
        self,
        name: str,
        evaluator: Callable[[Dict[str, Any]], bool],
    ) -> None:
        """Register a custom condition evaluator."""
        self._custom_conditions[name] = evaluator
    
    async def evaluate(
        self,
        condition: ExecutionCondition,
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """
        Evaluate a condition.
        
        Returns:
            Tuple of (passed, reason)
        """
        if not condition.enabled:
            return True, "Condition disabled"
        
        try:
            if condition.condition_type == ConditionType.HOST_UP:
                return await self._check_host_up(condition, context)
            
            elif condition.condition_type == ConditionType.PORT_CHANGED:
                return self._check_port_changed(condition, context)
            
            elif condition.condition_type == ConditionType.SERVICE_CHANGED:
                return self._check_service_changed(condition, context)
            
            elif condition.condition_type == ConditionType.TIME_WINDOW:
                return self._check_time_window(condition, context)
            
            elif condition.condition_type == ConditionType.PREVIOUS_SUCCESS:
                return self._check_previous_success(condition, context)
            
            elif condition.condition_type == ConditionType.CUSTOM:
                return self._check_custom(condition, context)
            
            return True, "Unknown condition type - allowing"
        
        except Exception as e:
            logger.error(f"Error evaluating condition {condition.condition_id}: {e}")
            return False, f"Evaluation error: {str(e)}"
    
    async def _check_host_up(
        self,
        condition: ExecutionCondition,
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Check if host is up using ping."""
        import socket
        
        target = context.get("target", "")
        timeout = condition.parameters.get("timeout", 5)
        
        try:
            # Try to resolve and connect
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(target)
            return True, f"Host {target} is reachable"
        except socket.error as e:
            return False, f"Host {target} is not reachable: {e}"
    
    def _check_port_changed(
        self,
        condition: ExecutionCondition,
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Check if ports changed since last scan."""
        previous_results = context.get("previous_results", {})
        if not previous_results:
            return True, "No previous results - allowing scan"
        
        # This would compare with stored results
        return True, "Port change check passed"
    
    def _check_service_changed(
        self,
        condition: ExecutionCondition,
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Check if services changed since last scan."""
        previous_results = context.get("previous_results", {})
        if not previous_results:
            return True, "No previous results - allowing scan"
        
        return True, "Service change check passed"
    
    def _check_time_window(
        self,
        condition: ExecutionCondition,
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Check if current time is within allowed window."""
        params = condition.parameters
        start_hour = params.get("start_hour", 0)
        end_hour = params.get("end_hour", 24)
        allowed_days = params.get("allowed_days", list(range(7)))
        
        now = datetime.now()
        
        if now.weekday() not in allowed_days:
            return False, f"Day {now.strftime('%A')} not in allowed days"
        
        if not (start_hour <= now.hour < end_hour):
            return False, f"Hour {now.hour} not in window {start_hour}-{end_hour}"
        
        return True, "Within time window"
    
    def _check_previous_success(
        self,
        condition: ExecutionCondition,
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Check if previous run was successful."""
        last_result = context.get("last_result")
        if last_result is None:
            return True, "No previous run - allowing"
        
        if last_result.success:
            return True, "Previous run succeeded"
        return False, f"Previous run failed: {last_result.error_message}"
    
    def _check_custom(
        self,
        condition: ExecutionCondition,
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Check custom condition."""
        func_name = condition.parameters.get("function")
        if func_name and func_name in self._custom_conditions:
            try:
                result = self._custom_conditions[func_name](context)
                return result, "Custom condition evaluated"
            except Exception as e:
                return False, f"Custom condition error: {e}"
        
        return True, "Custom condition not found - allowing"


# =============================================================================
# Hook Executor
# =============================================================================

class HookExecutor:
    """Executes scan hooks."""
    
    def __init__(self):
        self._custom_hooks: Dict[str, Callable] = {}
    
    def register_hook(self, name: str, func: Callable) -> None:
        """Register a custom hook function."""
        self._custom_hooks[name] = func
    
    async def execute(
        self,
        hook: ScanHook,
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """
        Execute a hook.
        
        Returns:
            Tuple of (success, output/error)
        """
        if not hook.enabled:
            return True, "Hook disabled"
        
        try:
            # Check if it's a registered function
            if hook.action in self._custom_hooks:
                result = await self._execute_function(hook, context)
                return True, result
            
            # Otherwise treat as shell command
            return await self._execute_command(hook, context)
        
        except Exception as e:
            logger.error(f"Error executing hook {hook.hook_id}: {e}")
            return False, str(e)
    
    async def _execute_function(
        self,
        hook: ScanHook,
        context: Dict[str, Any],
    ) -> str:
        """Execute a registered function."""
        func = self._custom_hooks[hook.action]
        
        if asyncio.iscoroutinefunction(func):
            result = await asyncio.wait_for(
                func(context),
                timeout=hook.timeout
            )
        else:
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, func, context
                ),
                timeout=hook.timeout
            )
        
        return str(result) if result else "OK"
    
    async def _execute_command(
        self,
        hook: ScanHook,
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Execute a shell command."""
        # Substitute variables in command
        command = hook.action
        for key, value in context.items():
            command = command.replace(f"${{{key}}}", str(value))
            command = command.replace(f"${key}", str(value))
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=hook.timeout
            )
            
            if process.returncode == 0:
                return True, stdout.decode() if stdout else "OK"
            else:
                return False, stderr.decode() if stderr else f"Exit code: {process.returncode}"
        
        except asyncio.TimeoutError:
            return False, f"Command timed out after {hook.timeout}s"


# =============================================================================
# Scan Scheduler
# =============================================================================

class ScanScheduler:
    """
    Main scheduler for automated scans.
    
    Features:
    - Cron-like scheduling
    - One-time and recurring scans
    - Pre/post scan hooks
    - Conditional execution
    - Scan chaining
    """
    
    def __init__(
        self,
        storage: Optional[ScheduleStorage] = None,
        check_interval: int = 60,
    ):
        self.storage = storage or ScheduleStorage()
        self.check_interval = check_interval
        self.condition_evaluator = ConditionEvaluator()
        self.hook_executor = HookExecutor()
        
        self._running = False
        self._scheduler_task: Optional[asyncio.Task] = None
        self._active_scans: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()
        
        # Callbacks
        self._on_scan_start: Optional[Callable] = None
        self._on_scan_complete: Optional[Callable] = None
        self._on_scan_error: Optional[Callable] = None
    
    def set_callbacks(
        self,
        on_start: Optional[Callable] = None,
        on_complete: Optional[Callable] = None,
        on_error: Optional[Callable] = None,
    ) -> None:
        """Set callback functions for scan events."""
        self._on_scan_start = on_start
        self._on_scan_complete = on_complete
        self._on_scan_error = on_error
    
    # -------------------------------------------------------------------------
    # Schedule Management
    # -------------------------------------------------------------------------
    
    def add_schedule(self, schedule: ScheduledScan) -> ScheduledScan:
        """Add a new scheduled scan."""
        # Calculate next run time
        schedule.next_run = schedule.calculate_next_run()
        
        # Save to storage
        self.storage.save_schedule(schedule)
        
        logger.info(f"Added schedule '{schedule.name}' (ID: {schedule.schedule_id})")
        return schedule
    
    def create_schedule(
        self,
        name: str,
        target: str,
        ports: str = "1-1000",
        schedule_type: ScheduleType = ScheduleType.ONCE,
        cron_expression: Optional[str] = None,
        interval_minutes: Optional[int] = None,
        run_at: Optional[datetime] = None,
        days_of_week: Optional[List[int]] = None,
        scan_type: str = "tcp",
        profile_name: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> ScheduledScan:
        """Create and add a new scheduled scan."""
        schedule = ScheduledScan(
            schedule_id=None,
            name=name,
            target=target,
            ports=ports,
            schedule_type=schedule_type,
            cron_expression=cron_expression,
            interval_minutes=interval_minutes,
            run_at=run_at,
            days_of_week=days_of_week or [],
            scan_type=scan_type,
            profile_name=profile_name,
            options=options or {},
            description=description,
            tags=tags or [],
        )
        
        return self.add_schedule(schedule)
    
    def get_schedule(self, schedule_id: str) -> Optional[ScheduledScan]:
        """Get a schedule by ID."""
        return self.storage.get_schedule(schedule_id)
    
    def list_schedules(
        self,
        status: Optional[ScheduleStatus] = None,
        limit: Optional[int] = None,
    ) -> List[ScheduledScan]:
        """List all schedules."""
        return self.storage.list_schedules(status=status, limit=limit)
    
    def update_schedule(self, schedule: ScheduledScan) -> None:
        """Update an existing schedule."""
        schedule.next_run = schedule.calculate_next_run()
        self.storage.save_schedule(schedule)
        logger.info(f"Updated schedule '{schedule.name}' (ID: {schedule.schedule_id})")
    
    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule."""
        result = self.storage.delete_schedule(schedule_id)
        if result:
            logger.info(f"Deleted schedule ID: {schedule_id}")
        return result
    
    def pause_schedule(self, schedule_id: str) -> bool:
        """Pause a schedule."""
        schedule = self.get_schedule(schedule_id)
        if schedule:
            schedule.status = ScheduleStatus.PAUSED
            self.storage.save_schedule(schedule)
            logger.info(f"Paused schedule '{schedule.name}'")
            return True
        return False
    
    def resume_schedule(self, schedule_id: str) -> bool:
        """Resume a paused schedule."""
        schedule = self.get_schedule(schedule_id)
        if schedule:
            schedule.status = ScheduleStatus.PENDING
            schedule.next_run = schedule.calculate_next_run()
            self.storage.save_schedule(schedule)
            logger.info(f"Resumed schedule '{schedule.name}'")
            return True
        return False
    
    # -------------------------------------------------------------------------
    # Hook and Condition Management
    # -------------------------------------------------------------------------
    
    def add_hook(
        self,
        schedule_id: str,
        hook_type: HookType,
        action: str,
        timeout: int = 60,
    ) -> Optional[ScanHook]:
        """Add a hook to a schedule."""
        schedule = self.get_schedule(schedule_id)
        if not schedule:
            return None
        
        hook = ScanHook(
            hook_id=hashlib.md5(f"{schedule_id}{hook_type.value}{action}".encode()).hexdigest()[:8],
            hook_type=hook_type,
            action=action,
            timeout=timeout,
        )
        
        schedule.hooks.append(hook)
        self.storage.save_schedule(schedule)
        
        return hook
    
    def add_condition(
        self,
        schedule_id: str,
        condition_type: ConditionType,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[ExecutionCondition]:
        """Add a condition to a schedule."""
        schedule = self.get_schedule(schedule_id)
        if not schedule:
            return None
        
        condition = ExecutionCondition(
            condition_id=hashlib.md5(
                f"{schedule_id}{condition_type.value}".encode()
            ).hexdigest()[:8],
            condition_type=condition_type,
            parameters=parameters or {},
        )
        
        schedule.conditions.append(condition)
        self.storage.save_schedule(schedule)
        
        return condition
    
    def set_chain(
        self,
        schedule_id: str,
        next_schedule_id: str,
        on_success_only: bool = True,
    ) -> bool:
        """Set up scan chaining."""
        schedule = self.get_schedule(schedule_id)
        if not schedule:
            return False
        
        schedule.chain_next = next_schedule_id
        schedule.chain_on_success_only = on_success_only
        self.storage.save_schedule(schedule)
        
        return True
    
    # -------------------------------------------------------------------------
    # Scheduler Daemon
    # -------------------------------------------------------------------------
    
    async def start(self) -> None:
        """Start the scheduler daemon."""
        if self._running:
            logger.warning("Scheduler already running")
            return
        
        self._running = True
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Scheduler daemon started")
    
    async def stop(self) -> None:
        """Stop the scheduler daemon."""
        self._running = False
        
        # Cancel scheduler task
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        
        # Cancel active scans
        for task in self._active_scans.values():
            task.cancel()
        
        logger.info("Scheduler daemon stopped")
    
    async def _scheduler_loop(self) -> None:
        """Main scheduler loop."""
        logger.info(f"Scheduler loop started (check interval: {self.check_interval}s)")
        
        while self._running:
            try:
                # Get due schedules
                due_schedules = self.storage.get_due_schedules()
                
                for schedule in due_schedules:
                    if schedule.schedule_id not in self._active_scans:
                        # Start scan in background
                        task = asyncio.create_task(
                            self._execute_schedule(schedule)
                        )
                        self._active_scans[schedule.schedule_id] = task
                
                # Clean up completed tasks
                completed = [
                    sid for sid, task in self._active_scans.items()
                    if task.done()
                ]
                for sid in completed:
                    del self._active_scans[sid]
                
                # Wait for next check
                await asyncio.sleep(self.check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(self.check_interval)
    
    async def _execute_schedule(self, schedule: ScheduledScan) -> None:
        """Execute a scheduled scan."""
        run_id = hashlib.md5(
            f"{schedule.schedule_id}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]
        
        result = ScheduleRunResult(
            run_id=run_id,
            schedule_id=schedule.schedule_id,
            started_at=datetime.now(),
        )
        
        try:
            # Update status
            schedule.status = ScheduleStatus.RUNNING
            self.storage.save_schedule(schedule)
            
            # Check conditions
            context = {
                "target": schedule.target,
                "ports": schedule.ports,
                "schedule": schedule,
                "last_result": self._get_last_result(schedule.schedule_id),
            }
            
            for condition in schedule.conditions:
                passed, reason = await self.condition_evaluator.evaluate(
                    condition, context
                )
                result.conditions_checked.append(
                    f"{condition.condition_type.value}: {reason}"
                )
                
                if not passed:
                    logger.info(
                        f"Schedule '{schedule.name}' skipped: {reason}"
                    )
                    result.success = False
                    result.error_message = f"Condition not met: {reason}"
                    self._finalize_schedule(schedule, result, skipped=True)
                    return
            
            # Execute pre-scan hooks
            for hook in schedule.hooks:
                if hook.hook_type == HookType.PRE_SCAN:
                    success, output = await self.hook_executor.execute(
                        hook, context
                    )
                    result.hooks_executed.append(f"pre_scan:{hook.hook_id}")
                    if not success:
                        logger.warning(f"Pre-scan hook failed: {output}")
            
            # Notify scan start
            if self._on_scan_start:
                await self._call_callback(self._on_scan_start, schedule, result)
            
            # Execute the scan
            scan_result = await self._run_scan(schedule)
            
            # Update result
            result.success = True
            result.open_ports = scan_result.get("open_ports", 0)
            result.closed_ports = scan_result.get("closed_ports", 0)
            result.filtered_ports = scan_result.get("filtered_ports", 0)
            result.results_file = scan_result.get("results_file")
            
            # Execute post-scan hooks
            context["scan_result"] = scan_result
            for hook in schedule.hooks:
                if hook.hook_type == HookType.POST_SCAN:
                    success, output = await self.hook_executor.execute(
                        hook, context
                    )
                    result.hooks_executed.append(f"post_scan:{hook.hook_id}")
            
            # Notify completion
            if self._on_scan_complete:
                await self._call_callback(self._on_scan_complete, schedule, result)
            
            # Handle chain
            if schedule.chain_next:
                await self._execute_chain(schedule, result)
            
        except Exception as e:
            logger.error(f"Schedule execution error: {e}")
            result.success = False
            result.error_message = str(e)
            
            # Execute error hooks
            context["error"] = str(e)
            for hook in schedule.hooks:
                if hook.hook_type == HookType.ON_ERROR:
                    await self.hook_executor.execute(hook, context)
                    result.hooks_executed.append(f"on_error:{hook.hook_id}")
            
            # Notify error
            if self._on_scan_error:
                await self._call_callback(self._on_scan_error, schedule, result)
        
        finally:
            result.completed_at = datetime.now()
            result.duration_seconds = (
                result.completed_at - result.started_at
            ).total_seconds()
            
            self._finalize_schedule(schedule, result)
    
    async def _run_scan(self, schedule: ScheduledScan) -> Dict[str, Any]:
        """Run the actual scan."""
        from spectrescan.core.scanner import PortScanner
        from spectrescan.core.utils import parse_ports
        
        # Parse ports
        ports = parse_ports(schedule.ports)
        
        # Create scanner with options
        scanner = PortScanner(
            timeout=schedule.options.get("timeout", 2.0),
            threads=schedule.options.get("threads", 100),
        )
        
        # Run scan
        results = scanner.scan(
            target=schedule.target,
            ports=ports,
        )
        
        # Summarize results
        open_ports = sum(1 for r in results if r.state == "open")
        closed_ports = sum(1 for r in results if r.state == "closed")
        filtered_ports = sum(1 for r in results if r.state == "filtered")
        
        # Save results to file
        results_dir = Path.home() / ".spectrescan" / "scheduled_results"
        results_dir.mkdir(parents=True, exist_ok=True)
        
        results_file = results_dir / f"{schedule.schedule_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(results_file, "w") as f:
            json.dump({
                "schedule_id": schedule.schedule_id,
                "target": schedule.target,
                "ports": schedule.ports,
                "timestamp": datetime.now().isoformat(),
                "results": [
                    {
                        "host": r.host,
                        "port": r.port,
                        "state": r.state,
                        "service": r.service,
                        "banner": r.banner,
                    }
                    for r in results
                ],
            }, f, indent=2)
        
        return {
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "filtered_ports": filtered_ports,
            "results_file": str(results_file),
            "results": results,
        }
    
    def _finalize_schedule(
        self,
        schedule: ScheduledScan,
        result: ScheduleRunResult,
        skipped: bool = False,
    ) -> None:
        """Finalize schedule after execution."""
        # Update schedule stats
        schedule.last_run = result.started_at
        schedule.run_count += 1
        
        if result.success:
            schedule.success_count += 1
            schedule.status = ScheduleStatus.PENDING
        else:
            schedule.failure_count += 1
            schedule.status = ScheduleStatus.FAILED if not skipped else ScheduleStatus.PENDING
        
        # Calculate next run
        if schedule.schedule_type == ScheduleType.ONCE:
            schedule.status = ScheduleStatus.COMPLETED
            schedule.next_run = None
        else:
            schedule.next_run = schedule.calculate_next_run()
        
        # Save schedule and result
        self.storage.save_schedule(schedule)
        self.storage.save_run_result(result)
    
    def _get_last_result(self, schedule_id: str) -> Optional[ScheduleRunResult]:
        """Get last run result for a schedule."""
        history = self.storage.get_run_history(schedule_id, limit=1)
        return history[0] if history else None
    
    async def _execute_chain(
        self,
        schedule: ScheduledScan,
        result: ScheduleRunResult,
    ) -> None:
        """Execute chained schedule."""
        if schedule.chain_on_success_only and not result.success:
            logger.info(f"Skipping chain - previous scan failed")
            return
        
        next_schedule = self.get_schedule(schedule.chain_next)
        if next_schedule:
            logger.info(f"Executing chained schedule: {next_schedule.name}")
            await self._execute_schedule(next_schedule)
    
    async def _call_callback(
        self,
        callback: Callable,
        schedule: ScheduledScan,
        result: ScheduleRunResult,
    ) -> None:
        """Call a callback function safely."""
        try:
            if asyncio.iscoroutinefunction(callback):
                await callback(schedule, result)
            else:
                callback(schedule, result)
        except Exception as e:
            logger.error(f"Callback error: {e}")
    
    # -------------------------------------------------------------------------
    # Manual Execution
    # -------------------------------------------------------------------------
    
    async def run_now(self, schedule_id: str) -> Optional[ScheduleRunResult]:
        """Manually trigger a scheduled scan."""
        schedule = self.get_schedule(schedule_id)
        if not schedule:
            return None
        
        # Run immediately in background
        task = asyncio.create_task(self._execute_schedule(schedule))
        self._active_scans[schedule_id] = task
        
        # Wait for completion
        await task
        
        # Return latest result
        return self._get_last_result(schedule_id)
    
    def get_run_history(
        self,
        schedule_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[ScheduleRunResult]:
        """Get run history."""
        return self.storage.get_run_history(schedule_id, limit)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scheduler statistics."""
        schedules = self.list_schedules()
        history = self.get_run_history(limit=1000)
        
        return {
            "total_schedules": len(schedules),
            "active_schedules": sum(
                1 for s in schedules
                if s.status in (ScheduleStatus.PENDING, ScheduleStatus.RUNNING)
            ),
            "paused_schedules": sum(
                1 for s in schedules
                if s.status == ScheduleStatus.PAUSED
            ),
            "total_runs": len(history),
            "successful_runs": sum(1 for r in history if r.success),
            "failed_runs": sum(1 for r in history if not r.success),
            "total_open_ports_found": sum(r.open_ports for r in history),
            "avg_duration_seconds": (
                sum(r.duration_seconds for r in history) / len(history)
                if history else 0
            ),
        }


# =============================================================================
# CLI Helper Functions
# =============================================================================

def parse_cron_shorthand(shorthand: str) -> str:
    """
    Parse cron shorthand to full expression.
    
    Supports:
    - @hourly: 0 * * * *
    - @daily: 0 0 * * *
    - @weekly: 0 0 * * 0
    - @monthly: 0 0 1 * *
    - @yearly: 0 0 1 1 *
    """
    shortcuts = {
        "@hourly": "0 * * * *",
        "@daily": "0 0 * * *",
        "@midnight": "0 0 * * *",
        "@weekly": "0 0 * * 0",
        "@monthly": "0 0 1 * *",
        "@yearly": "0 0 1 1 *",
        "@annually": "0 0 1 1 *",
    }
    
    return shortcuts.get(shorthand.lower(), shorthand)


def parse_interval(interval_str: str) -> int:
    """
    Parse interval string to minutes.
    
    Supports:
    - 30m, 30min, 30 minutes
    - 2h, 2hr, 2 hours
    - 1d, 1 day
    """
    interval_str = interval_str.lower().strip()
    
    # Patterns
    patterns = [
        (r"^(\d+)\s*m(?:in(?:ute)?s?)?$", 1),      # minutes
        (r"^(\d+)\s*h(?:(?:ou)?rs?)?$", 60),       # hours
        (r"^(\d+)\s*d(?:ays?)?$", 1440),           # days
        (r"^(\d+)\s*w(?:eeks?)?$", 10080),         # weeks
    ]
    
    for pattern, multiplier in patterns:
        match = re.match(pattern, interval_str)
        if match:
            return int(match.group(1)) * multiplier
    
    # Try as plain number (assume minutes)
    try:
        return int(interval_str)
    except ValueError:
        raise ValueError(f"Invalid interval format: {interval_str}")


def format_next_run(dt: Optional[datetime]) -> str:
    """Format next run time for display."""
    if dt is None:
        return "N/A"
    
    now = datetime.now()
    delta = dt - now
    
    if delta.total_seconds() < 0:
        return "Overdue"
    elif delta.total_seconds() < 60:
        return "< 1 minute"
    elif delta.total_seconds() < 3600:
        minutes = int(delta.total_seconds() / 60)
        return f"in {minutes} minute{'s' if minutes != 1 else ''}"
    elif delta.total_seconds() < 86400:
        hours = int(delta.total_seconds() / 3600)
        return f"in {hours} hour{'s' if hours != 1 else ''}"
    else:
        days = int(delta.total_seconds() / 86400)
        return f"in {days} day{'s' if days != 1 else ''}"
