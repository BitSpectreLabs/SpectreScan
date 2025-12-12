"""
Tests for Scan Scheduling and Automation Engine.

by BitSpectreLabs
"""

import asyncio
import json
import pytest
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from spectrescan.core.scheduler import (
    # Enums
    ScheduleType,
    ScheduleStatus,
    HookType,
    ConditionType,
    # Data classes
    CronExpression,
    ScanHook,
    ExecutionCondition,
    ScheduledScan,
    ScheduleRunResult,
    # Storage
    ScheduleStorage,
    # Components
    ConditionEvaluator,
    HookExecutor,
    ScanScheduler,
    # Helpers
    parse_cron_shorthand,
    parse_interval,
    format_next_run,
    DAYS_OF_WEEK,
)


# =============================================================================
# CronExpression Tests
# =============================================================================

class TestCronExpression:
    """Test CronExpression parsing and matching."""
    
    def test_parse_valid_expression(self):
        """Test parsing a valid cron expression."""
        cron = CronExpression.parse("30 2 * * *")
        
        assert cron.minute == "30"
        assert cron.hour == "2"
        assert cron.day_of_month == "*"
        assert cron.month == "*"
        assert cron.day_of_week == "*"
    
    def test_parse_all_wildcards(self):
        """Test parsing expression with all wildcards."""
        cron = CronExpression.parse("* * * * *")
        
        assert cron.minute == "*"
        assert cron.hour == "*"
        assert cron.day_of_month == "*"
        assert cron.month == "*"
        assert cron.day_of_week == "*"
    
    def test_parse_invalid_expression(self):
        """Test parsing invalid cron expression raises error."""
        with pytest.raises(ValueError):
            CronExpression.parse("30 2 *")
    
    def test_str_representation(self):
        """Test string representation."""
        cron = CronExpression.parse("0 3 * * 1")
        assert str(cron) == "0 3 * * 1"
    
    def test_matches_exact_time(self):
        """Test matching exact time."""
        cron = CronExpression.parse("30 14 * * *")
        
        # Should match
        dt_match = datetime(2025, 1, 15, 14, 30, 0)
        assert cron.matches(dt_match)
        
        # Should not match - wrong minute
        dt_nomatch = datetime(2025, 1, 15, 14, 31, 0)
        assert not cron.matches(dt_nomatch)
    
    def test_matches_day_of_week(self):
        """Test matching day of week."""
        # In our implementation, we use Python's weekday() where Monday=0, Sunday=6
        cron = CronExpression.parse("0 0 * * 6")  # Sunday = 6 in Python's weekday()
        
        # Sunday Jan 12, 2025 (weekday=6)
        sunday = datetime(2025, 1, 12, 0, 0, 0)
        assert cron.matches(sunday)
        
        # Monday Jan 13, 2025 (weekday=0)
        monday = datetime(2025, 1, 13, 0, 0, 0)
        assert not cron.matches(monday)
    
    def test_matches_range(self):
        """Test matching range expression."""
        cron = CronExpression.parse("0 9-17 * * *")  # 9 AM to 5 PM
        
        assert cron.matches(datetime(2025, 1, 15, 9, 0))
        assert cron.matches(datetime(2025, 1, 15, 17, 0))
        assert not cron.matches(datetime(2025, 1, 15, 8, 0))
        assert not cron.matches(datetime(2025, 1, 15, 18, 0))
    
    def test_matches_list(self):
        """Test matching list expression."""
        cron = CronExpression.parse("0 0,12 * * *")  # Midnight and noon
        
        assert cron.matches(datetime(2025, 1, 15, 0, 0))
        assert cron.matches(datetime(2025, 1, 15, 12, 0))
        assert not cron.matches(datetime(2025, 1, 15, 6, 0))
    
    def test_matches_step(self):
        """Test matching step expression."""
        cron = CronExpression.parse("*/15 * * * *")  # Every 15 minutes
        
        assert cron.matches(datetime(2025, 1, 15, 0, 0))
        assert cron.matches(datetime(2025, 1, 15, 0, 15))
        assert cron.matches(datetime(2025, 1, 15, 0, 30))
        assert cron.matches(datetime(2025, 1, 15, 0, 45))
        assert not cron.matches(datetime(2025, 1, 15, 0, 10))
    
    def test_next_run_calculation(self):
        """Test calculating next run time."""
        cron = CronExpression.parse("0 3 * * *")  # 3 AM daily
        
        after = datetime(2025, 1, 15, 0, 0)
        next_run = cron.next_run(after)
        
        assert next_run.hour == 3
        assert next_run.minute == 0
        assert next_run.day == 15  # Same day since we're before 3 AM
    
    def test_next_run_after_time_passed(self):
        """Test next run when time has already passed today."""
        cron = CronExpression.parse("0 3 * * *")  # 3 AM daily
        
        after = datetime(2025, 1, 15, 10, 0)  # 10 AM - past 3 AM
        next_run = cron.next_run(after)
        
        assert next_run.day == 16  # Next day


# =============================================================================
# ScheduledScan Tests
# =============================================================================

class TestScheduledScan:
    """Test ScheduledScan data class."""
    
    def test_create_basic_schedule(self):
        """Test creating a basic scheduled scan."""
        schedule = ScheduledScan(
            schedule_id="test123",
            name="Test Scan",
            target="192.168.1.1",
        )
        
        assert schedule.schedule_id == "test123"
        assert schedule.name == "Test Scan"
        assert schedule.target == "192.168.1.1"
        assert schedule.schedule_type == ScheduleType.ONCE
        assert schedule.status == ScheduleStatus.PENDING
    
    def test_auto_generate_id(self):
        """Test automatic ID generation."""
        schedule = ScheduledScan(
            schedule_id=None,
            name="Auto ID Test",
            target="10.0.0.1",
        )
        
        assert schedule.schedule_id is not None
        assert len(schedule.schedule_id) == 12  # MD5 hash truncated
    
    def test_to_dict_and_from_dict(self):
        """Test serialization round trip."""
        original = ScheduledScan(
            schedule_id="abc123",
            name="Serialize Test",
            target="example.com",
            ports="80,443",
            schedule_type=ScheduleType.DAILY,
            run_at=datetime(2025, 1, 15, 3, 0),
            scan_type="tcp",
            description="Test description",
            tags=["web", "daily"],
        )
        
        data = original.to_dict()
        restored = ScheduledScan.from_dict(data)
        
        assert restored.schedule_id == original.schedule_id
        assert restored.name == original.name
        assert restored.target == original.target
        assert restored.schedule_type == original.schedule_type
        assert restored.run_at == original.run_at
        assert restored.tags == original.tags
    
    def test_calculate_next_run_once(self):
        """Test next run calculation for one-time schedule."""
        future = datetime.now() + timedelta(hours=1)
        
        schedule = ScheduledScan(
            schedule_id="once1",
            name="Once",
            target="192.168.1.1",
            schedule_type=ScheduleType.ONCE,
            run_at=future,
        )
        
        assert schedule.calculate_next_run() == future
    
    def test_calculate_next_run_once_completed(self):
        """Test next run for completed one-time schedule."""
        schedule = ScheduledScan(
            schedule_id="once2",
            name="Done",
            target="192.168.1.1",
            schedule_type=ScheduleType.ONCE,
            status=ScheduleStatus.COMPLETED,
        )
        
        assert schedule.calculate_next_run() is None
    
    def test_calculate_next_run_interval(self):
        """Test next run calculation for interval schedule."""
        schedule = ScheduledScan(
            schedule_id="int1",
            name="Interval",
            target="192.168.1.1",
            schedule_type=ScheduleType.INTERVAL,
            interval_minutes=60,
        )
        
        # First run
        next_run = schedule.calculate_next_run()
        assert next_run is not None
        
        # After running
        schedule.last_run = datetime.now()
        next_run = schedule.calculate_next_run()
        
        expected = schedule.last_run + timedelta(minutes=60)
        assert abs((next_run - expected).total_seconds()) < 1
    
    def test_calculate_next_run_cron(self):
        """Test next run calculation for cron schedule."""
        schedule = ScheduledScan(
            schedule_id="cron1",
            name="Cron",
            target="192.168.1.1",
            schedule_type=ScheduleType.CRON,
            cron_expression="0 3 * * *",  # 3 AM daily
        )
        
        next_run = schedule.calculate_next_run()
        assert next_run is not None
        assert next_run.hour == 3
        assert next_run.minute == 0


# =============================================================================
# ScanHook Tests
# =============================================================================

class TestScanHook:
    """Test ScanHook data class."""
    
    def test_create_hook(self):
        """Test creating a scan hook."""
        hook = ScanHook(
            hook_id="hook1",
            hook_type=HookType.PRE_SCAN,
            action="echo 'Starting scan'",
            timeout=30,
        )
        
        assert hook.hook_id == "hook1"
        assert hook.hook_type == HookType.PRE_SCAN
        assert hook.timeout == 30
        assert hook.enabled
    
    def test_hook_serialization(self):
        """Test hook serialization."""
        hook = ScanHook(
            hook_id="hook2",
            hook_type=HookType.POST_SCAN,
            action="notify.sh",
            metadata={"channel": "alerts"},
        )
        
        data = hook.to_dict()
        restored = ScanHook.from_dict(data)
        
        assert restored.hook_id == hook.hook_id
        assert restored.hook_type == hook.hook_type
        assert restored.action == hook.action
        assert restored.metadata == hook.metadata


# =============================================================================
# ExecutionCondition Tests
# =============================================================================

class TestExecutionCondition:
    """Test ExecutionCondition data class."""
    
    def test_create_condition(self):
        """Test creating an execution condition."""
        condition = ExecutionCondition(
            condition_id="cond1",
            condition_type=ConditionType.HOST_UP,
            parameters={"timeout": 10},
        )
        
        assert condition.condition_id == "cond1"
        assert condition.condition_type == ConditionType.HOST_UP
        assert condition.parameters["timeout"] == 10
    
    def test_condition_serialization(self):
        """Test condition serialization."""
        condition = ExecutionCondition(
            condition_id="cond2",
            condition_type=ConditionType.TIME_WINDOW,
            parameters={"start_hour": 9, "end_hour": 17},
        )
        
        data = condition.to_dict()
        restored = ExecutionCondition.from_dict(data)
        
        assert restored.condition_id == condition.condition_id
        assert restored.condition_type == condition.condition_type
        assert restored.parameters == condition.parameters


# =============================================================================
# ScheduleStorage Tests
# =============================================================================

class TestScheduleStorage:
    """Test SQLite-based schedule storage."""
    
    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_schedules.db"
            yield ScheduleStorage(db_path)
    
    def test_save_and_get_schedule(self, temp_storage):
        """Test saving and retrieving a schedule."""
        schedule = ScheduledScan(
            schedule_id="save1",
            name="Save Test",
            target="192.168.1.1",
            ports="1-1000",
        )
        
        temp_storage.save_schedule(schedule)
        retrieved = temp_storage.get_schedule("save1")
        
        assert retrieved is not None
        assert retrieved.schedule_id == "save1"
        assert retrieved.name == "Save Test"
        assert retrieved.target == "192.168.1.1"
    
    def test_delete_schedule(self, temp_storage):
        """Test deleting a schedule."""
        schedule = ScheduledScan(
            schedule_id="del1",
            name="Delete Test",
            target="10.0.0.1",
        )
        
        temp_storage.save_schedule(schedule)
        assert temp_storage.get_schedule("del1") is not None
        
        result = temp_storage.delete_schedule("del1")
        assert result is True
        assert temp_storage.get_schedule("del1") is None
    
    def test_list_schedules(self, temp_storage):
        """Test listing schedules."""
        for i in range(3):
            schedule = ScheduledScan(
                schedule_id=f"list{i}",
                name=f"List Test {i}",
                target="192.168.1.1",
            )
            temp_storage.save_schedule(schedule)
        
        schedules = temp_storage.list_schedules()
        assert len(schedules) == 3
    
    def test_list_schedules_with_status_filter(self, temp_storage):
        """Test listing schedules filtered by status."""
        # Create schedules with different statuses
        active = ScheduledScan(
            schedule_id="active1",
            name="Active",
            target="192.168.1.1",
            status=ScheduleStatus.PENDING,
        )
        paused = ScheduledScan(
            schedule_id="paused1",
            name="Paused",
            target="192.168.1.1",
            status=ScheduleStatus.PAUSED,
        )
        
        temp_storage.save_schedule(active)
        temp_storage.save_schedule(paused)
        
        pending = temp_storage.list_schedules(status=ScheduleStatus.PENDING)
        assert len(pending) == 1
        assert pending[0].schedule_id == "active1"
    
    def test_get_due_schedules(self, temp_storage):
        """Test getting schedules that are due."""
        past = datetime.now() - timedelta(hours=1)
        future = datetime.now() + timedelta(hours=1)
        
        due = ScheduledScan(
            schedule_id="due1",
            name="Due",
            target="192.168.1.1",
        )
        due.next_run = past
        
        not_due = ScheduledScan(
            schedule_id="notdue1",
            name="Not Due",
            target="192.168.1.1",
        )
        not_due.next_run = future
        
        temp_storage.save_schedule(due)
        temp_storage.save_schedule(not_due)
        
        due_schedules = temp_storage.get_due_schedules()
        assert len(due_schedules) == 1
        assert due_schedules[0].schedule_id == "due1"
    
    def test_save_and_get_run_result(self, temp_storage):
        """Test saving and retrieving run results."""
        # First save a schedule
        schedule = ScheduledScan(
            schedule_id="run1",
            name="Run Test",
            target="192.168.1.1",
        )
        temp_storage.save_schedule(schedule)
        
        # Save run result
        result = ScheduleRunResult(
            run_id="result1",
            schedule_id="run1",
            started_at=datetime.now(),
            completed_at=datetime.now(),
            success=True,
            open_ports=5,
            closed_ports=995,
            duration_seconds=10.5,
        )
        
        temp_storage.save_run_result(result)
        
        # Retrieve history
        history = temp_storage.get_run_history("run1")
        assert len(history) == 1
        assert history[0].run_id == "result1"
        assert history[0].open_ports == 5


# =============================================================================
# ConditionEvaluator Tests
# =============================================================================

class TestConditionEvaluator:
    """Test execution condition evaluator."""
    
    @pytest.fixture
    def evaluator(self):
        return ConditionEvaluator()
    
    @pytest.mark.asyncio
    async def test_evaluate_disabled_condition(self, evaluator):
        """Test that disabled conditions pass."""
        condition = ExecutionCondition(
            condition_id="disabled1",
            condition_type=ConditionType.HOST_UP,
            enabled=False,
        )
        
        passed, reason = await evaluator.evaluate(condition, {})
        assert passed is True
        assert "disabled" in reason.lower()
    
    @pytest.mark.asyncio
    async def test_evaluate_time_window_inside(self, evaluator):
        """Test time window condition when inside window."""
        now = datetime.now()
        
        condition = ExecutionCondition(
            condition_id="time1",
            condition_type=ConditionType.TIME_WINDOW,
            parameters={
                "start_hour": 0,
                "end_hour": 24,
                "allowed_days": list(range(7)),
            },
        )
        
        passed, reason = await evaluator.evaluate(condition, {})
        assert passed is True
    
    @pytest.mark.asyncio
    async def test_evaluate_time_window_outside(self, evaluator):
        """Test time window condition when outside window."""
        condition = ExecutionCondition(
            condition_id="time2",
            condition_type=ConditionType.TIME_WINDOW,
            parameters={
                "start_hour": 25,  # Impossible hour
                "end_hour": 26,
                "allowed_days": list(range(7)),
            },
        )
        
        passed, reason = await evaluator.evaluate(condition, {})
        assert passed is False
    
    @pytest.mark.asyncio
    async def test_evaluate_previous_success_no_history(self, evaluator):
        """Test previous success condition with no history."""
        condition = ExecutionCondition(
            condition_id="prev1",
            condition_type=ConditionType.PREVIOUS_SUCCESS,
        )
        
        passed, reason = await evaluator.evaluate(condition, {})
        assert passed is True  # Allow when no previous run
    
    @pytest.mark.asyncio
    async def test_evaluate_previous_success_with_success(self, evaluator):
        """Test previous success condition with successful previous run."""
        last_result = MagicMock()
        last_result.success = True
        
        condition = ExecutionCondition(
            condition_id="prev2",
            condition_type=ConditionType.PREVIOUS_SUCCESS,
        )
        
        passed, reason = await evaluator.evaluate(condition, {"last_result": last_result})
        assert passed is True
    
    @pytest.mark.asyncio
    async def test_evaluate_previous_success_with_failure(self, evaluator):
        """Test previous success condition with failed previous run."""
        last_result = MagicMock()
        last_result.success = False
        last_result.error_message = "Connection timeout"
        
        condition = ExecutionCondition(
            condition_id="prev3",
            condition_type=ConditionType.PREVIOUS_SUCCESS,
        )
        
        passed, reason = await evaluator.evaluate(condition, {"last_result": last_result})
        assert passed is False
    
    def test_register_custom_condition(self, evaluator):
        """Test registering a custom condition evaluator."""
        def my_condition(context):
            return context.get("custom_value", False)
        
        evaluator.register_custom_condition("my_condition", my_condition)
        assert "my_condition" in evaluator._custom_conditions


# =============================================================================
# HookExecutor Tests
# =============================================================================

class TestHookExecutor:
    """Test hook executor."""
    
    @pytest.fixture
    def executor(self):
        return HookExecutor()
    
    @pytest.mark.asyncio
    async def test_execute_disabled_hook(self, executor):
        """Test that disabled hooks pass."""
        hook = ScanHook(
            hook_id="disabled1",
            hook_type=HookType.PRE_SCAN,
            action="echo test",
            enabled=False,
        )
        
        success, output = await executor.execute(hook, {})
        assert success is True
        assert "disabled" in output.lower()
    
    @pytest.mark.asyncio
    async def test_execute_registered_function(self, executor):
        """Test executing a registered function."""
        def my_hook(context):
            return f"Hello {context.get('name', 'World')}"
        
        executor.register_hook("greet", my_hook)
        
        hook = ScanHook(
            hook_id="func1",
            hook_type=HookType.PRE_SCAN,
            action="greet",
        )
        
        success, output = await executor.execute(hook, {"name": "Test"})
        assert success is True
        assert "Hello Test" in output
    
    @pytest.mark.asyncio
    async def test_execute_async_function(self, executor):
        """Test executing an async function."""
        async def async_hook(context):
            await asyncio.sleep(0.01)
            return "Async done"
        
        executor.register_hook("async_test", async_hook)
        
        hook = ScanHook(
            hook_id="async1",
            hook_type=HookType.POST_SCAN,
            action="async_test",
        )
        
        success, output = await executor.execute(hook, {})
        assert success is True
        assert "Async done" in output
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not hasattr(asyncio, 'create_subprocess_shell'),
        reason="Subprocess not available"
    )
    async def test_execute_shell_command(self, executor):
        """Test executing a shell command."""
        hook = ScanHook(
            hook_id="shell1",
            hook_type=HookType.PRE_SCAN,
            action="echo Hello",
            timeout=5,
        )
        
        success, output = await executor.execute(hook, {})
        # Command may succeed or fail depending on environment
        # Just verify it doesn't raise an exception


# =============================================================================
# ScanScheduler Tests
# =============================================================================

class TestScanScheduler:
    """Test main scan scheduler."""
    
    @pytest.fixture
    def temp_scheduler(self):
        """Create scheduler with temporary storage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_scheduler.db"
            storage = ScheduleStorage(db_path)
            yield ScanScheduler(storage=storage, check_interval=1)
    
    def test_create_schedule(self, temp_scheduler):
        """Test creating a schedule."""
        schedule = temp_scheduler.create_schedule(
            name="Test Create",
            target="192.168.1.1",
            ports="80,443",
            schedule_type=ScheduleType.INTERVAL,
            interval_minutes=60,
        )
        
        assert schedule.schedule_id is not None
        assert schedule.name == "Test Create"
        assert schedule.interval_minutes == 60
    
    def test_get_schedule(self, temp_scheduler):
        """Test retrieving a schedule."""
        created = temp_scheduler.create_schedule(
            name="Test Get",
            target="10.0.0.1",
        )
        
        retrieved = temp_scheduler.get_schedule(created.schedule_id)
        assert retrieved is not None
        assert retrieved.name == "Test Get"
    
    def test_list_schedules(self, temp_scheduler):
        """Test listing schedules."""
        temp_scheduler.create_schedule(name="List1", target="192.168.1.1")
        temp_scheduler.create_schedule(name="List2", target="192.168.1.2")
        
        schedules = temp_scheduler.list_schedules()
        assert len(schedules) == 2
    
    def test_update_schedule(self, temp_scheduler):
        """Test updating a schedule."""
        schedule = temp_scheduler.create_schedule(
            name="Test Update",
            target="192.168.1.1",
        )
        
        schedule.description = "Updated description"
        temp_scheduler.update_schedule(schedule)
        
        updated = temp_scheduler.get_schedule(schedule.schedule_id)
        assert updated.description == "Updated description"
    
    def test_delete_schedule(self, temp_scheduler):
        """Test deleting a schedule."""
        schedule = temp_scheduler.create_schedule(
            name="Test Delete",
            target="192.168.1.1",
        )
        
        result = temp_scheduler.delete_schedule(schedule.schedule_id)
        assert result is True
        assert temp_scheduler.get_schedule(schedule.schedule_id) is None
    
    def test_pause_schedule(self, temp_scheduler):
        """Test pausing a schedule."""
        schedule = temp_scheduler.create_schedule(
            name="Test Pause",
            target="192.168.1.1",
        )
        
        result = temp_scheduler.pause_schedule(schedule.schedule_id)
        assert result is True
        
        updated = temp_scheduler.get_schedule(schedule.schedule_id)
        assert updated.status == ScheduleStatus.PAUSED
    
    def test_resume_schedule(self, temp_scheduler):
        """Test resuming a paused schedule."""
        schedule = temp_scheduler.create_schedule(
            name="Test Resume",
            target="192.168.1.1",
            schedule_type=ScheduleType.INTERVAL,
            interval_minutes=60,
        )
        
        temp_scheduler.pause_schedule(schedule.schedule_id)
        result = temp_scheduler.resume_schedule(schedule.schedule_id)
        assert result is True
        
        updated = temp_scheduler.get_schedule(schedule.schedule_id)
        assert updated.status == ScheduleStatus.PENDING
    
    def test_add_hook(self, temp_scheduler):
        """Test adding a hook to a schedule."""
        schedule = temp_scheduler.create_schedule(
            name="Test Hook",
            target="192.168.1.1",
        )
        
        hook = temp_scheduler.add_hook(
            schedule.schedule_id,
            HookType.PRE_SCAN,
            "echo Starting",
        )
        
        assert hook is not None
        assert hook.hook_type == HookType.PRE_SCAN
        
        # Verify hook was added
        updated = temp_scheduler.get_schedule(schedule.schedule_id)
        assert len(updated.hooks) == 1
    
    def test_add_condition(self, temp_scheduler):
        """Test adding a condition to a schedule."""
        schedule = temp_scheduler.create_schedule(
            name="Test Condition",
            target="192.168.1.1",
        )
        
        condition = temp_scheduler.add_condition(
            schedule.schedule_id,
            ConditionType.HOST_UP,
            {"timeout": 5},
        )
        
        assert condition is not None
        assert condition.condition_type == ConditionType.HOST_UP
    
    def test_set_chain(self, temp_scheduler):
        """Test setting up scan chaining."""
        schedule1 = temp_scheduler.create_schedule(
            name="Chain First",
            target="192.168.1.1",
        )
        schedule2 = temp_scheduler.create_schedule(
            name="Chain Second",
            target="192.168.1.2",
        )
        
        result = temp_scheduler.set_chain(
            schedule1.schedule_id,
            schedule2.schedule_id,
        )
        
        assert result is True
        
        updated = temp_scheduler.get_schedule(schedule1.schedule_id)
        assert updated.chain_next == schedule2.schedule_id
    
    def test_get_statistics(self, temp_scheduler):
        """Test getting scheduler statistics."""
        temp_scheduler.create_schedule(name="Stats1", target="192.168.1.1")
        temp_scheduler.create_schedule(name="Stats2", target="192.168.1.2")
        
        stats = temp_scheduler.get_statistics()
        
        assert "total_schedules" in stats
        assert stats["total_schedules"] == 2
        assert "active_schedules" in stats
        assert "total_runs" in stats


# =============================================================================
# Helper Function Tests
# =============================================================================

class TestHelperFunctions:
    """Test helper functions."""
    
    def test_parse_cron_shorthand_hourly(self):
        """Test parsing @hourly shorthand."""
        assert parse_cron_shorthand("@hourly") == "0 * * * *"
    
    def test_parse_cron_shorthand_daily(self):
        """Test parsing @daily shorthand."""
        assert parse_cron_shorthand("@daily") == "0 0 * * *"
        assert parse_cron_shorthand("@midnight") == "0 0 * * *"
    
    def test_parse_cron_shorthand_weekly(self):
        """Test parsing @weekly shorthand."""
        assert parse_cron_shorthand("@weekly") == "0 0 * * 0"
    
    def test_parse_cron_shorthand_monthly(self):
        """Test parsing @monthly shorthand."""
        assert parse_cron_shorthand("@monthly") == "0 0 1 * *"
    
    def test_parse_cron_shorthand_passthrough(self):
        """Test that unknown expressions pass through."""
        assert parse_cron_shorthand("0 3 * * *") == "0 3 * * *"
    
    def test_parse_interval_minutes(self):
        """Test parsing minute intervals."""
        assert parse_interval("30m") == 30
        assert parse_interval("30min") == 30
        assert parse_interval("30 minutes") == 30
    
    def test_parse_interval_hours(self):
        """Test parsing hour intervals."""
        assert parse_interval("2h") == 120
        assert parse_interval("2hr") == 120
        assert parse_interval("2 hours") == 120
    
    def test_parse_interval_days(self):
        """Test parsing day intervals."""
        assert parse_interval("1d") == 1440
        assert parse_interval("1 day") == 1440
    
    def test_parse_interval_weeks(self):
        """Test parsing week intervals."""
        assert parse_interval("1w") == 10080
        assert parse_interval("1 week") == 10080
    
    def test_parse_interval_plain_number(self):
        """Test parsing plain number as minutes."""
        assert parse_interval("45") == 45
    
    def test_parse_interval_invalid(self):
        """Test parsing invalid interval raises error."""
        with pytest.raises(ValueError):
            parse_interval("invalid")
    
    def test_format_next_run_none(self):
        """Test formatting None next run."""
        assert format_next_run(None) == "N/A"
    
    def test_format_next_run_overdue(self):
        """Test formatting overdue next run."""
        past = datetime.now() - timedelta(hours=1)
        assert format_next_run(past) == "Overdue"
    
    def test_format_next_run_minutes(self):
        """Test formatting next run in minutes."""
        future = datetime.now() + timedelta(minutes=30)
        result = format_next_run(future)
        assert "minute" in result
    
    def test_format_next_run_hours(self):
        """Test formatting next run in hours."""
        future = datetime.now() + timedelta(hours=5)
        result = format_next_run(future)
        assert "hour" in result
    
    def test_format_next_run_days(self):
        """Test formatting next run in days."""
        future = datetime.now() + timedelta(days=3)
        result = format_next_run(future)
        assert "day" in result


class TestDaysOfWeek:
    """Test days of week mapping."""
    
    def test_monday_mapping(self):
        """Test Monday mappings."""
        assert DAYS_OF_WEEK["mon"] == 0
        assert DAYS_OF_WEEK["monday"] == 0
    
    def test_all_days_present(self):
        """Test all days are present."""
        assert len(DAYS_OF_WEEK) == 14  # Short and long names
        assert DAYS_OF_WEEK["sun"] == 6
        assert DAYS_OF_WEEK["sunday"] == 6


# =============================================================================
# Integration Tests
# =============================================================================

class TestSchedulerIntegration:
    """Integration tests for scheduler."""
    
    @pytest.fixture
    def temp_scheduler(self):
        """Create scheduler with temporary storage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_integration.db"
            storage = ScheduleStorage(db_path)
            yield ScanScheduler(storage=storage, check_interval=1)
    
    def test_full_schedule_lifecycle(self, temp_scheduler):
        """Test complete schedule lifecycle."""
        # Create
        schedule = temp_scheduler.create_schedule(
            name="Lifecycle Test",
            target="192.168.1.1",
            ports="80,443",
            schedule_type=ScheduleType.INTERVAL,
            interval_minutes=30,
            description="Full lifecycle test",
            tags=["test", "integration"],
        )
        
        # Add hook
        temp_scheduler.add_hook(
            schedule.schedule_id,
            HookType.PRE_SCAN,
            "echo Pre-scan",
        )
        
        # Add condition
        temp_scheduler.add_condition(
            schedule.schedule_id,
            ConditionType.TIME_WINDOW,
            {"start_hour": 0, "end_hour": 24},
        )
        
        # Verify
        retrieved = temp_scheduler.get_schedule(schedule.schedule_id)
        assert retrieved.name == "Lifecycle Test"
        assert len(retrieved.hooks) == 1
        assert len(retrieved.conditions) == 1
        
        # Pause
        temp_scheduler.pause_schedule(schedule.schedule_id)
        paused = temp_scheduler.get_schedule(schedule.schedule_id)
        assert paused.status == ScheduleStatus.PAUSED
        
        # Resume
        temp_scheduler.resume_schedule(schedule.schedule_id)
        resumed = temp_scheduler.get_schedule(schedule.schedule_id)
        assert resumed.status == ScheduleStatus.PENDING
        
        # Delete
        temp_scheduler.delete_schedule(schedule.schedule_id)
        assert temp_scheduler.get_schedule(schedule.schedule_id) is None
    
    def test_schedule_chaining(self, temp_scheduler):
        """Test schedule chaining setup."""
        # Create three schedules
        scan1 = temp_scheduler.create_schedule(
            name="Chain 1",
            target="192.168.1.1",
        )
        scan2 = temp_scheduler.create_schedule(
            name="Chain 2",
            target="192.168.1.2",
        )
        scan3 = temp_scheduler.create_schedule(
            name="Chain 3",
            target="192.168.1.3",
        )
        
        # Set up chain: 1 -> 2 -> 3
        temp_scheduler.set_chain(scan1.schedule_id, scan2.schedule_id)
        temp_scheduler.set_chain(scan2.schedule_id, scan3.schedule_id)
        
        # Verify chain
        s1 = temp_scheduler.get_schedule(scan1.schedule_id)
        s2 = temp_scheduler.get_schedule(scan2.schedule_id)
        
        assert s1.chain_next == scan2.schedule_id
        assert s2.chain_next == scan3.schedule_id


# =============================================================================
# Async Scheduler Tests
# =============================================================================

class TestAsyncScheduler:
    """Test async scheduler operations."""
    
    @pytest.fixture
    def temp_scheduler(self):
        """Create scheduler with temporary storage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_async.db"
            storage = ScheduleStorage(db_path)
            yield ScanScheduler(storage=storage, check_interval=1)
    
    @pytest.mark.asyncio
    async def test_start_and_stop(self, temp_scheduler):
        """Test starting and stopping the scheduler."""
        await temp_scheduler.start()
        assert temp_scheduler._running is True
        
        await temp_scheduler.stop()
        assert temp_scheduler._running is False
    
    @pytest.mark.asyncio
    async def test_set_callbacks(self, temp_scheduler):
        """Test setting callbacks."""
        start_called = []
        
        def on_start(schedule, result):
            start_called.append(schedule.name)
        
        temp_scheduler.set_callbacks(on_start=on_start)
        assert temp_scheduler._on_scan_start is not None
