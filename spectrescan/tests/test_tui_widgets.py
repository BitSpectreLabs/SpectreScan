"""
Tests for TUI widgets.

Author: BitSpectreLabs
License: MIT
"""

import pytest
from unittest.mock import MagicMock, patch
from spectrescan.core.utils import ScanResult


class TestResultsTableWidget:
    """Tests for ResultsTable widget."""
    
    def test_import(self):
        """Test importing ResultsTable."""
        from spectrescan.tui.widgets.results_table import ResultsTable
        assert ResultsTable is not None
    
    def test_initialization(self):
        """Test ResultsTable initialization."""
        from spectrescan.tui.widgets.results_table import ResultsTable
        table = ResultsTable()
        assert table.cursor_type == "row"
        assert table.zebra_stripes is True
        assert table.show_header is True
        assert table._results_count == 0
        assert table._columns_added is False
    
    def test_results_count_property(self):
        """Test results_count property."""
        from spectrescan.tui.widgets.results_table import ResultsTable
        table = ResultsTable()
        assert table.results_count == 0


class TestProgressWidget:
    """Tests for ProgressWidget."""
    
    def test_import(self):
        """Test importing ProgressWidget."""
        from spectrescan.tui.widgets.progress import ProgressWidget
        assert ProgressWidget is not None
    
    def test_initialization(self):
        """Test ProgressWidget initialization."""
        from spectrescan.tui.widgets.progress import ProgressWidget
        widget = ProgressWidget()
        assert widget.total_ports == 0
        assert widget.scanned_ports == 0
        assert widget.open_ports == 0
        assert widget.closed_ports == 0
        assert widget.filtered_ports == 0


class TestLogsWidget:
    """Tests for LogsWidget."""
    
    def test_import(self):
        """Test importing LogsWidget."""
        from spectrescan.tui.widgets.logs import LogsWidget
        assert LogsWidget is not None
    
    def test_initialization(self):
        """Test LogsWidget initialization."""
        from spectrescan.tui.widgets.logs import LogsWidget
        widget = LogsWidget()
        assert widget.max_lines == 1000
        assert widget.auto_scroll is True


class TestResultsTableMethods:
    """Tests for ResultsTable methods."""
    
    def test_filter_open_only_exists(self):
        """Test filter_open_only method exists."""
        from spectrescan.tui.widgets.results_table import ResultsTable
        table = ResultsTable()
        assert hasattr(table, 'filter_open_only')
    
    def test_clear_results_exists(self):
        """Test clear_results method exists."""
        from spectrescan.tui.widgets.results_table import ResultsTable
        table = ResultsTable()
        assert hasattr(table, 'clear_results')
    
    def test_add_result_exists(self):
        """Test add_result method exists."""
        from spectrescan.tui.widgets.results_table import ResultsTable
        table = ResultsTable()
        assert hasattr(table, 'add_result')


class TestLogsWidgetMethods:
    """Tests for LogsWidget methods."""
    
    def test_log_info_exists(self):
        """Test log_info method exists."""
        from spectrescan.tui.widgets.logs import LogsWidget
        widget = LogsWidget()
        assert hasattr(widget, 'log_info')
    
    def test_log_success_exists(self):
        """Test log_success method exists."""
        from spectrescan.tui.widgets.logs import LogsWidget
        widget = LogsWidget()
        assert hasattr(widget, 'log_success')
    
    def test_log_error_exists(self):
        """Test log_error method exists."""
        from spectrescan.tui.widgets.logs import LogsWidget
        widget = LogsWidget()
        assert hasattr(widget, 'log_error')
    
    def test_log_warning_exists(self):
        """Test log_warning method exists."""
        from spectrescan.tui.widgets.logs import LogsWidget
        widget = LogsWidget()
        assert hasattr(widget, 'log_warning')


class TestProgressWidgetMethods:
    """Tests for ProgressWidget methods."""
    
    def test_set_total_exists(self):
        """Test set_total method exists."""
        from spectrescan.tui.widgets.progress import ProgressWidget
        widget = ProgressWidget()
        assert hasattr(widget, 'set_total')
    
    def test_update_progress_exists(self):
        """Test update_progress method exists."""
        from spectrescan.tui.widgets.progress import ProgressWidget
        widget = ProgressWidget()
        assert hasattr(widget, 'update_progress')
    
    def test_reset_exists(self):
        """Test reset method exists."""
        from spectrescan.tui.widgets.progress import ProgressWidget
        widget = ProgressWidget()
        assert hasattr(widget, 'reset')
