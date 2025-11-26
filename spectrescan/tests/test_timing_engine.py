"""
Comprehensive unit tests for SpectreScan timing engine module
by BitSpectreLabs

Tests for spectrescan.core.timing_engine module to increase coverage.
"""

import pytest
from spectrescan.core.timing_engine import (
    TimingLevel,
    TimingTemplate,
    TIMING_TEMPLATES,
    get_timing_template,
    get_timing_template_by_name,
    list_timing_templates,
    RTTCalculator,
)


class TestTimingLevel:
    """Tests for TimingLevel enum."""
    
    def test_all_levels_exist(self):
        """Test all timing levels exist."""
        assert TimingLevel.PARANOID.value == "T0"
        assert TimingLevel.SNEAKY.value == "T1"
        assert TimingLevel.POLITE.value == "T2"
        assert TimingLevel.NORMAL.value == "T3"
        assert TimingLevel.AGGRESSIVE.value == "T4"
        assert TimingLevel.INSANE.value == "T5"
    
    def test_level_count(self):
        """Test correct number of timing levels."""
        assert len(TimingLevel) == 6


class TestTimingTemplate:
    """Tests for TimingTemplate dataclass."""
    
    def test_create_valid_template(self):
        """Test creating a valid timing template."""
        template = TimingTemplate(
            name="Test",
            level=TimingLevel.NORMAL,
            max_concurrent=100,
            timeout=3.0,
            min_rtt_timeout=0.5,
            max_rtt_timeout=5.0,
            initial_rtt_timeout=1.0,
            max_retries=3,
            scan_delay=0.0,
            host_timeout=5.0
        )
        assert template.name == "Test"
        assert template.level == TimingLevel.NORMAL
        assert template.max_concurrent == 100
    
    def test_invalid_max_concurrent(self):
        """Test that max_concurrent < 1 raises error."""
        with pytest.raises(ValueError, match="max_concurrent"):
            TimingTemplate(
                name="Invalid",
                level=TimingLevel.NORMAL,
                max_concurrent=0,
                timeout=3.0,
                min_rtt_timeout=0.5,
                max_rtt_timeout=5.0,
                initial_rtt_timeout=1.0,
                max_retries=3,
                scan_delay=0.0,
                host_timeout=5.0
            )
    
    def test_invalid_timeout(self):
        """Test that timeout <= 0 raises error."""
        with pytest.raises(ValueError, match="timeout"):
            TimingTemplate(
                name="Invalid",
                level=TimingLevel.NORMAL,
                max_concurrent=100,
                timeout=0,
                min_rtt_timeout=0.5,
                max_rtt_timeout=5.0,
                initial_rtt_timeout=1.0,
                max_retries=3,
                scan_delay=0.0,
                host_timeout=5.0
            )
    
    def test_invalid_rtt_range(self):
        """Test that min_rtt > max_rtt raises error."""
        with pytest.raises(ValueError, match="min_rtt_timeout"):
            TimingTemplate(
                name="Invalid",
                level=TimingLevel.NORMAL,
                max_concurrent=100,
                timeout=3.0,
                min_rtt_timeout=10.0,  # Greater than max
                max_rtt_timeout=5.0,
                initial_rtt_timeout=1.0,
                max_retries=3,
                scan_delay=0.0,
                host_timeout=5.0
            )


class TestTimingTemplates:
    """Tests for predefined timing templates."""
    
    def test_paranoid_template(self):
        """Test T0 (Paranoid) template values."""
        template = TIMING_TEMPLATES[TimingLevel.PARANOID]
        assert template.name == "Paranoid"
        assert template.max_concurrent == 1
        assert template.timeout == 300.0
        assert template.scan_delay == 5.0
    
    def test_sneaky_template(self):
        """Test T1 (Sneaky) template values."""
        template = TIMING_TEMPLATES[TimingLevel.SNEAKY]
        assert template.name == "Sneaky"
        assert template.max_concurrent == 10
        assert template.scan_delay == 1.0
    
    def test_polite_template(self):
        """Test T2 (Polite) template values."""
        template = TIMING_TEMPLATES[TimingLevel.POLITE]
        assert template.name == "Polite"
        assert template.max_concurrent == 50
        assert template.scan_delay == 0.4
    
    def test_normal_template(self):
        """Test T3 (Normal) template values."""
        template = TIMING_TEMPLATES[TimingLevel.NORMAL]
        assert template.name == "Normal"
        assert template.max_concurrent == 500
        assert template.scan_delay == 0.0
    
    def test_aggressive_template(self):
        """Test T4 (Aggressive) template values."""
        template = TIMING_TEMPLATES[TimingLevel.AGGRESSIVE]
        assert template.name == "Aggressive"
        assert template.max_concurrent == 1000
        assert template.timeout == 1.5
    
    def test_insane_template(self):
        """Test T5 (Insane) template values."""
        template = TIMING_TEMPLATES[TimingLevel.INSANE]
        assert template.name == "Insane"
        assert template.max_concurrent == 2000
        assert template.timeout == 0.5


class TestGetTimingTemplate:
    """Tests for get_timing_template function."""
    
    def test_get_paranoid(self):
        """Test getting paranoid template."""
        template = get_timing_template(TimingLevel.PARANOID)
        assert template.name == "Paranoid"
        assert template.level == TimingLevel.PARANOID
    
    def test_get_normal_default(self):
        """Test default template is normal."""
        template = get_timing_template()
        assert template.name == "Normal"
    
    def test_get_all_levels(self):
        """Test getting all timing levels."""
        for level in TimingLevel:
            template = get_timing_template(level)
            assert template is not None
            assert template.level == level


class TestGetTimingTemplateByName:
    """Tests for get_timing_template_by_name function."""
    
    def test_get_by_t0(self):
        """Test getting template by T0."""
        template = get_timing_template_by_name("T0")
        assert template.name == "Paranoid"
    
    def test_get_by_t1(self):
        """Test getting template by T1."""
        template = get_timing_template_by_name("T1")
        assert template.name == "Sneaky"
    
    def test_get_by_t2(self):
        """Test getting template by T2."""
        template = get_timing_template_by_name("T2")
        assert template.name == "Polite"
    
    def test_get_by_t3(self):
        """Test getting template by T3."""
        template = get_timing_template_by_name("T3")
        assert template.name == "Normal"
    
    def test_get_by_t4(self):
        """Test getting template by T4."""
        template = get_timing_template_by_name("T4")
        assert template.name == "Aggressive"
    
    def test_get_by_t5(self):
        """Test getting template by T5."""
        template = get_timing_template_by_name("T5")
        assert template.name == "Insane"
    
    def test_lowercase_works(self):
        """Test lowercase names work."""
        template = get_timing_template_by_name("t3")
        assert template.name == "Normal"
    
    def test_invalid_name_returns_none(self):
        """Test invalid name returns None."""
        template = get_timing_template_by_name("T99")
        assert template is None
    
    def test_empty_name_returns_none(self):
        """Test empty name returns None."""
        template = get_timing_template_by_name("")
        assert template is None


class TestListTimingTemplates:
    """Tests for list_timing_templates function."""
    
    def test_returns_all_templates(self):
        """Test returns all templates."""
        templates = list_timing_templates()
        assert len(templates) == 6
    
    def test_keyed_by_level_value(self):
        """Test templates are keyed by level value."""
        templates = list_timing_templates()
        assert "T0" in templates
        assert "T1" in templates
        assert "T2" in templates
        assert "T3" in templates
        assert "T4" in templates
        assert "T5" in templates
    
    def test_correct_template_types(self):
        """Test all templates are TimingTemplate instances."""
        templates = list_timing_templates()
        for key, template in templates.items():
            assert isinstance(template, TimingTemplate)


class TestRTTCalculator:
    """Tests for RTTCalculator class."""
    
    def test_create_calculator(self):
        """Test creating RTT calculator."""
        template = get_timing_template(TimingLevel.NORMAL)
        calculator = RTTCalculator(template)
        assert calculator is not None
    
    def test_calculator_with_different_templates(self):
        """Test calculator with different timing templates."""
        for level in TimingLevel:
            template = get_timing_template(level)
            calculator = RTTCalculator(template)
            assert calculator is not None


class TestTimingTemplateValidation:
    """Tests for timing template validation."""
    
    def test_all_templates_valid(self):
        """Test all predefined templates pass validation."""
        for level, template in TIMING_TEMPLATES.items():
            assert template.max_concurrent >= 1
            assert template.timeout > 0
            assert template.min_rtt_timeout <= template.max_rtt_timeout
    
    def test_increasing_concurrency(self):
        """Test concurrency generally increases with aggression."""
        paranoid = TIMING_TEMPLATES[TimingLevel.PARANOID]
        sneaky = TIMING_TEMPLATES[TimingLevel.SNEAKY]
        normal = TIMING_TEMPLATES[TimingLevel.NORMAL]
        insane = TIMING_TEMPLATES[TimingLevel.INSANE]
        
        assert paranoid.max_concurrent < sneaky.max_concurrent
        assert sneaky.max_concurrent < normal.max_concurrent
        assert normal.max_concurrent < insane.max_concurrent
    
    def test_decreasing_timeout(self):
        """Test timeout generally decreases with aggression."""
        paranoid = TIMING_TEMPLATES[TimingLevel.PARANOID]
        normal = TIMING_TEMPLATES[TimingLevel.NORMAL]
        insane = TIMING_TEMPLATES[TimingLevel.INSANE]
        
        assert paranoid.timeout > normal.timeout
        assert normal.timeout > insane.timeout


class TestTimingTemplateUseCases:
    """Tests for timing template use cases."""
    
    def test_stealth_scanning(self):
        """Test sneaky template is good for stealth scanning."""
        template = get_timing_template(TimingLevel.SNEAKY)
        # Should have low concurrency and delays
        assert template.max_concurrent <= 10
        assert template.scan_delay >= 1.0
    
    def test_fast_scanning(self):
        """Test insane template is good for fast scanning."""
        template = get_timing_template(TimingLevel.INSANE)
        # Should have high concurrency and no delay
        assert template.max_concurrent >= 1000
        assert template.scan_delay == 0.0
    
    def test_balanced_scanning(self):
        """Test normal template provides good balance."""
        template = get_timing_template(TimingLevel.NORMAL)
        # Should have moderate settings
        assert 100 <= template.max_concurrent <= 1000
        assert 1.0 <= template.timeout <= 10.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
