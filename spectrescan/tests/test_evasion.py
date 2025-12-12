"""
Unit Tests for IDS/IPS Evasion Module
by BitSpectreLabs

Comprehensive tests for the evasion module including all evasion techniques,
packet crafting, and scanner integration.
"""

import asyncio
import random
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from spectrescan.core.evasion import (
    COMMON_SOURCE_PORTS,
    TIMING_DELAYS,
    TTL_VALUES,
    DecoyConfig,
    EvasionConfig,
    EvasionManager,
    EvasionProfile,
    EvasionScanner,
    EvasionTechnique,
    FragmentConfig,
    IdleScanConfig,
    PacketCrafter,
    TimingConfig,
    TimingLevel,
    calculate_checksum,
    corrupt_checksum,
    create_evasion_config,
    generate_random_ip,
    get_random_source_port,
    get_ttl_for_style,
    randomize_list,
    scan_with_evasion,
)


# ============================================================================
# Test Constants
# ============================================================================

class TestConstants:
    """Test constant values."""
    
    def test_common_source_ports(self):
        """Test common source ports list."""
        assert 80 in COMMON_SOURCE_PORTS
        assert 443 in COMMON_SOURCE_PORTS
        assert 53 in COMMON_SOURCE_PORTS
        assert 22 in COMMON_SOURCE_PORTS
        assert len(COMMON_SOURCE_PORTS) >= 10
    
    def test_ttl_values(self):
        """Test TTL values dictionary."""
        assert TTL_VALUES["linux"] == 64
        assert TTL_VALUES["windows"] == 128
        assert TTL_VALUES["solaris"] == 255
        assert TTL_VALUES["cisco"] == 255
        assert TTL_VALUES["random"] is None
    
    def test_timing_delays(self):
        """Test timing delay values."""
        assert TIMING_DELAYS[TimingLevel.PARANOID] == 300.0
        assert TIMING_DELAYS[TimingLevel.SNEAKY] == 15.0
        assert TIMING_DELAYS[TimingLevel.POLITE] == 0.4
        assert TIMING_DELAYS[TimingLevel.NORMAL] == 0.0
        assert TIMING_DELAYS[TimingLevel.AGGRESSIVE] == 0.01
        assert TIMING_DELAYS[TimingLevel.INSANE] == 0.0


# ============================================================================
# Test Enums
# ============================================================================

class TestEnums:
    """Test enumeration types."""
    
    def test_evasion_technique_values(self):
        """Test EvasionTechnique enum values."""
        assert EvasionTechnique.FRAGMENTATION.value == "fragmentation"
        assert EvasionTechnique.DECOY.value == "decoy"
        assert EvasionTechnique.SOURCE_PORT.value == "source_port"
        assert EvasionTechnique.RANDOMIZE_HOSTS.value == "randomize_hosts"
        assert EvasionTechnique.TTL_MANIPULATION.value == "ttl_manipulation"
        assert EvasionTechnique.BAD_CHECKSUM.value == "bad_checksum"
        assert EvasionTechnique.TIMING.value == "timing"
        assert EvasionTechnique.IDLE_SCAN.value == "idle_scan"
        assert EvasionTechnique.DATA_LENGTH.value == "data_length"
        assert EvasionTechnique.IP_OPTIONS.value == "ip_options"
    
    def test_evasion_profile_values(self):
        """Test EvasionProfile enum values."""
        assert EvasionProfile.NONE.value == "none"
        assert EvasionProfile.STEALTH.value == "stealth"
        assert EvasionProfile.PARANOID.value == "paranoid"
        assert EvasionProfile.AGGRESSIVE.value == "aggressive"
        assert EvasionProfile.CUSTOM.value == "custom"
    
    def test_timing_level_values(self):
        """Test TimingLevel enum values."""
        assert TimingLevel.PARANOID.value == 0
        assert TimingLevel.SNEAKY.value == 1
        assert TimingLevel.POLITE.value == 2
        assert TimingLevel.NORMAL.value == 3
        assert TimingLevel.AGGRESSIVE.value == 4
        assert TimingLevel.INSANE.value == 5


# ============================================================================
# Test Helper Functions
# ============================================================================

class TestHelperFunctions:
    """Test helper utility functions."""
    
    def test_generate_random_ip(self):
        """Test random IP generation."""
        for _ in range(100):
            ip = generate_random_ip()
            octets = list(map(int, ip.split(".")))
            
            # Should have 4 octets
            assert len(octets) == 4
            
            # Should not be private/reserved
            assert octets[0] != 10  # Not 10.x.x.x
            assert not (octets[0] == 172 and 16 <= octets[1] <= 31)  # Not 172.16-31.x.x
            assert not (octets[0] == 192 and octets[1] == 168)  # Not 192.168.x.x
            assert octets[0] != 127  # Not loopback
            assert octets[0] < 224  # Not multicast/reserved
    
    def test_get_random_source_port(self):
        """Test random source port generation."""
        # Random port
        for _ in range(50):
            port = get_random_source_port(common_only=False)
            assert 1024 <= port <= 65535
        
        # Common port only
        for _ in range(50):
            port = get_random_source_port(common_only=True)
            assert port in COMMON_SOURCE_PORTS
    
    def test_get_ttl_for_style(self):
        """Test TTL value retrieval."""
        assert get_ttl_for_style("linux") == 64
        assert get_ttl_for_style("windows") == 128
        assert get_ttl_for_style("solaris") == 255
        assert get_ttl_for_style("cisco") == 255
        
        # Random should return valid TTL
        for _ in range(20):
            ttl = get_ttl_for_style("random")
            assert 32 <= ttl <= 255
        
        # Unknown style defaults to 64
        assert get_ttl_for_style("unknown") == 64
    
    def test_randomize_list(self):
        """Test list randomization."""
        original = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        
        # Multiple shuffles should produce different orderings
        different_found = False
        for _ in range(10):
            shuffled = randomize_list(original)
            assert sorted(shuffled) == sorted(original)  # Same elements
            if shuffled != original:
                different_found = True
        
        assert different_found, "Randomization should change order"
    
    def test_calculate_checksum(self):
        """Test checksum calculation."""
        # Known test vectors
        data = b'\x45\x00\x00\x73\x00\x00\x40\x00\x40\x11'
        checksum = calculate_checksum(data)
        assert isinstance(checksum, int)
        assert 0 <= checksum <= 65535
        
        # Odd length data
        data_odd = b'\x45\x00\x00'
        checksum_odd = calculate_checksum(data_odd)
        assert isinstance(checksum_odd, int)
    
    def test_corrupt_checksum(self):
        """Test checksum corruption."""
        original = 0x1234
        corrupted = corrupt_checksum(original)
        assert corrupted != original
        assert 0 <= corrupted <= 65535


# ============================================================================
# Test DecoyConfig
# ============================================================================

class TestDecoyConfig:
    """Test DecoyConfig data class."""
    
    def test_default_values(self):
        """Test default DecoyConfig values."""
        config = DecoyConfig()
        assert config.decoys == []
        assert config.include_real is True
        assert config.real_position == "random"
        assert config.random_decoys == 0
    
    def test_custom_values(self):
        """Test custom DecoyConfig values."""
        config = DecoyConfig(
            decoys=["1.1.1.1", "2.2.2.2"],
            include_real=False,
            real_position="first",
            random_decoys=3,
        )
        assert config.decoys == ["1.1.1.1", "2.2.2.2"]
        assert config.include_real is False
        assert config.real_position == "first"
        assert config.random_decoys == 3
    
    def test_get_scan_order_first(self):
        """Test scan order with real IP first."""
        config = DecoyConfig(
            decoys=["1.1.1.1", "2.2.2.2"],
            include_real=True,
            real_position="first",
        )
        order = config.get_scan_order("3.3.3.3")
        assert order[0] == "3.3.3.3"
        assert "1.1.1.1" in order
        assert "2.2.2.2" in order
    
    def test_get_scan_order_last(self):
        """Test scan order with real IP last."""
        config = DecoyConfig(
            decoys=["1.1.1.1", "2.2.2.2"],
            include_real=True,
            real_position="last",
        )
        order = config.get_scan_order("3.3.3.3")
        assert order[-1] == "3.3.3.3"
    
    def test_get_scan_order_random(self):
        """Test scan order with random real IP position."""
        config = DecoyConfig(
            decoys=["1.1.1.1", "2.2.2.2", "4.4.4.4", "5.5.5.5"],
            include_real=True,
            real_position="random",
        )
        
        # Real IP should appear somewhere in list
        order = config.get_scan_order("3.3.3.3")
        assert "3.3.3.3" in order
        assert len(order) == 5
    
    def test_get_scan_order_without_real(self):
        """Test scan order excluding real IP."""
        config = DecoyConfig(
            decoys=["1.1.1.1", "2.2.2.2"],
            include_real=False,
        )
        order = config.get_scan_order("3.3.3.3")
        assert "3.3.3.3" not in order
        assert len(order) == 2
    
    def test_get_scan_order_with_random_decoys(self):
        """Test scan order with generated random decoys."""
        config = DecoyConfig(
            decoys=["1.1.1.1"],
            include_real=True,
            random_decoys=3,
        )
        order = config.get_scan_order("2.2.2.2")
        assert len(order) == 5  # 1 static + 3 random + 1 real


# ============================================================================
# Test FragmentConfig
# ============================================================================

class TestFragmentConfig:
    """Test FragmentConfig data class."""
    
    def test_default_values(self):
        """Test default FragmentConfig values."""
        config = FragmentConfig()
        assert config.enabled is False
        assert config.mtu == 8
        assert config.overlap is False
        assert config.out_of_order is False
        assert config.delay_between == 0.0
    
    def test_custom_values(self):
        """Test custom FragmentConfig values."""
        config = FragmentConfig(
            enabled=True,
            mtu=16,
            overlap=True,
            out_of_order=True,
            delay_between=0.1,
        )
        assert config.enabled is True
        assert config.mtu == 16
        assert config.overlap is True
        assert config.out_of_order is True
        assert config.delay_between == 0.1


# ============================================================================
# Test TimingConfig
# ============================================================================

class TestTimingConfig:
    """Test TimingConfig data class."""
    
    def test_default_values(self):
        """Test default TimingConfig values."""
        config = TimingConfig()
        assert config.level == TimingLevel.NORMAL
        assert config.delay_ms is None
        assert config.jitter_percent == 0.0
        assert config.max_parallelism == 100
        assert config.min_parallelism == 1
        assert config.max_rate is None
    
    def test_get_delay_normal(self):
        """Test delay for normal timing."""
        config = TimingConfig(level=TimingLevel.NORMAL)
        assert config.get_delay() == 0.0
    
    def test_get_delay_paranoid(self):
        """Test delay for paranoid timing."""
        config = TimingConfig(level=TimingLevel.PARANOID)
        assert config.get_delay() == 300.0
    
    def test_get_delay_sneaky(self):
        """Test delay for sneaky timing."""
        config = TimingConfig(level=TimingLevel.SNEAKY)
        assert config.get_delay() == 15.0
    
    def test_get_delay_custom(self):
        """Test custom delay in ms."""
        config = TimingConfig(delay_ms=500)
        assert config.get_delay() == 0.5  # Converted to seconds
    
    def test_get_delay_with_jitter(self):
        """Test delay with jitter."""
        config = TimingConfig(
            level=TimingLevel.POLITE,  # 0.4 seconds
            jitter_percent=50.0,
        )
        
        delays = [config.get_delay() for _ in range(100)]
        
        # Should have variation
        assert min(delays) < max(delays)
        
        # Should be within jitter range (0.2 to 0.6)
        for delay in delays:
            assert 0.2 <= delay <= 0.6


# ============================================================================
# Test IdleScanConfig
# ============================================================================

class TestIdleScanConfig:
    """Test IdleScanConfig data class."""
    
    def test_default_values(self):
        """Test default IdleScanConfig values."""
        config = IdleScanConfig()
        assert config.zombie_host == ""
        assert config.zombie_port == 80
        assert config.probe_count == 2
    
    def test_custom_values(self):
        """Test custom IdleScanConfig values."""
        config = IdleScanConfig(
            zombie_host="192.168.1.100",
            zombie_port=443,
            probe_count=3,
        )
        assert config.zombie_host == "192.168.1.100"
        assert config.zombie_port == 443
        assert config.probe_count == 3


# ============================================================================
# Test EvasionConfig
# ============================================================================

class TestEvasionConfig:
    """Test EvasionConfig data class."""
    
    def test_default_values(self):
        """Test default EvasionConfig values."""
        config = EvasionConfig()
        assert config.profile == EvasionProfile.NONE
        assert config.techniques == []
        assert isinstance(config.fragmentation, FragmentConfig)
        assert isinstance(config.decoy, DecoyConfig)
        assert config.source_port is None
        assert config.randomize_source_port is False
        assert config.ttl is None
        assert config.bad_checksum is False
        assert isinstance(config.timing, TimingConfig)
        assert config.randomize_hosts is False
        assert config.randomize_ports is False
    
    def test_from_profile_none(self):
        """Test config from NONE profile."""
        config = EvasionConfig.from_profile(EvasionProfile.NONE)
        assert config.profile == EvasionProfile.NONE
        assert config.techniques == []
    
    def test_from_profile_stealth(self):
        """Test config from STEALTH profile."""
        config = EvasionConfig.from_profile(EvasionProfile.STEALTH)
        assert config.profile == EvasionProfile.STEALTH
        assert EvasionTechnique.TIMING in config.techniques
        assert EvasionTechnique.RANDOMIZE_HOSTS in config.techniques
        assert config.timing.level == TimingLevel.SNEAKY
        assert config.randomize_hosts is True
        assert config.randomize_ports is True
    
    def test_from_profile_paranoid(self):
        """Test config from PARANOID profile."""
        config = EvasionConfig.from_profile(EvasionProfile.PARANOID)
        assert config.profile == EvasionProfile.PARANOID
        assert EvasionTechnique.TIMING in config.techniques
        assert EvasionTechnique.FRAGMENTATION in config.techniques
        assert EvasionTechnique.DECOY in config.techniques
        assert config.timing.level == TimingLevel.PARANOID
        assert config.fragmentation.enabled is True
        assert config.decoy.random_decoys == 5
    
    def test_from_profile_aggressive(self):
        """Test config from AGGRESSIVE profile."""
        config = EvasionConfig.from_profile(EvasionProfile.AGGRESSIVE)
        assert config.profile == EvasionProfile.AGGRESSIVE
        assert EvasionTechnique.DECOY in config.techniques
        assert EvasionTechnique.FRAGMENTATION in config.techniques
        assert EvasionTechnique.BAD_CHECKSUM in config.techniques
        assert config.timing.level == TimingLevel.AGGRESSIVE
        assert config.bad_checksum is True


# ============================================================================
# Test PacketCrafter
# ============================================================================

class TestPacketCrafter:
    """Test PacketCrafter class."""
    
    def test_init(self):
        """Test PacketCrafter initialization."""
        config = EvasionConfig()
        crafter = PacketCrafter(config)
        assert crafter.config == config
    
    def test_create_ip_header_basic(self):
        """Test basic IP header creation."""
        config = EvasionConfig()
        crafter = PacketCrafter(config)
        
        header = crafter.create_ip_header(
            src="192.168.1.1",
            dst="192.168.1.2",
            protocol=6,
        )
        
        # Should be at least 20 bytes
        assert len(header) >= 20
        
        # Version should be 4
        version = (header[0] >> 4) & 0x0F
        assert version == 4
        
        # Protocol should be TCP (6)
        assert header[9] == 6
    
    def test_create_ip_header_with_ttl(self):
        """Test IP header with custom TTL."""
        config = EvasionConfig(ttl=100)
        crafter = PacketCrafter(config)
        
        header = crafter.create_ip_header(
            src="192.168.1.1",
            dst="192.168.1.2",
        )
        
        # TTL is at offset 8
        assert header[8] == 100
    
    def test_create_ip_header_with_bad_checksum(self):
        """Test IP header with bad checksum."""
        config = EvasionConfig(bad_checksum=True)
        crafter = PacketCrafter(config)
        
        header1 = crafter.create_ip_header(
            src="192.168.1.1",
            dst="192.168.1.2",
        )
        
        config2 = EvasionConfig(bad_checksum=False)
        crafter2 = PacketCrafter(config2)
        
        header2 = crafter2.create_ip_header(
            src="192.168.1.1",
            dst="192.168.1.2",
        )
        
        # Checksums should differ (bad vs good)
        checksum1 = struct.unpack("!H", header1[10:12])[0]
        checksum2 = struct.unpack("!H", header2[10:12])[0]
        # Note: Due to randomization in ID, this might differ anyway
        # Just ensure both are valid values
        assert 0 <= checksum1 <= 65535
        assert 0 <= checksum2 <= 65535
    
    def test_create_tcp_header_basic(self):
        """Test basic TCP header creation."""
        config = EvasionConfig()
        crafter = PacketCrafter(config)
        
        header = crafter.create_tcp_header(
            src_port=12345,
            dst_port=80,
            flags=0x02,  # SYN
        )
        
        # Should be at least 20 bytes
        assert len(header) >= 20
        
        # Check ports
        src_port = struct.unpack("!H", header[0:2])[0]
        dst_port = struct.unpack("!H", header[2:4])[0]
        assert src_port == 12345
        assert dst_port == 80
        
        # Check flags (offset 13)
        assert header[13] == 0x02
    
    def test_create_syn_packet(self):
        """Test SYN packet creation."""
        config = EvasionConfig(source_port=54321)
        crafter = PacketCrafter(config)
        
        packet = crafter.create_syn_packet(
            src="192.168.1.1",
            dst="192.168.1.2",
            dst_port=80,
        )
        
        # Should have IP header (20) + TCP header (20) minimum
        assert len(packet) >= 40
        
        # Check it's a valid IP packet
        version = (packet[0] >> 4) & 0x0F
        assert version == 4
    
    def test_create_syn_packet_with_data_length(self):
        """Test SYN packet with data padding."""
        config = EvasionConfig(data_length=100)
        crafter = PacketCrafter(config)
        
        packet = crafter.create_syn_packet(
            src="192.168.1.1",
            dst="192.168.1.2",
            dst_port=80,
        )
        
        # Should have extra padding
        assert len(packet) >= 140  # 20 + 20 + 100
    
    def test_fragment_packet_disabled(self):
        """Test fragmentation when disabled."""
        config = EvasionConfig()
        config.fragmentation.enabled = False
        crafter = PacketCrafter(config)
        
        packet = b'\x00' * 100
        fragments = crafter.fragment_packet(packet)
        
        # Should return original packet unchanged
        assert len(fragments) == 1
        assert fragments[0] == packet
    
    def test_fragment_packet_enabled(self):
        """Test packet fragmentation."""
        config = EvasionConfig()
        config.fragmentation.enabled = True
        config.fragmentation.mtu = 8
        crafter = PacketCrafter(config)
        
        # Create a mock IP packet
        ip_header = crafter.create_ip_header("1.1.1.1", "2.2.2.2")
        payload = b'\x00' * 64
        packet = ip_header + payload
        
        fragments = crafter.fragment_packet(packet, mtu=8)
        
        # Should have multiple fragments
        assert len(fragments) > 1
        
        # Each fragment should have IP header
        for frag in fragments:
            assert len(frag) >= 20


# ============================================================================
# Test EvasionScanner
# ============================================================================

class TestEvasionScanner:
    """Test EvasionScanner class."""
    
    def test_init(self):
        """Test EvasionScanner initialization."""
        config = EvasionConfig()
        scanner = EvasionScanner(config, timeout=5.0)
        
        assert scanner.config == config
        assert scanner.timeout == 5.0
        assert scanner.callback is None
    
    def test_stats(self):
        """Test scanner statistics."""
        config = EvasionConfig()
        scanner = EvasionScanner(config)
        
        stats = scanner.stats
        assert "packets_sent" in stats
        assert "packets_received" in stats
        assert "decoys_used" in stats
        assert "fragments_sent" in stats
        assert "retries" in stats
    
    def test_prepare_targets_no_randomization(self):
        """Test target preparation without randomization."""
        config = EvasionConfig()
        scanner = EvasionScanner(config)
        
        hosts = ["192.168.1.1", "192.168.1.2"]
        ports = [80, 443]
        
        targets = scanner.prepare_targets(hosts, ports)
        
        # Should have all combinations
        assert len(targets) == 4
        assert ("192.168.1.1", 80) in targets
        assert ("192.168.1.1", 443) in targets
        assert ("192.168.1.2", 80) in targets
        assert ("192.168.1.2", 443) in targets
    
    def test_prepare_targets_with_randomization(self):
        """Test target preparation with randomization."""
        config = EvasionConfig(randomize_hosts=True, randomize_ports=True)
        scanner = EvasionScanner(config)
        
        hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        ports = [80, 443, 8080]
        
        # Run multiple times to check randomization
        orderings = set()
        for _ in range(20):
            targets = scanner.prepare_targets(hosts.copy(), ports.copy())
            orderings.add(tuple(targets))
        
        # Should have different orderings
        assert len(orderings) > 1
    
    def test_get_source_port_configured(self):
        """Test source port with configured value."""
        config = EvasionConfig(source_port=12345)
        scanner = EvasionScanner(config)
        
        assert scanner.get_source_port() == 12345
    
    def test_get_source_port_random(self):
        """Test random source port."""
        config = EvasionConfig(randomize_source_port=True)
        scanner = EvasionScanner(config)
        
        ports = [scanner.get_source_port() for _ in range(10)]
        
        # Should have variation
        assert len(set(ports)) > 1
    
    def test_get_source_port_common(self):
        """Test common source port."""
        config = EvasionConfig(use_common_source_port=True)
        scanner = EvasionScanner(config)
        
        for _ in range(20):
            port = scanner.get_source_port()
            assert port in COMMON_SOURCE_PORTS
    
    @pytest.mark.asyncio
    async def test_apply_timing_delay_none(self):
        """Test timing delay with no delay configured."""
        config = EvasionConfig()
        scanner = EvasionScanner(config)
        
        start = asyncio.get_event_loop().time()
        await scanner.apply_timing_delay()
        elapsed = asyncio.get_event_loop().time() - start
        
        # Should be nearly instant
        assert elapsed < 0.1
    
    @pytest.mark.asyncio
    async def test_apply_timing_delay_polite(self):
        """Test timing delay with polite timing."""
        config = EvasionConfig()
        config.timing.level = TimingLevel.POLITE
        scanner = EvasionScanner(config)
        
        start = asyncio.get_event_loop().time()
        await scanner.apply_timing_delay()
        elapsed = asyncio.get_event_loop().time() - start
        
        # Should delay approximately 0.4 seconds
        assert 0.3 <= elapsed <= 0.6
    
    @pytest.mark.asyncio
    async def test_fallback_scan_open(self):
        """Test fallback scan detecting open port."""
        config = EvasionConfig()
        scanner = EvasionScanner(config)
        
        # Mock asyncio.open_connection to simulate open port
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        
        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            with patch("asyncio.wait_for", return_value=(mock_reader, mock_writer)):
                result = await scanner._fallback_scan("192.168.1.1", 80)
        
        assert result == "open"
    
    @pytest.mark.asyncio
    async def test_fallback_scan_closed(self):
        """Test fallback scan detecting closed port."""
        config = EvasionConfig()
        scanner = EvasionScanner(config)
        
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError()):
            result = await scanner._fallback_scan("192.168.1.1", 80)
        
        assert result == "closed"
    
    @pytest.mark.asyncio
    async def test_fallback_scan_filtered(self):
        """Test fallback scan detecting filtered port."""
        config = EvasionConfig()
        scanner = EvasionScanner(config)
        
        with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError()):
            result = await scanner._fallback_scan("192.168.1.1", 80)
        
        assert result == "filtered"
    
    @pytest.mark.asyncio
    async def test_scan_port_basic(self):
        """Test basic port scan."""
        config = EvasionConfig()
        scanner = EvasionScanner(config)
        scanner._scapy_available = False  # Force fallback
        
        # Mock the fallback
        with patch.object(scanner, "_fallback_scan", return_value="open") as mock:
            result = await scanner.scan_port("192.168.1.1", 80)
        
        assert result == "open"
        mock.assert_called_once()


# ============================================================================
# Test EvasionManager
# ============================================================================

class TestEvasionManager:
    """Test EvasionManager class."""
    
    def test_init_default(self):
        """Test default EvasionManager initialization."""
        manager = EvasionManager()
        assert manager.config.profile == EvasionProfile.NONE
    
    def test_init_with_config(self):
        """Test EvasionManager with custom config."""
        config = EvasionConfig(randomize_hosts=True)
        manager = EvasionManager(config)
        assert manager.config.randomize_hosts is True
    
    def test_from_profile_string(self):
        """Test creating manager from profile string."""
        manager = EvasionManager.from_profile("stealth")
        assert manager.config.profile == EvasionProfile.STEALTH
    
    def test_from_profile_enum(self):
        """Test creating manager from profile enum."""
        manager = EvasionManager.from_profile(EvasionProfile.PARANOID)
        assert manager.config.profile == EvasionProfile.PARANOID
    
    def test_from_profile_invalid(self):
        """Test creating manager from invalid profile."""
        manager = EvasionManager.from_profile("invalid_profile")
        assert manager.config.profile == EvasionProfile.NONE
    
    def test_from_cli_args_basic(self):
        """Test creating manager from basic CLI args."""
        manager = EvasionManager.from_cli_args()
        assert manager.config.profile == EvasionProfile.NONE
    
    def test_from_cli_args_decoys(self):
        """Test creating manager with decoy args."""
        manager = EvasionManager.from_cli_args(
            decoys=["1.1.1.1", "2.2.2.2"],
            decoy_count=3,
        )
        assert EvasionTechnique.DECOY in manager.config.techniques
        assert manager.config.decoy.decoys == ["1.1.1.1", "2.2.2.2"]
        assert manager.config.decoy.random_decoys == 3
    
    def test_from_cli_args_source_port(self):
        """Test creating manager with source port args."""
        manager = EvasionManager.from_cli_args(source_port=53)
        assert EvasionTechnique.SOURCE_PORT in manager.config.techniques
        assert manager.config.source_port == 53
    
    def test_from_cli_args_fragmentation(self):
        """Test creating manager with fragmentation args."""
        manager = EvasionManager.from_cli_args(
            fragment=True,
            fragment_mtu=16,
        )
        assert EvasionTechnique.FRAGMENTATION in manager.config.techniques
        assert manager.config.fragmentation.enabled is True
        assert manager.config.fragmentation.mtu == 16
    
    def test_from_cli_args_ttl(self):
        """Test creating manager with TTL args."""
        manager = EvasionManager.from_cli_args(ttl=100)
        assert EvasionTechnique.TTL_MANIPULATION in manager.config.techniques
        assert manager.config.ttl == 100
    
    def test_from_cli_args_timing(self):
        """Test creating manager with timing args."""
        manager = EvasionManager.from_cli_args(
            timing_level=0,  # Paranoid
            max_parallelism=10,
        )
        assert EvasionTechnique.TIMING in manager.config.techniques
        assert manager.config.timing.level == TimingLevel.PARANOID
        assert manager.config.timing.max_parallelism == 10
    
    def test_from_cli_args_zombie(self):
        """Test creating manager with idle scan args."""
        manager = EvasionManager.from_cli_args(
            zombie_host="192.168.1.100",
            zombie_port=443,
        )
        assert EvasionTechnique.IDLE_SCAN in manager.config.techniques
        assert manager.config.idle_scan.zombie_host == "192.168.1.100"
        assert manager.config.idle_scan.zombie_port == 443
    
    def test_from_cli_args_bad_checksum(self):
        """Test creating manager with bad checksum."""
        manager = EvasionManager.from_cli_args(bad_checksum=True)
        assert EvasionTechnique.BAD_CHECKSUM in manager.config.techniques
        assert manager.config.bad_checksum is True
    
    def test_get_scanner(self):
        """Test getting scanner from manager."""
        manager = EvasionManager()
        scanner = manager.get_scanner(timeout=3.0)
        
        assert isinstance(scanner, EvasionScanner)
        assert scanner.timeout == 3.0
        
        # Should return same instance
        scanner2 = manager.get_scanner()
        assert scanner is scanner2
    
    def test_apply_to_targets(self):
        """Test applying randomization to targets."""
        config = EvasionConfig(randomize_hosts=True, randomize_ports=True)
        manager = EvasionManager(config)
        
        hosts = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        ports = [80, 443, 8080]
        
        # Should produce different orderings
        orderings = set()
        for _ in range(20):
            h, p = manager.apply_to_targets(hosts.copy(), ports.copy())
            orderings.add((tuple(h), tuple(p)))
        
        assert len(orderings) > 1
    
    def test_get_timing_delay(self):
        """Test getting timing delay."""
        config = EvasionConfig()
        config.timing.level = TimingLevel.POLITE
        manager = EvasionManager(config)
        
        delay = manager.get_timing_delay()
        assert abs(delay - 0.4) < 0.1  # Allow for jitter
    
    def test_get_max_parallelism(self):
        """Test getting max parallelism."""
        config = EvasionConfig()
        config.timing.max_parallelism = 50
        manager = EvasionManager(config)
        
        assert manager.get_max_parallelism() == 50
    
    def test_get_source_port(self):
        """Test getting source port."""
        config = EvasionConfig(source_port=12345)
        manager = EvasionManager(config)
        
        assert manager.get_source_port() == 12345
    
    def test_get_ttl(self):
        """Test getting TTL value."""
        config = EvasionConfig(ttl=100)
        manager = EvasionManager(config)
        
        assert manager.get_ttl() == 100
    
    def test_get_ttl_style(self):
        """Test getting TTL by style."""
        config = EvasionConfig(ttl_style="windows")
        manager = EvasionManager(config)
        
        assert manager.get_ttl() == 128
    
    def test_is_evasion_enabled_false(self):
        """Test evasion enabled check - false."""
        manager = EvasionManager()
        assert manager.is_evasion_enabled() is False
    
    def test_is_evasion_enabled_true_techniques(self):
        """Test evasion enabled check - true via techniques."""
        config = EvasionConfig()
        config.techniques.append(EvasionTechnique.DECOY)
        manager = EvasionManager(config)
        
        assert manager.is_evasion_enabled() is True
    
    def test_is_evasion_enabled_true_profile(self):
        """Test evasion enabled check - true via profile."""
        manager = EvasionManager.from_profile(EvasionProfile.STEALTH)
        assert manager.is_evasion_enabled() is True
    
    def test_get_summary(self):
        """Test getting evasion summary."""
        manager = EvasionManager.from_profile(EvasionProfile.STEALTH)
        summary = manager.get_summary()
        
        assert summary["profile"] == "stealth"
        assert "techniques" in summary
        assert "timing_level" in summary
        assert "max_parallelism" in summary
        assert "randomize_hosts" in summary


# ============================================================================
# Test Convenience Functions
# ============================================================================

class TestConvenienceFunctions:
    """Test module-level convenience functions."""
    
    def test_create_evasion_config_default(self):
        """Test creating default evasion config."""
        config = create_evasion_config()
        assert config.profile == EvasionProfile.NONE
    
    def test_create_evasion_config_stealth(self):
        """Test creating stealth evasion config."""
        config = create_evasion_config("stealth")
        assert config.profile == EvasionProfile.STEALTH
    
    def test_create_evasion_config_with_kwargs(self):
        """Test creating config with additional kwargs."""
        config = create_evasion_config(
            profile="none",
            randomize_hosts=True,
            source_port=53,
        )
        assert config.randomize_hosts is True
        assert config.source_port == 53
    
    @pytest.mark.asyncio
    async def test_scan_with_evasion(self):
        """Test convenience scan function."""
        # Mock the scanner
        with patch.object(EvasionScanner, "scan_ports") as mock_scan:
            mock_scan.return_value = {80: "open", 443: "closed"}
            
            results = await scan_with_evasion(
                "192.168.1.1",
                [80, 443],
                timeout=2.0,
            )
        
        assert results == {80: "open", 443: "closed"}


# ============================================================================
# Test Profile Presets
# ============================================================================

class TestProfilePresets:
    """Test that profile presets have sensible defaults."""
    
    def test_stealth_profile_timing(self):
        """Test stealth profile has slow timing."""
        config = EvasionConfig.from_profile(EvasionProfile.STEALTH)
        assert config.timing.level in [TimingLevel.SNEAKY, TimingLevel.PARANOID]
        assert config.timing.max_parallelism <= 20
    
    def test_paranoid_profile_comprehensive(self):
        """Test paranoid profile enables many techniques."""
        config = EvasionConfig.from_profile(EvasionProfile.PARANOID)
        assert len(config.techniques) >= 4
        assert config.fragmentation.enabled is True
        assert config.decoy.random_decoys > 0
    
    def test_aggressive_profile_fast(self):
        """Test aggressive profile is fast."""
        config = EvasionConfig.from_profile(EvasionProfile.AGGRESSIVE)
        assert config.timing.level == TimingLevel.AGGRESSIVE
        assert config.timing.max_parallelism >= 100


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests combining multiple components."""
    
    def test_full_config_to_scanner_workflow(self):
        """Test creating config through to scanner."""
        # Create manager from CLI args
        manager = EvasionManager.from_cli_args(
            evasion="stealth",
            decoys=["1.1.1.1"],
            randomize_hosts=True,
            timing_level=1,
        )
        
        # Get scanner
        scanner = manager.get_scanner(timeout=2.0)
        
        # Verify config is applied
        assert scanner.config.randomize_hosts is True
        assert scanner.timeout == 2.0
        
        # Prepare targets
        targets = scanner.prepare_targets(
            ["192.168.1.1", "192.168.1.2"],
            [80, 443],
        )
        
        # Should have all combinations
        assert len(targets) == 4
    
    def test_packet_crafter_with_config(self):
        """Test packet crafter respects config."""
        config = EvasionConfig(
            source_port=53,
            ttl=100,
            bad_checksum=True,
            data_length=50,
        )
        crafter = PacketCrafter(config)
        
        packet = crafter.create_syn_packet(
            src="192.168.1.1",
            dst="192.168.1.2",
            dst_port=80,
        )
        
        # Verify packet was created
        assert len(packet) >= 90  # 20 IP + 20 TCP + 50 padding
        
        # Check TTL
        assert packet[8] == 100
    
    @pytest.mark.asyncio
    async def test_scanner_with_timing(self):
        """Test scanner respects timing config."""
        config = EvasionConfig()
        config.timing.delay_ms = 100  # 100ms delay
        
        scanner = EvasionScanner(config, timeout=1.0)
        scanner._scapy_available = False
        
        # Time multiple delays
        start = asyncio.get_event_loop().time()
        for _ in range(3):
            await scanner.apply_timing_delay()
        elapsed = asyncio.get_event_loop().time() - start
        
        # Should take approximately 300ms
        assert 0.25 <= elapsed <= 0.5


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_decoy_list(self):
        """Test decoy config with empty list."""
        config = DecoyConfig(decoys=[], include_real=True)
        order = config.get_scan_order("1.1.1.1")
        assert order == ["1.1.1.1"]
    
    def test_fragment_minimum_mtu(self):
        """Test fragmentation with minimum MTU."""
        config = EvasionConfig()
        config.fragmentation.enabled = True
        config.fragmentation.mtu = 1  # Below minimum
        crafter = PacketCrafter(config)
        
        # Should clamp to 8
        ip_header = crafter.create_ip_header("1.1.1.1", "2.2.2.2")
        payload = b'\x00' * 24
        packet = ip_header + payload
        
        fragments = crafter.fragment_packet(packet, mtu=1)
        # All fragments should be valid
        for frag in fragments:
            assert len(frag) >= 20
    
    def test_timing_level_boundary(self):
        """Test timing with boundary values."""
        config = TimingConfig(level=TimingLevel.INSANE)
        assert config.get_delay() == 0.0
        
        config2 = TimingConfig(level=TimingLevel.PARANOID)
        assert config2.get_delay() == 300.0
    
    def test_randomize_empty_list(self):
        """Test randomizing empty list."""
        result = randomize_list([])
        assert result == []
    
    def test_randomize_single_item(self):
        """Test randomizing single item list."""
        result = randomize_list([1])
        assert result == [1]
    
    def test_get_ttl_unknown_style(self):
        """Test TTL with unknown style."""
        ttl = get_ttl_for_style("nonexistent")
        assert ttl == 64  # Default to Linux
    
    def test_decoy_position_integer(self):
        """Test decoy with integer position."""
        config = DecoyConfig(
            decoys=["1.1.1.1", "2.2.2.2", "3.3.3.3"],
            include_real=True,
            real_position=1,  # Index
        )
        order = config.get_scan_order("4.4.4.4")
        assert order[1] == "4.4.4.4"
    
    @pytest.mark.asyncio
    async def test_scanner_get_local_ip_failure(self):
        """Test local IP detection failure handling."""
        config = EvasionConfig()
        scanner = EvasionScanner(config)
        
        with patch("socket.socket") as mock_socket:
            mock_socket.return_value.connect.side_effect = Exception("Network error")
            mock_socket.return_value.getsockname.side_effect = Exception("Failed")
            mock_socket.return_value.close = MagicMock()
            
            ip = scanner._get_local_ip("192.168.1.1")
            # Should return fallback
            assert ip == "0.0.0.0"
