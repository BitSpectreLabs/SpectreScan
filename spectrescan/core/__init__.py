"""Core scanning engine modules."""

from spectrescan.core.scanner import PortScanner
from spectrescan.core.presets import ScanPreset
from spectrescan.core.ssl_analyzer import (
    SSLAnalyzer,
    SSLAnalysisResult,
    CertificateInfo,
    CipherInfo,
    VulnerabilityResult,
    TLSVersion,
    CipherStrength,
    VulnerabilityStatus,
    analyze_ssl,
    get_certificate_info,
    check_ssl_vulnerabilities,
)
from spectrescan.core.cve_matcher import (
    CVEMatcher,
    CVEEntry,
    CVEMatchResult,
    CVESeverity,
    CVSSScore,
    CVSSVersion,
    CVEReference,
    CVECache,
    format_cve_report,
    cve_result_to_dict,
)
from spectrescan.core.checkpoint import (
    CheckpointManager,
    CheckpointData,
    CheckpointState,
    ScanProgress,
    can_resume_scan,
    get_resume_summary,
)
from spectrescan.core.config import (
    ConfigManager,
    SpectrescanConfig,
    ScanDefaults,
    ServiceDetectionConfig,
    OutputConfig,
    APIConfig,
    NotificationsConfig,
    CheckpointsConfig,
    AdvancedConfig,
    ConfigError,
    get_config,
    get_config_manager,
    reload_config,
)

# DNS Enumeration - optional import (requires dnspython)
try:
    from spectrescan.core.dns_enum import (
        DNSEnumerator,
        DNSRecord,
        DNSRecordType,
        DNSEnumerationResult,
        SubdomainResult,
        ZoneTransferResult,
        format_dns_report,
    )
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    DNSEnumerator = None
    DNSRecord = None
    DNSRecordType = None
    DNSEnumerationResult = None
    SubdomainResult = None
    ZoneTransferResult = None
    format_dns_report = None

# NSE Engine - optional import (requires lupa for execution)
try:
    from spectrescan.core.nse_engine import (
        NSEEngine,
        NSEScriptInfo,
        NSEScriptResult,
        NSEHostInfo,
        NSEPortInfo,
        NSECategory,
        NSEScriptParser,
        NSELibrary,
        parse_script_args,
        format_nse_results,
        create_nse_engine,
    )
    NSE_AVAILABLE = True
except ImportError:
    NSE_AVAILABLE = False
    NSEEngine = None
    NSEScriptInfo = None
    NSEScriptResult = None
    NSEHostInfo = None
    NSEPortInfo = None
    NSECategory = None
    NSEScriptParser = None
    NSELibrary = None
    parse_script_args = None
    format_nse_results = None
    create_nse_engine = None

__all__ = [
    "PortScanner",
    "ScanPreset",
    # SSL Analyzer
    "SSLAnalyzer",
    "SSLAnalysisResult",
    "CertificateInfo",
    "CipherInfo",
    "VulnerabilityResult",
    "TLSVersion",
    "CipherStrength",
    "VulnerabilityStatus",
    "analyze_ssl",
    "get_certificate_info",
    "check_ssl_vulnerabilities",
    # CVE Matcher
    "CVEMatcher",
    "CVEEntry",
    "CVEMatchResult",
    "CVESeverity",
    "CVSSScore",
    "CVSSVersion",
    "CVEReference",
    "CVECache",
    "format_cve_report",
    "cve_result_to_dict",
    # Checkpoint
    "CheckpointManager",
    "CheckpointData",
    "CheckpointState",
    "ScanProgress",
    "can_resume_scan",
    "get_resume_summary",
    # Config
    "ConfigManager",
    "SpectrescanConfig",
    "ScanDefaults",
    "ServiceDetectionConfig",
    "OutputConfig",
    "APIConfig",
    "NotificationsConfig",
    "CheckpointsConfig",
    "AdvancedConfig",
    "ConfigError",
    "get_config",
    "get_config_manager",
    "reload_config",
    # DNS Enumeration
    "DNS_AVAILABLE",
    "DNSEnumerator",
    "DNSRecord",
    "DNSRecordType",
    "DNSEnumerationResult",
    "SubdomainResult",
    "ZoneTransferResult",
    "format_dns_report",
    # NSE Engine
    "NSE_AVAILABLE",
    "NSEEngine",
    "NSEScriptInfo",
    "NSEScriptResult",
    "NSEHostInfo",
    "NSEPortInfo",
    "NSECategory",
    "NSEScriptParser",
    "NSELibrary",
    "parse_script_args",
    "format_nse_results",
    "create_nse_engine",
]
