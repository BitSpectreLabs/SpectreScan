"""
Configuration File Support for SpectreScan.

Provides TOML-based configuration management:
- Default config location (~/.spectrescan/config.toml)
- Project-level config (.spectrescan.toml)
- Environment variable overrides
- Config validation and error messages
- Config generation and display commands

by BitSpectreLabs
"""

import os
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Union
from enum import Enum

# Use tomllib for Python 3.11+, fallback to tomli for older versions
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None  # type: ignore


class ConfigSection(str, Enum):
    """Configuration sections."""
    DEFAULTS = "defaults"
    SCAN = "scan"
    SERVICE_DETECTION = "service_detection"
    OUTPUT = "output"
    API = "api"
    NOTIFICATIONS = "notifications"
    CHECKPOINTS = "checkpoints"
    ADVANCED = "advanced"


@dataclass
class ScanDefaults:
    """Default scan configuration."""
    threads: int = 100
    timeout: float = 2.0
    rate_limit: Optional[int] = None
    randomize: bool = False
    default_ports: str = "1-1000"
    scan_type: str = "tcp"
    timing_template: int = 3
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanDefaults":
        """Create from dictionary."""
        return cls(
            threads=data.get("threads", 100),
            timeout=data.get("timeout", 2.0),
            rate_limit=data.get("rate_limit"),
            randomize=data.get("randomize", False),
            default_ports=data.get("default_ports", "1-1000"),
            scan_type=data.get("scan_type", "tcp"),
            timing_template=data.get("timing_template", 3),
        )


@dataclass
class ServiceDetectionConfig:
    """Service detection configuration."""
    enabled: bool = True
    banner_grabbing: bool = True
    os_detection: bool = False
    ssl_analysis: bool = False
    cve_matching: bool = False
    version_intensity: int = 7
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServiceDetectionConfig":
        """Create from dictionary."""
        return cls(
            enabled=data.get("enabled", True),
            banner_grabbing=data.get("banner_grabbing", True),
            os_detection=data.get("os_detection", False),
            ssl_analysis=data.get("ssl_analysis", False),
            cve_matching=data.get("cve_matching", False),
            version_intensity=data.get("version_intensity", 7),
        )


@dataclass
class OutputConfig:
    """Output configuration."""
    default_format: str = "text"
    color_enabled: bool = True
    verbose: bool = False
    quiet: bool = False
    save_results: bool = False
    results_directory: str = "~/.spectrescan/results"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OutputConfig":
        """Create from dictionary."""
        return cls(
            default_format=data.get("default_format", "text"),
            color_enabled=data.get("color_enabled", True),
            verbose=data.get("verbose", False),
            quiet=data.get("quiet", False),
            save_results=data.get("save_results", False),
            results_directory=data.get("results_directory", "~/.spectrescan/results"),
        )


@dataclass
class APIConfig:
    """API server configuration."""
    host: str = "127.0.0.1"
    port: int = 8080
    workers: int = 4
    enable_auth: bool = True
    token_expiry_hours: int = 24
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "APIConfig":
        """Create from dictionary."""
        return cls(
            host=data.get("host", "127.0.0.1"),
            port=data.get("port", 8080),
            workers=data.get("workers", 4),
            enable_auth=data.get("enable_auth", True),
            token_expiry_hours=data.get("token_expiry_hours", 24),
            cors_origins=data.get("cors_origins", ["*"]),
        )


@dataclass
class NotificationsConfig:
    """Notification configuration."""
    enabled: bool = False
    on_scan_complete: bool = True
    on_scan_error: bool = True
    on_critical_finding: bool = True
    webhook_url: Optional[str] = None
    slack_webhook: Optional[str] = None
    discord_webhook: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NotificationsConfig":
        """Create from dictionary."""
        return cls(
            enabled=data.get("enabled", False),
            on_scan_complete=data.get("on_scan_complete", True),
            on_scan_error=data.get("on_scan_error", True),
            on_critical_finding=data.get("on_critical_finding", True),
            webhook_url=data.get("webhook_url"),
            slack_webhook=data.get("slack_webhook"),
            discord_webhook=data.get("discord_webhook"),
        )


@dataclass
class CheckpointsConfig:
    """Checkpoint configuration."""
    enabled: bool = True
    auto_save: bool = True
    auto_save_interval: int = 30
    cleanup_days: int = 7
    checkpoint_directory: str = "~/.spectrescan/checkpoints"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CheckpointsConfig":
        """Create from dictionary."""
        return cls(
            enabled=data.get("enabled", True),
            auto_save=data.get("auto_save", True),
            auto_save_interval=data.get("auto_save_interval", 30),
            cleanup_days=data.get("cleanup_days", 7),
            checkpoint_directory=data.get("checkpoint_directory", "~/.spectrescan/checkpoints"),
        )


@dataclass
class AdvancedConfig:
    """Advanced configuration."""
    max_retries: int = 3
    retry_delay: float = 1.0
    connection_pool_size: int = 100
    dns_timeout: float = 5.0
    max_memory_mb: int = 512
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AdvancedConfig":
        """Create from dictionary."""
        return cls(
            max_retries=data.get("max_retries", 3),
            retry_delay=data.get("retry_delay", 1.0),
            connection_pool_size=data.get("connection_pool_size", 100),
            dns_timeout=data.get("dns_timeout", 5.0),
            max_memory_mb=data.get("max_memory_mb", 512),
            log_level=data.get("log_level", "INFO"),
            log_file=data.get("log_file"),
        )


@dataclass
class SpectrescanConfig:
    """
    Complete SpectreScan configuration.
    
    Contains all configuration sections.
    """
    scan: ScanDefaults = field(default_factory=ScanDefaults)
    service_detection: ServiceDetectionConfig = field(default_factory=ServiceDetectionConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    api: APIConfig = field(default_factory=APIConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    checkpoints: CheckpointsConfig = field(default_factory=CheckpointsConfig)
    advanced: AdvancedConfig = field(default_factory=AdvancedConfig)
    
    # Custom profiles
    profiles: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan": self.scan.to_dict(),
            "service_detection": self.service_detection.to_dict(),
            "output": self.output.to_dict(),
            "api": self.api.to_dict(),
            "notifications": self.notifications.to_dict(),
            "checkpoints": self.checkpoints.to_dict(),
            "advanced": self.advanced.to_dict(),
            "profiles": self.profiles,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SpectrescanConfig":
        """Create from dictionary."""
        return cls(
            scan=ScanDefaults.from_dict(data.get("scan", {})),
            service_detection=ServiceDetectionConfig.from_dict(data.get("service_detection", {})),
            output=OutputConfig.from_dict(data.get("output", {})),
            api=APIConfig.from_dict(data.get("api", {})),
            notifications=NotificationsConfig.from_dict(data.get("notifications", {})),
            checkpoints=CheckpointsConfig.from_dict(data.get("checkpoints", {})),
            advanced=AdvancedConfig.from_dict(data.get("advanced", {})),
            profiles=data.get("profiles", {}),
        )
    
    def get_value(self, key_path: str) -> Any:
        """
        Get a configuration value by dot-separated path.
        
        Args:
            key_path: Dot-separated path (e.g., "scan.threads")
        
        Returns:
            Configuration value
        """
        parts = key_path.split(".")
        obj: Any = self.to_dict()
        
        for part in parts:
            if isinstance(obj, dict):
                if part not in obj:
                    raise KeyError(f"Configuration key not found: {key_path}")
                obj = obj[part]
            else:
                raise KeyError(f"Configuration key not found: {key_path}")
        
        return obj
    
    def set_value(self, key_path: str, value: Any) -> None:
        """
        Set a configuration value by dot-separated path.
        
        Args:
            key_path: Dot-separated path (e.g., "scan.threads")
            value: Value to set
        """
        parts = key_path.split(".")
        if len(parts) < 2:
            raise ValueError(f"Invalid key path: {key_path}")
        
        section = parts[0]
        key = parts[1]
        
        # Get the section object
        if hasattr(self, section):
            section_obj = getattr(self, section)
            if hasattr(section_obj, key):
                # Convert value type if needed
                current_value = getattr(section_obj, key)
                if current_value is not None:
                    if isinstance(current_value, bool):
                        value = str(value).lower() in ("true", "1", "yes")
                    elif isinstance(current_value, int):
                        value = int(value)
                    elif isinstance(current_value, float):
                        value = float(value)
                setattr(section_obj, key, value)
            else:
                raise KeyError(f"Configuration key not found: {key_path}")
        else:
            raise KeyError(f"Configuration section not found: {section}")


class ConfigError(Exception):
    """Configuration error."""
    pass


class ConfigManager:
    """
    Configuration file manager.
    
    Handles loading and saving configuration from multiple sources:
    1. Built-in defaults
    2. User config (~/.spectrescan/config.toml)
    3. Project config (.spectrescan.toml)
    4. Environment variables (SPECTRESCAN_*)
    5. CLI arguments (highest priority)
    """
    
    DEFAULT_USER_CONFIG = Path.home() / ".spectrescan" / "config.toml"
    PROJECT_CONFIG_NAME = ".spectrescan.toml"
    ENV_PREFIX = "SPECTRESCAN_"
    
    def __init__(
        self,
        user_config_path: Optional[Path] = None,
        project_config_path: Optional[Path] = None,
        load_env: bool = True
    ):
        """
        Initialize ConfigManager.
        
        Args:
            user_config_path: Custom user config path
            project_config_path: Custom project config path
            load_env: Whether to load from environment variables
        """
        self.user_config_path = user_config_path or self.DEFAULT_USER_CONFIG
        self.project_config_path = project_config_path
        self.load_env = load_env
        
        # Start with defaults
        self._config = SpectrescanConfig()
        self._loaded_sources: List[str] = ["defaults"]
    
    def load(self) -> SpectrescanConfig:
        """
        Load configuration from all sources.
        
        Priority (lowest to highest):
        1. Built-in defaults
        2. User config
        3. Project config
        4. Environment variables
        
        Returns:
            Merged SpectrescanConfig
        """
        # Start fresh with defaults
        self._config = SpectrescanConfig()
        self._loaded_sources = ["defaults"]
        
        # Load user config
        if self.user_config_path.exists():
            try:
                self._load_toml_file(self.user_config_path)
                self._loaded_sources.append(f"user:{self.user_config_path}")
            except Exception as e:
                raise ConfigError(f"Error loading user config: {e}")
        
        # Find and load project config
        project_config = self._find_project_config()
        if project_config and project_config.exists():
            try:
                self._load_toml_file(project_config)
                self._loaded_sources.append(f"project:{project_config}")
            except Exception as e:
                raise ConfigError(f"Error loading project config: {e}")
        
        # Load environment variables
        if self.load_env:
            self._load_environment()
        
        return self._config
    
    def get_config(self) -> SpectrescanConfig:
        """Get current configuration."""
        return self._config
    
    def get_loaded_sources(self) -> List[str]:
        """Get list of loaded configuration sources."""
        return self._loaded_sources.copy()
    
    def save_user_config(
        self,
        config: Optional[SpectrescanConfig] = None,
        path: Optional[Path] = None
    ) -> Path:
        """
        Save configuration to user config file.
        
        Args:
            config: Configuration to save (uses current if None)
            path: Custom path (uses default if None)
        
        Returns:
            Path to saved config file
        """
        config = config or self._config
        path = path or self.user_config_path
        
        # Ensure directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate TOML content
        content = self._generate_toml(config)
        
        with open(path, "w") as f:
            f.write(content)
        
        return path
    
    def init_config(
        self,
        path: Optional[Path] = None,
        include_comments: bool = True
    ) -> Path:
        """
        Initialize a new configuration file with defaults.
        
        Args:
            path: Path for config file
            include_comments: Whether to include comments
        
        Returns:
            Path to created config file
        """
        path = path or self.user_config_path
        
        if path.exists():
            raise ConfigError(f"Config file already exists: {path}")
        
        config = SpectrescanConfig()
        content = self._generate_toml(config, include_comments=include_comments)
        
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        
        return path
    
    def get_value(self, key_path: str) -> Any:
        """Get a configuration value by dot-separated path."""
        return self._config.get_value(key_path)
    
    def set_value(self, key_path: str, value: Any) -> None:
        """Set a configuration value by dot-separated path."""
        self._config.set_value(key_path, value)
    
    def show_config(self, section: Optional[str] = None) -> str:
        """
        Generate a display string for configuration.
        
        Args:
            section: Specific section to show (shows all if None)
        
        Returns:
            Formatted configuration string
        """
        config_dict = self._config.to_dict()
        
        if section:
            if section not in config_dict:
                raise ConfigError(f"Unknown section: {section}")
            config_dict = {section: config_dict[section]}
        
        return self._format_config_display(config_dict)
    
    def validate(self) -> List[str]:
        """
        Validate current configuration.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Validate scan settings
        if self._config.scan.threads < 1:
            errors.append("scan.threads must be at least 1")
        if self._config.scan.threads > 10000:
            errors.append("scan.threads should not exceed 10000")
        
        if self._config.scan.timeout <= 0:
            errors.append("scan.timeout must be positive")
        
        if self._config.scan.timing_template < 0 or self._config.scan.timing_template > 5:
            errors.append("scan.timing_template must be between 0 and 5")
        
        # Validate API settings
        if self._config.api.port < 1 or self._config.api.port > 65535:
            errors.append("api.port must be between 1 and 65535")
        
        if self._config.api.workers < 1:
            errors.append("api.workers must be at least 1")
        
        # Validate checkpoint settings
        if self._config.checkpoints.auto_save_interval < 5:
            errors.append("checkpoints.auto_save_interval should be at least 5 seconds")
        
        # Validate advanced settings
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self._config.advanced.log_level.upper() not in valid_log_levels:
            errors.append(f"advanced.log_level must be one of: {', '.join(valid_log_levels)}")
        
        return errors
    
    def _find_project_config(self) -> Optional[Path]:
        """Find project config file by walking up directory tree."""
        if self.project_config_path:
            return self.project_config_path
        
        # Start from current directory
        current = Path.cwd()
        
        while current != current.parent:
            config_path = current / self.PROJECT_CONFIG_NAME
            if config_path.exists():
                return config_path
            current = current.parent
        
        return None
    
    def _load_toml_file(self, path: Path) -> None:
        """Load and merge a TOML config file."""
        if tomllib is None:
            raise ConfigError(
                "TOML support requires Python 3.11+ or 'tomli' package. "
                "Install with: pip install tomli"
            )
        
        with open(path, "rb") as f:
            data = tomllib.load(f)
        
        self._merge_config(data)
    
    def _merge_config(self, data: Dict[str, Any]) -> None:
        """Merge loaded config data into current config."""
        if "scan" in data:
            self._config.scan = ScanDefaults.from_dict({
                **self._config.scan.to_dict(),
                **data["scan"]
            })
        
        if "service_detection" in data:
            self._config.service_detection = ServiceDetectionConfig.from_dict({
                **self._config.service_detection.to_dict(),
                **data["service_detection"]
            })
        
        if "output" in data:
            self._config.output = OutputConfig.from_dict({
                **self._config.output.to_dict(),
                **data["output"]
            })
        
        if "api" in data:
            self._config.api = APIConfig.from_dict({
                **self._config.api.to_dict(),
                **data["api"]
            })
        
        if "notifications" in data:
            self._config.notifications = NotificationsConfig.from_dict({
                **self._config.notifications.to_dict(),
                **data["notifications"]
            })
        
        if "checkpoints" in data:
            self._config.checkpoints = CheckpointsConfig.from_dict({
                **self._config.checkpoints.to_dict(),
                **data["checkpoints"]
            })
        
        if "advanced" in data:
            self._config.advanced = AdvancedConfig.from_dict({
                **self._config.advanced.to_dict(),
                **data["advanced"]
            })
        
        if "profiles" in data:
            self._config.profiles.update(data["profiles"])
    
    def _load_environment(self) -> None:
        """Load configuration from environment variables."""
        env_mappings = {
            # Scan settings
            f"{self.ENV_PREFIX}THREADS": ("scan", "threads", int),
            f"{self.ENV_PREFIX}TIMEOUT": ("scan", "timeout", float),
            f"{self.ENV_PREFIX}RATE_LIMIT": ("scan", "rate_limit", int),
            f"{self.ENV_PREFIX}RANDOMIZE": ("scan", "randomize", self._parse_bool),
            f"{self.ENV_PREFIX}SCAN_TYPE": ("scan", "scan_type", str),
            f"{self.ENV_PREFIX}TIMING": ("scan", "timing_template", int),
            
            # Service detection
            f"{self.ENV_PREFIX}SERVICE_DETECTION": ("service_detection", "enabled", self._parse_bool),
            f"{self.ENV_PREFIX}BANNER_GRABBING": ("service_detection", "banner_grabbing", self._parse_bool),
            f"{self.ENV_PREFIX}OS_DETECTION": ("service_detection", "os_detection", self._parse_bool),
            f"{self.ENV_PREFIX}SSL_ANALYSIS": ("service_detection", "ssl_analysis", self._parse_bool),
            f"{self.ENV_PREFIX}CVE_MATCHING": ("service_detection", "cve_matching", self._parse_bool),
            
            # Output
            f"{self.ENV_PREFIX}OUTPUT_FORMAT": ("output", "default_format", str),
            f"{self.ENV_PREFIX}COLOR": ("output", "color_enabled", self._parse_bool),
            f"{self.ENV_PREFIX}VERBOSE": ("output", "verbose", self._parse_bool),
            f"{self.ENV_PREFIX}QUIET": ("output", "quiet", self._parse_bool),
            
            # API
            f"{self.ENV_PREFIX}API_HOST": ("api", "host", str),
            f"{self.ENV_PREFIX}API_PORT": ("api", "port", int),
            f"{self.ENV_PREFIX}API_WORKERS": ("api", "workers", int),
            f"{self.ENV_PREFIX}API_AUTH": ("api", "enable_auth", self._parse_bool),
            
            # Checkpoints
            f"{self.ENV_PREFIX}CHECKPOINTS": ("checkpoints", "enabled", self._parse_bool),
            f"{self.ENV_PREFIX}AUTOSAVE": ("checkpoints", "auto_save", self._parse_bool),
            f"{self.ENV_PREFIX}AUTOSAVE_INTERVAL": ("checkpoints", "auto_save_interval", int),
            
            # Advanced
            f"{self.ENV_PREFIX}LOG_LEVEL": ("advanced", "log_level", str),
            f"{self.ENV_PREFIX}LOG_FILE": ("advanced", "log_file", str),
            f"{self.ENV_PREFIX}MAX_MEMORY": ("advanced", "max_memory_mb", int),
        }
        
        for env_var, (section, key, converter) in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                try:
                    converted = converter(value)
                    section_obj = getattr(self._config, section)
                    setattr(section_obj, key, converted)
                    if "environment" not in self._loaded_sources:
                        self._loaded_sources.append("environment")
                except (ValueError, TypeError):
                    pass
    
    @staticmethod
    def _parse_bool(value: str) -> bool:
        """Parse boolean from string."""
        return value.lower() in ("true", "1", "yes", "on")
    
    def _generate_toml(
        self,
        config: SpectrescanConfig,
        include_comments: bool = True
    ) -> str:
        """Generate TOML content from config."""
        lines = []
        
        if include_comments:
            lines.extend([
                "# SpectreScan Configuration File",
                "# Generated by SpectreScan",
                "# https://github.com/BitSpectreLabs/SpectreScan",
                "",
            ])
        
        # Scan section
        if include_comments:
            lines.extend([
                "# Scan defaults",
                "# These settings apply to all scans unless overridden by CLI options",
            ])
        lines.append("[scan]")
        lines.append(f"threads = {config.scan.threads}")
        lines.append(f"timeout = {config.scan.timeout}")
        if config.scan.rate_limit:
            lines.append(f"rate_limit = {config.scan.rate_limit}")
        lines.append(f"randomize = {str(config.scan.randomize).lower()}")
        lines.append(f'default_ports = "{config.scan.default_ports}"')
        lines.append(f'scan_type = "{config.scan.scan_type}"')
        lines.append(f"timing_template = {config.scan.timing_template}")
        lines.append("")
        
        # Service detection section
        if include_comments:
            lines.append("# Service detection settings")
        lines.append("[service_detection]")
        lines.append(f"enabled = {str(config.service_detection.enabled).lower()}")
        lines.append(f"banner_grabbing = {str(config.service_detection.banner_grabbing).lower()}")
        lines.append(f"os_detection = {str(config.service_detection.os_detection).lower()}")
        lines.append(f"ssl_analysis = {str(config.service_detection.ssl_analysis).lower()}")
        lines.append(f"cve_matching = {str(config.service_detection.cve_matching).lower()}")
        lines.append(f"version_intensity = {config.service_detection.version_intensity}")
        lines.append("")
        
        # Output section
        if include_comments:
            lines.append("# Output settings")
        lines.append("[output]")
        lines.append(f'default_format = "{config.output.default_format}"')
        lines.append(f"color_enabled = {str(config.output.color_enabled).lower()}")
        lines.append(f"verbose = {str(config.output.verbose).lower()}")
        lines.append(f"quiet = {str(config.output.quiet).lower()}")
        lines.append(f"save_results = {str(config.output.save_results).lower()}")
        lines.append(f'results_directory = "{config.output.results_directory}"')
        lines.append("")
        
        # API section
        if include_comments:
            lines.append("# API server settings")
        lines.append("[api]")
        lines.append(f'host = "{config.api.host}"')
        lines.append(f"port = {config.api.port}")
        lines.append(f"workers = {config.api.workers}")
        lines.append(f"enable_auth = {str(config.api.enable_auth).lower()}")
        lines.append(f"token_expiry_hours = {config.api.token_expiry_hours}")
        cors_str = ", ".join(f'"{o}"' for o in config.api.cors_origins)
        lines.append(f"cors_origins = [{cors_str}]")
        lines.append("")
        
        # Notifications section
        if include_comments:
            lines.append("# Notification settings")
        lines.append("[notifications]")
        lines.append(f"enabled = {str(config.notifications.enabled).lower()}")
        lines.append(f"on_scan_complete = {str(config.notifications.on_scan_complete).lower()}")
        lines.append(f"on_scan_error = {str(config.notifications.on_scan_error).lower()}")
        lines.append(f"on_critical_finding = {str(config.notifications.on_critical_finding).lower()}")
        if config.notifications.webhook_url:
            lines.append(f'webhook_url = "{config.notifications.webhook_url}"')
        if config.notifications.slack_webhook:
            lines.append(f'slack_webhook = "{config.notifications.slack_webhook}"')
        if config.notifications.discord_webhook:
            lines.append(f'discord_webhook = "{config.notifications.discord_webhook}"')
        lines.append("")
        
        # Checkpoints section
        if include_comments:
            lines.append("# Checkpoint settings for scan resume")
        lines.append("[checkpoints]")
        lines.append(f"enabled = {str(config.checkpoints.enabled).lower()}")
        lines.append(f"auto_save = {str(config.checkpoints.auto_save).lower()}")
        lines.append(f"auto_save_interval = {config.checkpoints.auto_save_interval}")
        lines.append(f"cleanup_days = {config.checkpoints.cleanup_days}")
        lines.append(f'checkpoint_directory = "{config.checkpoints.checkpoint_directory}"')
        lines.append("")
        
        # Advanced section
        if include_comments:
            lines.append("# Advanced settings")
        lines.append("[advanced]")
        lines.append(f"max_retries = {config.advanced.max_retries}")
        lines.append(f"retry_delay = {config.advanced.retry_delay}")
        lines.append(f"connection_pool_size = {config.advanced.connection_pool_size}")
        lines.append(f"dns_timeout = {config.advanced.dns_timeout}")
        lines.append(f"max_memory_mb = {config.advanced.max_memory_mb}")
        lines.append(f'log_level = "{config.advanced.log_level}"')
        if config.advanced.log_file:
            lines.append(f'log_file = "{config.advanced.log_file}"')
        lines.append("")
        
        # Profiles section
        if config.profiles:
            if include_comments:
                lines.append("# Custom scan profiles")
            lines.append("[profiles]")
            for name, profile in config.profiles.items():
                lines.append(f'[profiles."{name}"]')
                for key, value in profile.items():
                    if isinstance(value, str):
                        lines.append(f'{key} = "{value}"')
                    elif isinstance(value, bool):
                        lines.append(f"{key} = {str(value).lower()}")
                    elif isinstance(value, list):
                        list_str = ", ".join(str(v) for v in value)
                        lines.append(f"{key} = [{list_str}]")
                    else:
                        lines.append(f"{key} = {value}")
                lines.append("")
        
        return "\n".join(lines)
    
    def _format_config_display(self, config_dict: Dict[str, Any], indent: int = 0) -> str:
        """Format config dictionary for display."""
        lines = []
        prefix = "  " * indent
        
        for key, value in config_dict.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}[{key}]")
                lines.append(self._format_config_display(value, indent + 1))
            elif isinstance(value, list):
                list_str = ", ".join(str(v) for v in value)
                lines.append(f"{prefix}{key} = [{list_str}]")
            elif isinstance(value, str):
                lines.append(f'{prefix}{key} = "{value}"')
            elif isinstance(value, bool):
                lines.append(f"{prefix}{key} = {str(value).lower()}")
            elif value is None:
                lines.append(f"{prefix}{key} = (not set)")
            else:
                lines.append(f"{prefix}{key} = {value}")
        
        return "\n".join(lines)


# Global config manager instance
_config_manager: Optional[ConfigManager] = None


def get_config_manager() -> ConfigManager:
    """Get or create global config manager."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
        _config_manager.load()
    return _config_manager


def get_config() -> SpectrescanConfig:
    """Get current configuration."""
    return get_config_manager().get_config()


def reload_config() -> SpectrescanConfig:
    """Reload configuration from all sources."""
    global _config_manager
    _config_manager = ConfigManager()
    return _config_manager.load()
