//! Typed configuration (`docs/contracts/config.md`).
//!
//! Layering: built-in defaults ← YAML file ← `SECURE_WEB__<SECTION>__<KEY>` environment variables.
//! Unknown keys are hard errors at every level (`deny_unknown_fields`), including keys that arrive
//! through the environment. [`Config::validate`] rejects every setting that would weaken a
//! security control (threat T16); callers must not use a config that failed validation.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};

/// Environment variable prefix for overrides; segments are separated by `__`.
pub const ENV_PREFIX: &str = "SECURE_WEB__";
/// Config file looked up in the current directory.
pub const CWD_CONFIG_FILE: &str = "secure-web.yaml";
/// Config file looked up under the home directory.
pub const HOME_CONFIG_FILE: &str = ".secure-web/config.yaml";
/// Hard maximum for `crawl.maxDepth`.
pub const MAX_CRAWL_DEPTH: u32 = 5;
/// Hard maximum for `crawl.maxPages`.
pub const MAX_CRAWL_PAGES: u32 = 1000;
/// The only accepted `security.scanner.failurePolicy`.
pub const SCANNER_FAILURE_POLICY_BLOCK: &str = "block";
/// Length of [`Config::policy_version`].
pub const POLICY_VERSION_LEN: usize = 12;

const DEFAULT_LISTEN_PORT: u16 = 8787;
const MB: u64 = 1_000_000;

/// Errors loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A config file could not be read.
    #[error("cannot read config file {path}: {source}")]
    Read {
        /// File path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// YAML syntax error, unknown key, or a value of the wrong type.
    #[error("invalid config ({origin}): {message}")]
    Parse {
        /// Where the failing input came from (file path, `environment`, or `merged config`).
        origin: String,
        /// Parser message.
        message: String,
    },
    /// A `SECURE_WEB__…` environment variable is malformed.
    #[error("invalid environment override {var}: {message}")]
    Env {
        /// Variable name.
        var: String,
        /// What is wrong with it.
        message: String,
    },
    /// The process environment could not be inspected (current directory, …).
    #[error("cannot resolve config search path: {0}")]
    Environment(String),
    /// One or more validation rules failed.
    #[error("config rejected: {}", format_violations(.violations))]
    Invalid {
        /// Every failed rule, in check order.
        violations: Vec<ConfigViolation>,
    },
    /// The config could not be serialized.
    #[error("cannot serialize config: {0}")]
    Serialize(String),
}

/// One failed validation rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigViolation {
    /// Dotted camelCase key, e.g. `security.network.blockPrivateAddresses`.
    pub key: String,
    /// Why the value is rejected.
    pub message: String,
}

impl fmt::Display for ConfigViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.key, self.message)
    }
}

fn format_violations(violations: &[ConfigViolation]) -> String {
    violations
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Non-fatal findings from [`Config::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigWarning {
    /// The scanner executable was not found. Every scan will fail closed (block) until it is.
    ScannerNotFound {
        /// Configured `security.scanner.executable`.
        executable: String,
    },
}

impl fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigWarning::ScannerNotFound { executable } => write!(
                f,
                "security.scanner.executable {executable:?} not found; every page will be blocked \
                 (SCANNER_FAILURE) until it is installed"
            ),
        }
    }
}

/// Where the effective config file came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// Loaded from this file (explicit `--config`, `./secure-web.yaml` or `~/.secure-web/config.yaml`).
    File(PathBuf),
    /// No file found; built-in defaults (plus environment overrides).
    Defaults,
}

impl fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigSource::File(path) => write!(f, "{}", path.display()),
            ConfigSource::Defaults => f.write_str("built-in defaults"),
        }
    }
}

/// A loaded and validated config.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedConfig {
    /// The effective config.
    pub config: Config,
    /// Which file (if any) it came from.
    pub source: ConfigSource,
    /// Non-fatal validation findings.
    pub warnings: Vec<ConfigWarning>,
}

// -------------------------------------------------------------------------------------------------
// Config tree
// -------------------------------------------------------------------------------------------------

/// Root of `secure-web.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    /// MCP server.
    pub server: ServerConfig,
    /// HTTP fetching.
    pub fetch: FetchConfig,
    /// Extraction limits.
    pub extract: ExtractConfig,
    /// Crawl budgets and scope.
    pub crawl: CrawlConfig,
    /// Scanner, policy and network protections. Hashed into [`Config::policy_version`].
    pub security: SecurityConfig,
    /// Search provider (v0.2).
    pub search: SearchConfig,
    /// Debugging.
    pub debug: DebugConfig,
}

/// `server:` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerConfig {
    /// MCP streamable-HTTP listen address.
    pub listen: SocketAddr,
    /// Permit a non-loopback `listen` address.
    pub allow_remote: bool,
    /// Workspace root (`runs/`, `private-audit/`). `~` is expanded by the consumer.
    pub workspace: PathBuf,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_LISTEN_PORT),
            allow_remote: false,
            workspace: PathBuf::from("~/.secure-web"),
        }
    }
}

/// `fetch:` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct FetchConfig {
    /// `User-Agent` header.
    pub user_agent: String,
    /// TCP/TLS connect timeout.
    #[serde(with = "duration_serde")]
    pub connect_timeout: Duration,
    /// Whole-request timeout.
    #[serde(with = "duration_serde")]
    pub request_timeout: Duration,
    /// Maximum redirect hops.
    pub max_redirects: u32,
    /// Permit `https` → `http` redirects.
    pub allow_redirect_downgrade: bool,
    /// Maximum decompressed page size in bytes.
    #[serde(with = "size_serde")]
    pub max_page_bytes: u64,
    /// Maximum JSON response size in bytes.
    #[serde(with = "size_serde")]
    pub max_json_bytes: u64,
    /// Concurrent requests per host.
    pub per_host_concurrency: u32,
    /// Minimum delay between requests to one host.
    #[serde(with = "duration_serde")]
    pub min_delay_per_host: Duration,
    /// Honour `Retry-After`.
    pub respect_retry_after: bool,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            user_agent: "SecureWeb/0.1 (+https://github.com/UnityInFlow/secure-web)".to_owned(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(20),
            max_redirects: 5,
            allow_redirect_downgrade: false,
            max_page_bytes: 5 * MB,
            max_json_bytes: MB,
            per_host_concurrency: 4,
            min_delay_per_host: Duration::ZERO,
            respect_retry_after: true,
        }
    }
}

/// `extract:` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtractConfig {
    /// Maximum `security_text` size in bytes; larger pages are `CONTENT_TOO_LARGE`.
    #[serde(with = "size_serde")]
    pub max_security_text_bytes: u64,
    /// Maximum links collected per page.
    pub max_links_per_page: u32,
    /// Maximum display (Markdown) size in bytes.
    #[serde(with = "size_serde")]
    pub max_display_bytes: u64,
}

impl Default for ExtractConfig {
    fn default() -> Self {
        Self {
            max_security_text_bytes: 2 * MB,
            max_links_per_page: 2000,
            max_display_bytes: MB,
        }
    }
}

/// Crawl scope (contract enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CrawlScope {
    /// Only the root URL's origin.
    SameOrigin,
    /// Only hosts listed in `allowedHosts`.
    Allowlist,
}

/// `crawl:` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct CrawlConfig {
    /// Maximum link depth (hard max [`MAX_CRAWL_DEPTH`]).
    pub max_depth: u32,
    /// Maximum pages fetched (hard max [`MAX_CRAWL_PAGES`]).
    pub max_pages: u32,
    /// Maximum total bytes fetched.
    #[serde(with = "size_serde")]
    pub max_total_bytes: u64,
    /// Maximum crawl duration.
    #[serde(with = "duration_serde")]
    pub max_duration: Duration,
    /// Global fetch concurrency.
    pub concurrency: u32,
    /// Maximum queued frontier entries.
    pub max_frontier: u32,
    /// Crawl scope.
    pub scope: CrawlScope,
    /// Hosts allowed when `scope = ALLOWLIST`.
    pub allowed_hosts: Vec<String>,
    /// Query parameters removed during canonicalization.
    pub strip_query_params: Vec<String>,
    /// robots.txt handling (v0.2).
    pub robots: RobotsConfig,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_depth: 2,
            max_pages: 100,
            max_total_bytes: 100 * MB,
            max_duration: Duration::from_secs(120),
            concurrency: 8,
            max_frontier: 10_000,
            scope: CrawlScope::SameOrigin,
            allowed_hosts: Vec::new(),
            strip_query_params: [
                "utm_source",
                "utm_medium",
                "utm_campaign",
                "utm_term",
                "utm_content",
                "fbclid",
                "gclid",
            ]
            .map(String::from)
            .to_vec(),
            robots: RobotsConfig::default(),
        }
    }
}

/// `crawl.robots:` section (v0.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct RobotsConfig {
    /// Honour robots.txt.
    pub enabled: bool,
    /// robots.txt cache lifetime.
    #[serde(with = "duration_serde")]
    pub cache_ttl: Duration,
}

impl Default for RobotsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_ttl: Duration::from_secs(3600),
        }
    }
}

/// `security:` section. Hashed into [`Config::policy_version`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityConfig {
    /// Injection scanner subprocess.
    pub scanner: ScannerConfig,
    /// Severity → action mapping.
    pub injection: InjectionPolicyConfig,
    /// What happens to `WARN` documents.
    pub warn_handling: WarnHandling,
    /// Network (SSRF) protections.
    pub network: NetworkConfig,
}

impl SecurityConfig {
    /// First 12 hex characters of SHA-256 over the canonical JSON (sorted keys, no whitespace,
    /// normalized durations) of this block. [`Config::policy_version`] delegates here so the
    /// policy engine, which only sees this block, stamps the same value.
    pub fn policy_version(&self) -> Result<String, ConfigError> {
        let value =
            serde_json::to_value(self).map_err(|err| ConfigError::Serialize(err.to_string()))?;
        let canonical = serde_json::to_string(&canonicalize_json(value))
            .map_err(|err| ConfigError::Serialize(err.to_string()))?;
        let mut version = hex::encode(Sha256::digest(canonical.as_bytes()));
        version.truncate(POLICY_VERSION_LEN);
        Ok(version)
    }
}

/// `security.scanner:` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ScannerConfig {
    /// Executable name (resolved on `PATH`) or absolute path.
    pub executable: String,
    /// Per-scan timeout; exceeding it blocks the page.
    #[serde(with = "duration_serde")]
    pub timeout: Duration,
    /// Must be `block` ([`SCANNER_FAILURE_POLICY_BLOCK`]); anything else is rejected by
    /// [`Config::validate`]. Kept as a string so a weakening value produces a validation error
    /// naming this key rather than a generic parse error.
    pub failure_policy: String,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            executable: "injection-scanner".to_owned(),
            timeout: Duration::from_secs(2),
            failure_policy: SCANNER_FAILURE_POLICY_BLOCK.to_owned(),
        }
    }
}

/// Action taken for findings of one severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InjectionAction {
    /// Block the page.
    Block,
    /// Store the page flagged `WARN`.
    Warn,
    /// Accept the page as `SAFE`.
    Allow,
}

/// `security.injection:` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct InjectionPolicyConfig {
    /// Action for `CRITICAL` findings (must be `block`).
    pub critical: InjectionAction,
    /// Action for `HIGH` findings (must be `block`).
    pub high: InjectionAction,
    /// Action for `MEDIUM` findings.
    pub medium: InjectionAction,
    /// Action for `LOW` findings.
    pub low: InjectionAction,
}

impl Default for InjectionPolicyConfig {
    fn default() -> Self {
        Self {
            critical: InjectionAction::Block,
            high: InjectionAction::Block,
            medium: InjectionAction::Warn,
            low: InjectionAction::Allow,
        }
    }
}

/// `security.warnHandling`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WarnHandling {
    /// Store `WARN` documents in the corpus, flagged.
    #[default]
    Store,
    /// Keep `WARN` documents out of the agent corpus.
    Quarantine,
}

/// `security.network:` section. The booleans cannot be switched off in v0.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkConfig {
    /// Block private, loopback and reserved destinations (must be `true`).
    pub block_private_addresses: bool,
    /// Block link-local destinations, including cloud metadata (must be `true`).
    pub block_link_local: bool,
    /// Re-validate every redirect hop (must be `true`).
    pub validate_redirects: bool,
    /// Additional blocked CIDR ranges.
    pub extra_blocked_cidrs: Vec<String>,
    /// Additional blocked host names.
    pub extra_blocked_hosts: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            block_private_addresses: true,
            block_link_local: true,
            validate_redirects: true,
            extra_blocked_cidrs: Vec::new(),
            extra_blocked_hosts: Vec::new(),
        }
    }
}

/// `search.provider` (v0.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchProviderKind {
    /// No search provider (v0.1).
    #[default]
    #[serde(rename = "none")]
    Disabled,
    /// Brave Search API.
    Brave,
    /// SearXNG instance.
    Searxng,
}

/// `search:` section (v0.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchConfig {
    /// Provider.
    pub provider: SearchProviderKind,
    /// Maximum results per query.
    pub max_results: u32,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            provider: SearchProviderKind::Disabled,
            max_results: 10,
        }
    }
}

/// Log verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// `trace`.
    Trace,
    /// `debug`.
    Debug,
    /// `info`.
    #[default]
    Info,
    /// `warn`.
    Warn,
    /// `error`.
    Error,
}

impl LogLevel {
    /// Lowercase name, usable as a `tracing` filter directive.
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

/// `debug:` section.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct DebugConfig {
    /// Keep raw response bodies under `private-audit/` (never in the agent corpus).
    pub retain_raw: bool,
    /// Default log level.
    pub log_level: LogLevel,
}

// -------------------------------------------------------------------------------------------------
// Loading
// -------------------------------------------------------------------------------------------------

impl Config {
    /// Load, layer and validate the config the way the CLI does: file search order
    /// (`explicit`, `./secure-web.yaml`, `~/.secure-web/config.yaml`, defaults) and the process
    /// environment.
    pub fn load(explicit: Option<&Path>) -> Result<LoadedConfig, ConfigError> {
        let cwd =
            std::env::current_dir().map_err(|err| ConfigError::Environment(err.to_string()))?;
        let home = home_dir();
        let env = process_env_overrides()?;
        Self::load_from(explicit, &cwd, home.as_deref(), env)
    }

    /// [`Config::load`] with the search roots and environment supplied by the caller.
    pub fn load_from<I, K, V>(
        explicit: Option<&Path>,
        cwd: &Path,
        home: Option<&Path>,
        env: I,
    ) -> Result<LoadedConfig, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let path = match explicit {
            Some(path) => Some(path.to_path_buf()),
            None => [
                Some(cwd.join(CWD_CONFIG_FILE)),
                home.map(|home| home.join(HOME_CONFIG_FILE)),
            ]
            .into_iter()
            .flatten()
            .find(|candidate| candidate.is_file()),
        };
        let (text, source) = match path {
            Some(path) => {
                let text = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
                    path: path.clone(),
                    source,
                })?;
                (Some(text), ConfigSource::File(path))
            }
            None => (None, ConfigSource::Defaults),
        };
        let origin = source.to_string();
        let config = Self::layer(text.as_deref(), &origin, env)?;
        let warnings = config.validate()?;
        Ok(LoadedConfig {
            config,
            source,
            warnings,
        })
    }

    /// Layer defaults ← `file_yaml` ← environment overrides. Does **not** validate; call
    /// [`Config::validate`] before using the result.
    pub fn load_layered<I, K, V>(file_yaml: Option<&str>, env: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        Self::layer(file_yaml, "config file", env)
    }

    fn layer<I, K, V>(file_yaml: Option<&str>, origin: &str, env: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut root = match file_yaml {
            Some(text) => {
                let value: Value =
                    serde_yaml::from_str(text).map_err(|err| ConfigError::Parse {
                        origin: origin.to_owned(),
                        message: err.to_string(),
                    })?;
                match value {
                    Value::Null => Value::Mapping(Mapping::new()),
                    Value::Mapping(_) => value,
                    _ => {
                        return Err(ConfigError::Parse {
                            origin: origin.to_owned(),
                            message: "top level must be a mapping".to_owned(),
                        })
                    }
                }
            }
            None => Value::Mapping(Mapping::new()),
        };
        let mut overrides: Vec<(String, String)> = env
            .into_iter()
            .filter(|(key, _)| key.as_ref().starts_with(ENV_PREFIX))
            .map(|(key, value)| (key.as_ref().to_owned(), value.as_ref().to_owned()))
            .collect();
        overrides.sort();
        let had_overrides = !overrides.is_empty();
        for (var, raw) in overrides {
            apply_env_override(&mut root, &var, &raw)?;
        }
        serde_yaml::from_value(root).map_err(|err| ConfigError::Parse {
            origin: if had_overrides {
                format!("{origin} + environment overrides")
            } else {
                origin.to_owned()
            },
            message: err.to_string(),
        })
    }

    /// Enforce every rule in `docs/contracts/config.md`. Weakening settings (T16) are errors and
    /// are all reported together; a missing scanner is only a warning because every scan then
    /// fails closed.
    pub fn validate(&self) -> Result<Vec<ConfigWarning>, ConfigError> {
        let mut violations = Vec::new();
        let mut reject = |key: &str, message: String| {
            violations.push(ConfigViolation {
                key: key.to_owned(),
                message,
            });
        };

        let security = &self.security;
        if security.scanner.failure_policy != SCANNER_FAILURE_POLICY_BLOCK {
            reject(
                "security.scanner.failurePolicy",
                format!(
                    "must be \"{SCANNER_FAILURE_POLICY_BLOCK}\" (scanner errors fail closed), got {:?}",
                    security.scanner.failure_policy
                ),
            );
        }
        if security.injection.critical != InjectionAction::Block {
            reject(
                "security.injection.critical",
                "must be \"block\"; CRITICAL findings always block".to_owned(),
            );
        }
        if security.injection.high != InjectionAction::Block {
            reject(
                "security.injection.high",
                "must be \"block\"; HIGH findings always block".to_owned(),
            );
        }
        let network_flags = [
            (
                "security.network.blockPrivateAddresses",
                security.network.block_private_addresses,
            ),
            (
                "security.network.blockLinkLocal",
                security.network.block_link_local,
            ),
            (
                "security.network.validateRedirects",
                security.network.validate_redirects,
            ),
        ];
        for (key, enabled) in network_flags {
            if !enabled {
                reject(key, "cannot be disabled in v0.1".to_owned());
            }
        }
        if self.crawl.max_depth > MAX_CRAWL_DEPTH {
            reject(
                "crawl.maxDepth",
                format!(
                    "{} exceeds the hard maximum {MAX_CRAWL_DEPTH}",
                    self.crawl.max_depth
                ),
            );
        }
        if self.crawl.max_pages > MAX_CRAWL_PAGES {
            reject(
                "crawl.maxPages",
                format!(
                    "{} exceeds the hard maximum {MAX_CRAWL_PAGES}",
                    self.crawl.max_pages
                ),
            );
        }
        // A zero budget cannot be honoured without silently changing it (invariant 5).
        let zero_budgets = [
            ("crawl.maxPages", self.crawl.max_pages == 0),
            ("crawl.maxDuration", self.crawl.max_duration.is_zero()),
            ("crawl.concurrency", self.crawl.concurrency == 0),
            ("crawl.maxFrontier", self.crawl.max_frontier == 0),
            ("crawl.maxTotalBytes", self.crawl.max_total_bytes == 0),
        ];
        for (key, is_zero) in zero_budgets {
            if is_zero {
                reject(key, "must be greater than zero".to_owned());
            }
        }
        for entry in &security.network.extra_blocked_cidrs {
            if let Err(err) = crate::network::parse_blocked_cidr(entry) {
                reject("security.network.extraBlockedCidrs", err.to_string());
            }
        }
        for entry in &security.network.extra_blocked_hosts {
            if let Err(err) = crate::network::normalize_blocked_host(entry) {
                reject("security.network.extraBlockedHosts", err.to_string());
            }
        }
        // `to_canonical`: `::ffff:0.0.0.0` binds as the IPv6 wildcard.
        if self.server.listen.ip().to_canonical().is_unspecified() {
            reject(
                "server.listen",
                format!(
                    "{} is a wildcard address; listen on one interface address (the HTTP transport accepts only that address as a remote Host)",
                    self.server.listen
                ),
            );
        } else if !self.server.listen.ip().is_loopback() && !self.server.allow_remote {
            reject(
                "server.listen",
                format!(
                    "{} is not a loopback address; set server.allowRemote: true to expose the server",
                    self.server.listen
                ),
            );
        }

        if !violations.is_empty() {
            return Err(ConfigError::Invalid { violations });
        }

        let mut warnings = Vec::new();
        if !executable_exists(&security.scanner.executable, std::env::var_os("PATH")) {
            warnings.push(ConfigWarning::ScannerNotFound {
                executable: security.scanner.executable.clone(),
            });
        }
        Ok(warnings)
    }

    /// First 12 hex characters of SHA-256 over the canonical JSON (sorted keys, no whitespace,
    /// normalized durations) of the `security` block.
    pub fn policy_version(&self) -> Result<String, ConfigError> {
        self.security.policy_version()
    }

    /// The effective config as YAML (`secure-web config --effective`). Sizes are rendered as
    /// plain byte counts, durations in `humantime` form. v0.1 has no secrets to redact.
    pub fn to_effective_yaml(&self) -> Result<String, ConfigError> {
        serde_yaml::to_string(self).map_err(|err| ConfigError::Serialize(err.to_string()))
    }
}

fn canonicalize_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, serde_json::Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            serde_json::Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, canonicalize_json(value)))
                    .collect(),
            )
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(canonicalize_json).collect())
        }
        other => other,
    }
}

/// `SECURE_WEB__*` variables from the process environment. A matching variable with a non-UTF-8
/// value is an error rather than silently ignored.
fn process_env_overrides() -> Result<Vec<(String, String)>, ConfigError> {
    let mut overrides = Vec::new();
    for (key, value) in std::env::vars_os() {
        let Some(key) = key.to_str() else { continue };
        if !key.starts_with(ENV_PREFIX) {
            continue;
        }
        let value = value.into_string().map_err(|_| ConfigError::Env {
            var: key.to_owned(),
            message: "value is not valid UTF-8".to_owned(),
        })?;
        overrides.push((key.to_owned(), value));
    }
    Ok(overrides)
}

fn home_dir() -> Option<PathBuf> {
    ["HOME", "USERPROFILE"]
        .into_iter()
        .filter_map(std::env::var_os)
        .find(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// `MAX_PAGE_BYTES` → `maxPageBytes`.
fn env_segment_to_key(segment: &str) -> String {
    let mut key = String::with_capacity(segment.len());
    let mut upper_next = false;
    for ch in segment.chars() {
        if ch == '_' {
            upper_next = !key.is_empty();
        } else if upper_next {
            key.push(ch.to_ascii_uppercase());
            upper_next = false;
        } else {
            key.push(ch.to_ascii_lowercase());
        }
    }
    key
}

/// Interpret an override value: booleans, numbers and `[a, b]` lists are typed; everything else
/// (including values that would parse as YAML mappings, like `Agent: x`) is a plain string.
fn env_value(raw: &str) -> Value {
    match serde_yaml::from_str::<Value>(raw) {
        Ok(value @ (Value::Bool(_) | Value::Number(_) | Value::Sequence(_))) => value,
        Ok(Value::Null | Value::String(_) | Value::Mapping(_) | Value::Tagged(_)) | Err(_) => {
            Value::String(raw.to_owned())
        }
    }
}

fn apply_env_override(root: &mut Value, var: &str, raw: &str) -> Result<(), ConfigError> {
    let env_error = |message: &str| ConfigError::Env {
        var: var.to_owned(),
        message: message.to_owned(),
    };
    let path = var.strip_prefix(ENV_PREFIX).unwrap_or_default();
    let segments: Vec<&str> = path.split("__").collect();
    if segments
        .iter()
        .any(|segment| segment.is_empty() || !segment.chars().any(|c| c.is_ascii_alphanumeric()))
    {
        return Err(env_error(
            "expected SECURE_WEB__<SECTION>__<KEY> with non-empty segments",
        ));
    }
    let Some((leaf, parents)) = segments.split_last() else {
        return Err(env_error("missing key"));
    };
    let mut node = root;
    for segment in parents {
        let Value::Mapping(map) = node else {
            return Err(env_error("parent key is not a section"));
        };
        node = map
            .entry(Value::String(env_segment_to_key(segment)))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
    }
    let Value::Mapping(map) = node else {
        return Err(env_error("parent key is not a section"));
    };
    map.insert(Value::String(env_segment_to_key(leaf)), env_value(raw));
    Ok(())
}

/// `true` when `executable` is an existing file path, or a bare name found in one of `path_var`'s
/// directories.
fn executable_exists(executable: &str, path_var: Option<OsString>) -> bool {
    let candidate = Path::new(executable);
    if executable.is_empty() {
        return false;
    }
    if candidate.is_absolute() || candidate.components().count() > 1 {
        return candidate.is_file();
    }
    let Some(paths) = path_var else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| {
        dir.join(executable).is_file()
            || (cfg!(windows) && dir.join(format!("{executable}.exe")).is_file())
    })
}

// -------------------------------------------------------------------------------------------------
// Serde helpers
// -------------------------------------------------------------------------------------------------

/// Durations as `humantime` strings: `5s`, `250ms`, `2m`, `1h`.
mod duration_serde {
    use std::time::Duration;

    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&humantime::format_duration(*value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let text = String::deserialize(deserializer)?;
        humantime::parse_duration(text.trim()).map_err(|err| {
            D::Error::custom(format!(
                "invalid duration {text:?} ({err}); use e.g. 5s, 250ms, 2m"
            ))
        })
    }
}

/// Sizes as plain byte counts or strings: `5MB`, `512KB` (decimal) and `1MiB` (binary).
mod size_serde {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Bytes(u64),
        Text(String),
    }

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(*value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let invalid = |shown: &str| {
            D::Error::custom(format!(
                "invalid size {shown}; use a byte count or e.g. 5MB, 512KB, 1MiB"
            ))
        };
        match Raw::deserialize(deserializer).map_err(|_| invalid("value"))? {
            Raw::Bytes(bytes) => Ok(bytes),
            Raw::Text(text) => text
                .trim()
                .parse::<bytesize::ByteSize>()
                .map(|size| size.as_u64())
                .map_err(|_| invalid(&format!("{text:?}"))),
        }
    }
}
