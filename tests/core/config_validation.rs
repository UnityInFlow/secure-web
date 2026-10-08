//! Configuration contract (`docs/contracts/config.md`) and threat T16 (config weakening).
//!
//! Every rule that would switch off a security control must be a hard startup error, whether the
//! weakening arrives through the YAML file or through a `SECURE_WEB__…` environment override.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use secure_web_core::config::{
    Config, ConfigError, ConfigSource, ConfigWarning, CrawlScope, InjectionAction,
};

const NO_ENV: [(&str, &str); 0] = [];

fn repo_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn parse(yaml: &str) -> Config {
    Config::load_layered(Some(yaml), NO_ENV).unwrap()
}

fn parse_err(yaml: &str) -> ConfigError {
    Config::load_layered(Some(yaml), NO_ENV).unwrap_err()
}

fn with_env<'a>(yaml: Option<&str>, env: impl IntoIterator<Item = (&'a str, &'a str)>) -> Config {
    Config::load_layered(yaml, env).unwrap()
}

/// Keys named by a validation failure.
fn violation_keys(config: &Config) -> Vec<String> {
    match config.validate() {
        Err(ConfigError::Invalid { violations }) => violations.into_iter().map(|v| v.key).collect(),
        Err(other) => panic!("expected ConfigError::Invalid, got {other:?}"),
        Ok(_) => Vec::new(),
    }
}

fn assert_rejected(yaml: &str, key: &str) {
    let keys = violation_keys(&parse(yaml));
    assert!(
        keys.iter().any(|k| k == key),
        "config was not rejected on {key}: {yaml}\nviolations: {keys:?}"
    );
}

fn assert_accepted(yaml: &str) {
    let keys = violation_keys(&parse(yaml));
    assert!(keys.is_empty(), "unexpected violations {keys:?} for {yaml}");
}

// ---------------------------------------------------------------------------------------------
// Defaults and shipped examples
// ---------------------------------------------------------------------------------------------

#[test]
fn defaults_are_valid() {
    Config::default().validate().unwrap();
}

#[test]
fn defaults_match_the_contract() {
    let c = Config::default();
    assert_eq!(c.server.listen.to_string(), "127.0.0.1:8787");
    assert!(!c.server.allow_remote);
    assert_eq!(c.server.workspace, PathBuf::from("~/.secure-web"));
    assert_eq!(c.fetch.connect_timeout, Duration::from_secs(5));
    assert_eq!(c.fetch.request_timeout, Duration::from_secs(20));
    assert_eq!(c.fetch.max_redirects, 5);
    assert!(!c.fetch.allow_redirect_downgrade);
    assert_eq!(c.fetch.max_page_bytes, 5_000_000);
    assert_eq!(c.fetch.max_json_bytes, 1_000_000);
    assert_eq!(c.extract.max_security_text_bytes, 2_000_000);
    assert_eq!(c.crawl.max_depth, 2);
    assert_eq!(c.crawl.max_pages, 100);
    assert_eq!(c.crawl.max_total_bytes, 100_000_000);
    assert_eq!(c.crawl.max_duration, Duration::from_secs(120));
    assert_eq!(c.crawl.scope, CrawlScope::SameOrigin);
    assert_eq!(c.crawl.max_frontier, 10_000);
    assert_eq!(c.security.scanner.executable, "injection-scanner");
    assert_eq!(c.security.scanner.timeout, Duration::from_secs(2));
    assert_eq!(c.security.scanner.failure_policy, "block");
    assert_eq!(c.security.injection.critical, InjectionAction::Block);
    assert_eq!(c.security.injection.high, InjectionAction::Block);
    assert_eq!(c.security.injection.medium, InjectionAction::Warn);
    assert_eq!(c.security.injection.low, InjectionAction::Allow);
    assert!(c.security.network.block_private_addresses);
    assert!(c.security.network.block_link_local);
    assert!(c.security.network.validate_redirects);
    assert!(!c.debug.retain_raw);
}

#[test]
fn empty_file_yields_defaults() {
    assert_eq!(parse(""), Config::default());
    assert_eq!(parse("{}"), Config::default());
    assert_eq!(parse("# only a comment\n"), Config::default());
}

#[test]
fn example_yaml_loads_validates_and_equals_defaults() {
    let yaml = fs::read_to_string(repo_file("config/secure-web.example.yaml")).unwrap();
    let config = parse(&yaml);
    config.validate().unwrap();
    assert_eq!(config, Config::default());
}

/// The YAML block in the contract document is the documented default; keep the code in sync.
#[test]
fn contract_document_yaml_equals_defaults() {
    let doc = fs::read_to_string(repo_file("docs/contracts/config.md")).unwrap();
    let start = doc.find("```yaml\n").unwrap() + "```yaml\n".len();
    let end = start + doc[start..].find("```").unwrap();
    assert_eq!(parse(&doc[start..end]), Config::default());
}

#[test]
fn effective_yaml_round_trips() {
    let config =
        parse("fetch:\n  maxPageBytes: 3MB\n  minDelayPerHost: 250ms\ncrawl:\n  maxDuration: 2m\n");
    let rendered = config.to_effective_yaml().unwrap();
    assert_eq!(parse(&rendered), config);
    assert!(rendered.contains("maxPageBytes: 3000000"), "{rendered}");
    assert!(rendered.contains("minDelayPerHost: 250ms"), "{rendered}");
    assert!(rendered.contains("maxDuration: 2m"), "{rendered}");
}

// ---------------------------------------------------------------------------------------------
// deny_unknown_fields
// ---------------------------------------------------------------------------------------------

#[test]
fn unknown_keys_are_hard_errors() {
    let cases = [
        "bogus: 1\n",
        "fetch:\n  maxPageByte: 5MB\n",
        "fetch:\n  max_page_bytes: 5MB\n",
        "security:\n  network:\n    blockPrivate: true\n",
        "security:\n  scanner:\n    skipScan: true\n",
        "crawl:\n  robots:\n    ignore: true\n",
    ];
    for yaml in cases {
        let err = parse_err(yaml);
        assert!(matches!(err, ConfigError::Parse { .. }), "{yaml}: {err:?}");
        assert!(err.to_string().contains("unknown field"), "{yaml}: {err}");
    }
}

#[test]
fn malformed_values_are_errors() {
    let cases = [
        "fetch:\n  connectTimeout: 5 parsecs\n",
        "fetch:\n  connectTimeout: 5\n",
        "fetch:\n  maxPageBytes: lots\n",
        "fetch:\n  maxPageBytes: -1\n",
        "crawl:\n  scope: same-origin\n",
        "security:\n  injection:\n    critical: panic\n",
        "server:\n  listen: not-an-address\n",
        "fetch: [1, 2]\n",
        "- just\n- a list\n",
        "fetch:\n  maxRedirects: [\n",
    ];
    for yaml in cases {
        assert!(
            Config::load_layered(Some(yaml), NO_ENV).is_err(),
            "accepted {yaml}"
        );
    }
}

#[test]
fn durations_and_sizes_parse_documented_forms() {
    let c = parse(
        "fetch:\n  connectTimeout: 250ms\n  requestTimeout: 2m\n  maxPageBytes: 512KB\n  maxJsonBytes: 1024\n\
         extract:\n  maxDisplayBytes: 1MiB\n",
    );
    assert_eq!(c.fetch.connect_timeout, Duration::from_millis(250));
    assert_eq!(c.fetch.request_timeout, Duration::from_secs(120));
    assert_eq!(c.fetch.max_page_bytes, 512_000);
    assert_eq!(c.fetch.max_json_bytes, 1024);
    assert_eq!(c.extract.max_display_bytes, 1_048_576);
}

// ---------------------------------------------------------------------------------------------
// T16: weakening rules
// ---------------------------------------------------------------------------------------------

#[test]
fn t16_scanner_failure_policy_must_be_block() {
    for value in ["allow", "warn", "Block", "\"\"", "skip"] {
        assert_rejected(
            &format!("security:\n  scanner:\n    failurePolicy: {value}\n"),
            "security.scanner.failurePolicy",
        );
    }
    assert_accepted("security:\n  scanner:\n    failurePolicy: block\n");
}

#[test]
fn t16_network_protections_cannot_be_disabled() {
    for key in [
        "blockPrivateAddresses",
        "blockLinkLocal",
        "validateRedirects",
    ] {
        assert_rejected(
            &format!("security:\n  network:\n    {key}: false\n"),
            &format!("security.network.{key}"),
        );
        assert_accepted(&format!("security:\n  network:\n    {key}: true\n"));
    }
}

#[test]
fn t16_blocking_severities_cannot_be_relaxed() {
    for severity in ["critical", "high"] {
        for action in ["warn", "allow"] {
            assert_rejected(
                &format!("security:\n  injection:\n    {severity}: {action}\n"),
                &format!("security.injection.{severity}"),
            );
        }
    }
    // Tightening is always allowed.
    assert_accepted("security:\n  injection:\n    medium: block\n    low: warn\n");
}

#[test]
fn t16_crawl_hard_maxima() {
    assert_rejected("crawl:\n  maxDepth: 6\n", "crawl.maxDepth");
    assert_rejected("crawl:\n  maxDepth: 4294967295\n", "crawl.maxDepth");
    assert_rejected("crawl:\n  maxPages: 1001\n", "crawl.maxPages");
    assert_accepted("crawl:\n  maxDepth: 5\n  maxPages: 1000\n");
}

/// A zero crawl budget was silently raised to 1 (pages, concurrency, frontier) or still let the
/// root fetch start (duration); a budget is either honoured exactly or refused (invariant 5).
#[test]
fn t7_zero_crawl_budgets_are_rejected() {
    for (yaml, key) in [
        ("crawl:\n  maxPages: 0\n", "crawl.maxPages"),
        ("crawl:\n  maxDuration: 0s\n", "crawl.maxDuration"),
        ("crawl:\n  concurrency: 0\n", "crawl.concurrency"),
        ("crawl:\n  maxFrontier: 0\n", "crawl.maxFrontier"),
        ("crawl:\n  maxTotalBytes: 0\n", "crawl.maxTotalBytes"),
    ] {
        assert_rejected(yaml, key);
    }
    assert_accepted("crawl:\n  maxDepth: 0\n");
    assert_accepted(
        "crawl:\n  maxPages: 1\n  maxDuration: 1ms\n  concurrency: 1\n  maxFrontier: 1\n  maxTotalBytes: 1\n",
    );
}

#[test]
fn t16_non_loopback_listen_requires_allow_remote() {
    for listen in ["192.168.1.10:8787", "\"[::ffff:127.0.0.1]:8787\""] {
        assert_rejected(&format!("server:\n  listen: {listen}\n"), "server.listen");
        assert_accepted(&format!(
            "server:\n  listen: {listen}\n  allowRemote: true\n"
        ));
    }
    assert_accepted("server:\n  listen: 127.0.0.1:9000\n");
    assert_accepted("server:\n  listen: 127.8.9.10:9000\n");
    assert_accepted("server:\n  listen: \"[::1]:9000\"\n");
}

/// The HTTP transport accepts only the listen IP as an extra `Host`, so a wildcard listen
/// address cannot serve remote clients: it is refused even with `allowRemote` (ADR-016).
#[test]
fn a_wildcard_listen_is_rejected_even_with_allow_remote() {
    for listen in ["0.0.0.0:8787", "\"[::]:8787\"", "\"[::ffff:0.0.0.0]:8787\""] {
        assert_rejected(&format!("server:\n  listen: {listen}\n"), "server.listen");
        assert_rejected(
            &format!("server:\n  listen: {listen}\n  allowRemote: true\n"),
            "server.listen",
        );
    }
}

#[test]
fn invalid_denylist_entries_are_config_errors() {
    for cidr in ["10.0.0.0", "10.0.0.0/33", "not-a-cidr", "\"\""] {
        assert_rejected(
            &format!("security:\n  network:\n    extraBlockedCidrs: [{cidr}]\n"),
            "security.network.extraBlockedCidrs",
        );
    }
    for host in [
        "\"\"",
        "10.0.0.1",
        "\"*.example.com\"",
        ".example.com",
        "example.com:80",
    ] {
        assert_rejected(
            &format!("security:\n  network:\n    extraBlockedHosts: [{host}]\n"),
            "security.network.extraBlockedHosts",
        );
    }
    assert_accepted(
        "security:\n  network:\n    extraBlockedCidrs: [203.0.113.0/24, \"2001:db8::/32\"]\n    \
         extraBlockedHosts: [internal.example, Bücher.example.]\n",
    );
    // Reported together with every other violation.
    let keys = violation_keys(&parse(
        "security:\n  network:\n    extraBlockedCidrs: [x]\n    extraBlockedHosts: [\"\"]\n\
         crawl:\n  maxDepth: 9\n",
    ));
    assert_eq!(
        keys,
        [
            "crawl.maxDepth",
            "security.network.extraBlockedCidrs",
            "security.network.extraBlockedHosts"
        ]
    );
}

#[test]
fn t16_all_violations_are_reported_together() {
    let keys = violation_keys(&parse(
        "security:\n  scanner:\n    failurePolicy: allow\n  network:\n    blockLinkLocal: false\n\
         crawl:\n  maxPages: 5000\n",
    ));
    assert_eq!(
        keys,
        [
            "security.scanner.failurePolicy",
            "security.network.blockLinkLocal",
            "crawl.maxPages"
        ]
    );
}

#[test]
fn t16_weakening_through_env_is_rejected() {
    let cases = [
        (
            "SECURE_WEB__SECURITY__NETWORK__BLOCK_PRIVATE_ADDRESSES",
            "false",
            "security.network.blockPrivateAddresses",
        ),
        (
            "SECURE_WEB__SECURITY__NETWORK__VALIDATE_REDIRECTS",
            "false",
            "security.network.validateRedirects",
        ),
        (
            "SECURE_WEB__SECURITY__SCANNER__FAILURE_POLICY",
            "allow",
            "security.scanner.failurePolicy",
        ),
        (
            "SECURE_WEB__SECURITY__INJECTION__CRITICAL",
            "allow",
            "security.injection.critical",
        ),
        ("SECURE_WEB__CRAWL__MAX_DEPTH", "9", "crawl.maxDepth"),
        (
            "SECURE_WEB__SERVER__LISTEN",
            "0.0.0.0:8787",
            "server.listen",
        ),
    ];
    for (var, value, key) in cases {
        let keys = violation_keys(&with_env(None, [(var, value)]));
        assert!(
            keys.iter().any(|k| k == key),
            "{var}={value} not rejected: {keys:?}"
        );
    }
}

#[test]
fn missing_scanner_is_a_warning_not_an_error() {
    let config = parse("security:\n  scanner:\n    executable: definitely-not-a-scanner-3f9a1c\n");
    let warnings = config.validate().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| matches!(w, ConfigWarning::ScannerNotFound { .. })),
        "{warnings:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Environment overrides
// ---------------------------------------------------------------------------------------------

#[test]
fn env_override_sets_nested_values() {
    let c = with_env(
        None,
        [
            ("SECURE_WEB__FETCH__MAX_PAGE_BYTES", "2MB"),
            ("SECURE_WEB__SECURITY__SCANNER__TIMEOUT", "3s"),
            ("SECURE_WEB__CRAWL__SCOPE", "ALLOWLIST"),
            (
                "SECURE_WEB__CRAWL__ALLOWED_HOSTS",
                "[docs.example.test, api.example.test]",
            ),
            ("SECURE_WEB__FETCH__USER_AGENT", "Agent: with colon"),
            ("SECURE_WEB__DEBUG__RETAIN_RAW", "true"),
        ],
    );
    assert_eq!(c.fetch.max_page_bytes, 2_000_000);
    assert_eq!(c.security.scanner.timeout, Duration::from_secs(3));
    assert_eq!(c.crawl.scope, CrawlScope::Allowlist);
    assert_eq!(
        c.crawl.allowed_hosts,
        ["docs.example.test", "api.example.test"]
    );
    assert_eq!(c.fetch.user_agent, "Agent: with colon");
    assert!(c.debug.retain_raw);
}

#[test]
fn env_override_beats_the_file() {
    let c = with_env(
        Some("fetch:\n  maxPageBytes: 4MB\n  maxRedirects: 3\n"),
        [("SECURE_WEB__FETCH__MAX_PAGE_BYTES", "1MB")],
    );
    assert_eq!(c.fetch.max_page_bytes, 1_000_000);
    assert_eq!(
        c.fetch.max_redirects, 3,
        "file value not overridden must survive"
    );
}

#[test]
fn unrelated_env_is_ignored() {
    let c = with_env(
        None,
        [
            ("PATH", "/usr/bin"),
            ("SECURE_WEB", "x"),
            ("SECURE_WEBX__FETCH__MAX_REDIRECTS", "1"),
            ("SECURE_WEB_FETCH__MAX_REDIRECTS", "1"),
        ],
    );
    assert_eq!(c, Config::default());
}

#[test]
fn unknown_or_malformed_env_keys_are_errors() {
    let cases = [
        ("SECURE_WEB__FETCH__MAX_PAGE_BYTE", "1MB"),
        ("SECURE_WEB__BOGUS", "1"),
        ("SECURE_WEB__", "1"),
        ("SECURE_WEB__FETCH____MAX_REDIRECTS", "1"),
        ("SECURE_WEB__FETCH__MAX_REDIRECTS", "many"),
    ];
    for (var, value) in cases {
        assert!(
            Config::load_layered(None, [(var, value)]).is_err(),
            "accepted {var}={value}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// policyVersion
// ---------------------------------------------------------------------------------------------

#[test]
fn policy_version_is_twelve_lowercase_hex() {
    let version = Config::default().policy_version().unwrap();
    assert_eq!(version.len(), 12);
    assert!(
        version
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{version}"
    );
}

#[test]
fn policy_version_is_stable_across_key_order() {
    let a = parse(
        "security:\n  scanner:\n    executable: /opt/scanner\n    timeout: 3s\n  injection:\n    medium: block\n    low: warn\n  warnHandling: quarantine\n",
    );
    let b = parse(
        "security:\n  warnHandling: quarantine\n  injection:\n    low: warn\n    medium: block\n  scanner:\n    timeout: 3000ms\n    executable: /opt/scanner\n",
    );
    assert_eq!(a.policy_version().unwrap(), b.policy_version().unwrap());
    assert_ne!(
        a.policy_version().unwrap(),
        Config::default().policy_version().unwrap()
    );
}

#[test]
fn policy_version_tracks_only_the_security_block() {
    let base = Config::default().policy_version().unwrap();
    let non_security = parse("fetch:\n  maxPageBytes: 1MB\ncrawl:\n  maxPages: 10\n");
    assert_eq!(non_security.policy_version().unwrap(), base);
    let security = parse("security:\n  injection:\n    medium: block\n");
    assert_ne!(security.policy_version().unwrap(), base);
}

// ---------------------------------------------------------------------------------------------
// File search order: --config, ./secure-web.yaml, ~/.secure-web/config.yaml, defaults
// ---------------------------------------------------------------------------------------------

struct Dirs {
    _root: tempfile::TempDir,
    cwd: PathBuf,
    home: PathBuf,
}

fn dirs() -> Dirs {
    let root = tempfile::tempdir().unwrap();
    let cwd = root.path().join("cwd");
    let home = root.path().join("home");
    fs::create_dir_all(&cwd).unwrap();
    fs::create_dir_all(home.join(".secure-web")).unwrap();
    Dirs {
        _root: root,
        cwd,
        home,
    }
}

#[test]
fn search_order_prefers_explicit_then_cwd_then_home_then_defaults() {
    let d = dirs();
    let explicit = d.cwd.join("explicit.yaml");
    fs::write(&explicit, "fetch:\n  maxRedirects: 1\n").unwrap();
    fs::write(d.cwd.join("secure-web.yaml"), "fetch:\n  maxRedirects: 2\n").unwrap();
    fs::write(
        d.home.join(".secure-web/config.yaml"),
        "fetch:\n  maxRedirects: 3\n",
    )
    .unwrap();

    let loaded = Config::load_from(Some(&explicit), &d.cwd, Some(&d.home), NO_ENV).unwrap();
    assert_eq!(loaded.config.fetch.max_redirects, 1);
    assert_eq!(loaded.source, ConfigSource::File(explicit.clone()));

    let loaded = Config::load_from(None, &d.cwd, Some(&d.home), NO_ENV).unwrap();
    assert_eq!(loaded.config.fetch.max_redirects, 2);

    fs::remove_file(d.cwd.join("secure-web.yaml")).unwrap();
    let loaded = Config::load_from(None, &d.cwd, Some(&d.home), NO_ENV).unwrap();
    assert_eq!(loaded.config.fetch.max_redirects, 3);

    fs::remove_file(d.home.join(".secure-web/config.yaml")).unwrap();
    let loaded = Config::load_from(None, &d.cwd, Some(&d.home), NO_ENV).unwrap();
    assert_eq!(loaded.source, ConfigSource::Defaults);
    assert_eq!(loaded.config, Config::default());
}

#[test]
fn missing_explicit_config_is_an_error() {
    let d = dirs();
    let err = Config::load_from(
        Some(&d.cwd.join("nope.yaml")),
        &d.cwd,
        Some(&d.home),
        NO_ENV,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::Read { .. }), "{err:?}");
}

#[test]
fn load_from_validates() {
    let d = dirs();
    fs::write(
        d.cwd.join("secure-web.yaml"),
        "security:\n  network:\n    blockLinkLocal: false\n",
    )
    .unwrap();
    let err = Config::load_from(None, &d.cwd, Some(&d.home), NO_ENV).unwrap_err();
    assert!(matches!(err, ConfigError::Invalid { .. }), "{err:?}");
    let err = Config::load_from(
        None,
        &d.home,
        Some(&d.home),
        [("SECURE_WEB__CRAWL__MAX_PAGES", "2000")],
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::Invalid { .. }), "{err:?}");
}
