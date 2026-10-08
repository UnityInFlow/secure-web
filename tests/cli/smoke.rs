//! CLI skeleton: subcommands, config loading and exit codes (`docs/contracts/mcp-contract.md`).
//!
//! Every invocation runs in an empty temporary directory with `HOME` pointed at it and all
//! `SECURE_WEB__*` variables removed, so a developer's own config can never leak into the result.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::process::{Command, Output};

use secure_web_core::config::{Config, LogLevel};

const SUBCOMMANDS: [&str; 6] = ["serve", "open", "crawl", "find", "inspect", "config"];

struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_secure-web"));
        cmd.args(args)
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("USERPROFILE", self.dir.path());
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SECURE_WEB") {
                cmd.env_remove(key);
            }
        }
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn run_with_env(&self, args: &[&str], key: &str, value: &str) -> Output {
        self.command(args).env(key, value).output().unwrap()
    }

    fn write(&self, name: &str, contents: &str) -> String {
        let path = self.dir.path().join(name);
        fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn help_lists_every_subcommand() {
    let output = Sandbox::new().run(&["--help"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let help = stdout(&output);
    for subcommand in SUBCOMMANDS {
        assert!(
            help.lines()
                .any(|line| line.trim_start().starts_with(subcommand)),
            "--help does not list {subcommand}:\n{help}"
        );
    }
    for flag in ["--config", "--workspace", "--log-level"] {
        assert!(help.contains(flag), "--help does not list {flag}:\n{help}");
    }
}

#[test]
fn version_flag_works() {
    let output = Sandbox::new().run(&["--version"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn unimplemented_subcommands_exit_1_with_not_implemented() {
    let sandbox = Sandbox::new();
    let invocations: [&[&str]; 2] = [
        &["find", "crawl_0123456789ab", "authentication"],
        &["inspect", "crawl_0123456789ab"],
    ];
    for args in invocations {
        let output = sandbox.run(args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("NOT_IMPLEMENTED"),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(stdout(&output).is_empty(), "{args:?}: {}", stdout(&output));
    }
}

/// `crawl` needs no network for these: the guard refuses a loopback root before anything is
/// fetched (the run is `FAILED`, exit 3), and bad arguments never create a run (exit 2).
#[test]
fn crawl_exit_codes_without_network() {
    let sandbox = Sandbox::new();
    let workspace = sandbox.dir.path().join("ws");
    let workspace = workspace.to_string_lossy();
    let output = sandbox.run(&[
        "--workspace",
        &workspace,
        "crawl",
        "http://127.0.0.1:1/",
        "--depth",
        "9",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["error"]["code"], "SSRF_BLOCKED");
    let crawl_id = body["error"]["details"]["crawlId"].as_str().unwrap();
    assert!(crawl_id.starts_with("crawl_"), "{crawl_id}");
    let manifest = body["error"]["details"]["manifestPath"].as_str().unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
    assert_eq!(manifest["kind"], "CRAWL");
    assert_eq!(manifest["status"], "FAILED");
    assert_eq!(manifest["policy"]["maxDepth"], 5);
    assert_eq!(manifest["failed"][0]["code"], "SSRF_BLOCKED");

    for args in [
        &["crawl", "not a url"][..],
        &[
            "crawl",
            "https://docs.example.test/",
            "--scope",
            "allowlist",
        ],
        &["crawl", "https://docs.example.test/", "--include", "("],
    ] {
        let mut full = vec!["--workspace", &workspace];
        full.extend_from_slice(args);
        let output = sandbox.run(&full);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(stderr(&output).contains("INVALID_ARGUMENT"), "{args:?}");
    }
    // Only the one FAILED run above was created.
    let runs = fs::read_dir(sandbox.dir.path().join("ws/runs"))
        .unwrap()
        .count();
    assert_eq!(runs, 1);
}

/// `open` needs no network for these: the guard refuses loopback before anything is fetched,
/// and an unparseable URL never reaches the guard. Exit codes per the contract.
#[test]
fn open_exit_codes_without_network() {
    let sandbox = Sandbox::new();
    let workspace = sandbox.dir.path().join("ws");
    let workspace = workspace.to_string_lossy();

    let output = sandbox.run(&[
        "--workspace",
        &workspace,
        "open",
        "http://127.0.0.1:1/",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["error"]["code"], "SSRF_BLOCKED");
    let manifest = body["error"]["details"]["manifestPath"].as_str().unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
    assert_eq!(manifest["kind"], "OPEN");
    assert_eq!(manifest["status"], "FAILED");
    assert_eq!(manifest["failed"][0]["code"], "SSRF_BLOCKED");

    for (url, code) in [
        ("not a url", 2),
        ("file:///etc/passwd", 2),
        ("http://user:pw@example.test/", 2),
        ("http://localhost:1/", 3),
        ("http://[::1]:1/", 3),
        ("http://169.254.169.254/", 3),
    ] {
        let output = sandbox.run(&["--workspace", &workspace, "open", url]);
        assert_eq!(
            output.status.code(),
            Some(code),
            "{url}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("error: "),
            "{url}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn serve_refuses_a_non_loopback_listen_override() {
    let sandbox = Sandbox::new();
    for listen in ["0.0.0.0:8787", "[::]:8787", "192.168.1.10:8787"] {
        let output = sandbox.run(&["serve", "--listen", listen]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{listen}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("server.listen"),
            "{listen}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn config_effective_prints_the_defaults_as_yaml() {
    let output = Sandbox::new().run(&["config", "--effective"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let yaml = stdout(&output);
    let config = Config::load_layered(Some(&yaml), [("", ""); 0]).unwrap();
    assert_eq!(config, Config::default());
    assert!(yaml.contains("# policyVersion: "), "{yaml}");
}

#[test]
fn config_without_flags_validates_and_reports_the_source() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["config"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("built-in defaults"),
        "{}",
        stdout(&output)
    );

    sandbox.write("secure-web.yaml", "fetch:\n  maxRedirects: 3\n");
    let output = sandbox.run(&["config"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("secure-web.yaml"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn global_overrides_apply_to_the_effective_config() {
    let sandbox = Sandbox::new();
    let file = sandbox.write("custom.yaml", "fetch:\n  maxRedirects: 3\n");
    let output = sandbox.run(&[
        "--config",
        &file,
        "--workspace",
        "/srv/secure-web",
        "--log-level",
        "debug",
        "config",
        "--effective",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let config = Config::load_layered(Some(&stdout(&output)), [("", ""); 0]).unwrap();
    assert_eq!(config.fetch.max_redirects, 3);
    assert_eq!(config.server.workspace.to_string_lossy(), "/srv/secure-web");
    assert_eq!(config.debug.log_level, LogLevel::Debug);
}

#[test]
fn env_override_reaches_the_effective_config() {
    let output = Sandbox::new().run_with_env(
        &["config", "--effective"],
        "SECURE_WEB__FETCH__MAX_PAGE_BYTES",
        "2MB",
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("maxPageBytes: 2000000"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn t16_weakened_config_file_exits_2() {
    let sandbox = Sandbox::new();
    sandbox.write(
        "secure-web.yaml",
        "security:\n  network:\n    blockPrivateAddresses: false\n",
    );
    for args in [
        &["config", "--effective"][..],
        &["open", "https://docs.example.test/"][..],
    ] {
        let output = sandbox.run(args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("security.network.blockPrivateAddresses"),
            "{}",
            stderr(&output)
        );
        assert!(stdout(&output).is_empty(), "{}", stdout(&output));
    }
}

#[test]
fn t16_weakening_env_override_exits_2() {
    let output = Sandbox::new().run_with_env(
        &["config", "--effective"],
        "SECURE_WEB__SECURITY__SCANNER__FAILURE_POLICY",
        "allow",
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("security.scanner.failurePolicy"));
}

#[test]
fn config_errors_exit_2() {
    let sandbox = Sandbox::new();
    let unknown = sandbox.write("unknown.yaml", "fetch:\n  maxPageByte: 5MB\n");
    let output = sandbox.run(&["--config", &unknown, "config"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("unknown field"),
        "{}",
        stderr(&output)
    );

    let missing = sandbox.dir.path().join("missing.yaml");
    let output = sandbox.run(&["--config", &missing.to_string_lossy(), "config"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

#[test]
fn usage_errors_exit_2() {
    let sandbox = Sandbox::new();
    for args in [
        &["bogus"][..],
        &["open"][..],
        &["--log-level", "loud", "config"][..],
        &[][..],
    ] {
        let output = sandbox.run(args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
    }
}
