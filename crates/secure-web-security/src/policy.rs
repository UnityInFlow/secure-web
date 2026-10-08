//! Policy engine: scanner findings → `Safe` / `Warn` / `Block` (`docs/security-policy.md` §5).
//!
//! ```text
//! max severity CRITICAL/HIGH -> Block(PromptInjection)     (config cannot weaken these)
//! max severity MEDIUM         -> security.injection.medium  (default warn)
//! max severity LOW            -> security.injection.low     (default allow)
//! no findings                 -> Safe
//! scan error                  -> Block(ScannerFailure)      (always; see decide_error)
//! ```
//!
//! Only the scanner's `matches` drive the decision; `low_confidence` never does.

use secure_web_core::config::{
    ConfigError, InjectionAction, InjectionPolicyConfig, SecurityConfig, WarnHandling,
    SCANNER_FAILURE_POLICY_BLOCK,
};
use secure_web_core::model::{BlockReason, SecurityDecision, SecurityFindings, Severity};
use serde::Serialize;

use crate::injection::ScanError;

/// The policy decision for one document. Carries enums only, never page text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyOutcome {
    /// Accept.
    Safe,
    /// Accept, flagged (or quarantined per `security.warnHandling`).
    Warn,
    /// Reject; nothing from the document is exposed.
    Block(BlockReason),
}

impl PolicyOutcome {
    /// The contract decision enum for this outcome.
    pub fn decision(self) -> SecurityDecision {
        match self {
            PolicyOutcome::Safe => SecurityDecision::Safe,
            PolicyOutcome::Warn => SecurityDecision::Warn,
            PolicyOutcome::Block(_) => SecurityDecision::Block,
        }
    }
}

/// Decides what happens to a scanned document.
pub trait SecurityPolicy: Send + Sync {
    /// Decide on successful scanner findings.
    fn decide(&self, findings: &SecurityFindings) -> PolicyOutcome;
    /// `policyVersion` stamped on every decision.
    fn policy_version(&self) -> &str;
}

/// The outcome for a failed scan: always `Block(ScannerFailure)`.
///
/// ADR-003 (scanner failure is fail-closed): no configuration value and no `ScanError` variant
/// turns a failed scan into an accept. This is a free function, not a [`SecurityPolicy`]
/// method, so no policy implementation can override it. The match is exhaustive on purpose: a
/// new `ScanError` variant must be added here consciously.
pub fn decide_error(err: &ScanError) -> PolicyOutcome {
    match err {
        ScanError::Unavailable(_)
        | ScanError::NotFound
        | ScanError::Spawn(_)
        | ScanError::InputTooLarge { .. }
        | ScanError::Io(_)
        | ScanError::Timeout(_)
        | ScanError::Crashed { .. }
        | ScanError::InvalidOutput(_)
        | ScanError::OutputTooLarge { .. }
        | ScanError::StderrTooLarge { .. } => PolicyOutcome::Block(BlockReason::ScannerFailure),
    }
}

/// Why a [`PolicyEngine`] could not be built.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// `security.scanner.failurePolicy` is not `block`.
    #[error(
        "security.scanner.failurePolicy must be \"block\" (scanner errors fail closed), got {0:?}"
    )]
    FailurePolicy(String),
    /// A `CRITICAL` or `HIGH` action is not `block`.
    #[error("security.injection.{0} must be \"block\"")]
    MustBlock(&'static str),
    /// The policy version could not be computed.
    #[error(transparent)]
    Version(#[from] ConfigError),
}

/// The v0.1 policy engine, built from the `security:` config block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEngine {
    injection: InjectionPolicyConfig,
    warn_handling: WarnHandling,
    policy_version: String,
}

impl PolicyEngine {
    /// Build the engine. Re-checks the rules `Config::validate` enforces, so an unvalidated
    /// config cannot weaken the policy: `failurePolicy` other than `block`, or a `CRITICAL`/`HIGH`
    /// action other than `block`, is refused.
    pub fn new(security: &SecurityConfig) -> Result<Self, PolicyError> {
        if security.scanner.failure_policy != SCANNER_FAILURE_POLICY_BLOCK {
            return Err(PolicyError::FailurePolicy(
                security.scanner.failure_policy.clone(),
            ));
        }
        if security.injection.critical != InjectionAction::Block {
            return Err(PolicyError::MustBlock("critical"));
        }
        if security.injection.high != InjectionAction::Block {
            return Err(PolicyError::MustBlock("high"));
        }
        Ok(Self {
            injection: security.injection.clone(),
            warn_handling: security.warn_handling,
            policy_version: security.policy_version()?,
        })
    }

    /// What the store does with `WARN` documents.
    pub fn warn_handling(&self) -> WarnHandling {
        self.warn_handling
    }

    fn action(&self, severity: Severity) -> InjectionAction {
        match severity {
            Severity::Critical => self.injection.critical,
            Severity::High => self.injection.high,
            Severity::Medium => self.injection.medium,
            Severity::Low => self.injection.low,
        }
    }
}

impl SecurityPolicy for PolicyEngine {
    /// Strictest action across all findings (`matches` only).
    fn decide(&self, findings: &SecurityFindings) -> PolicyOutcome {
        let strictest = findings
            .findings
            .iter()
            .map(|finding| self.action(finding.severity))
            .max_by_key(|action| match action {
                InjectionAction::Allow => 0,
                InjectionAction::Warn => 1,
                InjectionAction::Block => 2,
            });
        match strictest {
            None | Some(InjectionAction::Allow) => PolicyOutcome::Safe,
            Some(InjectionAction::Warn) => PolicyOutcome::Warn,
            Some(InjectionAction::Block) => PolicyOutcome::Block(BlockReason::PromptInjection),
        }
    }

    fn policy_version(&self) -> &str {
        &self.policy_version
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use secure_web_core::model::Finding;

    use super::*;
    use crate::injection::{InvalidOutput, VersionError};

    const ACTIONS: [InjectionAction; 3] = [
        InjectionAction::Allow,
        InjectionAction::Warn,
        InjectionAction::Block,
    ];

    fn finding(severity: Severity) -> Finding {
        Finding {
            id: "PI001".into(),
            severity,
            detector: "x".into(),
            line: 1,
            confidence: 1.0,
        }
    }

    fn findings(severities: &[Severity]) -> SecurityFindings {
        SecurityFindings::new(
            "injection-scanner 0.1.0".into(),
            severities.iter().copied().map(finding).collect(),
            0,
            Duration::ZERO,
        )
    }

    fn engine(medium: InjectionAction, low: InjectionAction) -> PolicyEngine {
        let mut security = SecurityConfig::default();
        security.injection.medium = medium;
        security.injection.low = low;
        PolicyEngine::new(&security).unwrap()
    }

    fn expected(action: InjectionAction) -> PolicyOutcome {
        match action {
            InjectionAction::Allow => PolicyOutcome::Safe,
            InjectionAction::Warn => PolicyOutcome::Warn,
            InjectionAction::Block => PolicyOutcome::Block(BlockReason::PromptInjection),
        }
    }

    /// Every severity × every configurable action.
    #[test]
    fn every_severity_and_action_combination() {
        for medium in ACTIONS {
            for low in ACTIONS {
                let policy = engine(medium, low);
                let block = PolicyOutcome::Block(BlockReason::PromptInjection);
                assert_eq!(policy.decide(&findings(&[])), PolicyOutcome::Safe);
                assert_eq!(policy.decide(&findings(&[Severity::Critical])), block);
                assert_eq!(policy.decide(&findings(&[Severity::High])), block);
                assert_eq!(
                    policy.decide(&findings(&[Severity::Medium])),
                    expected(medium)
                );
                assert_eq!(policy.decide(&findings(&[Severity::Low])), expected(low));
                // Strictest wins, whatever the order.
                let strictest = expected(medium.max_rank(low));
                assert_eq!(
                    policy.decide(&findings(&[Severity::Low, Severity::Medium])),
                    strictest
                );
                assert_eq!(
                    policy.decide(&findings(&[Severity::Medium, Severity::Low])),
                    strictest
                );
                for high in [Severity::High, Severity::Critical] {
                    assert_eq!(
                        policy.decide(&findings(&[Severity::Low, high, Severity::Medium])),
                        block
                    );
                }
            }
        }
    }

    trait Rank {
        fn max_rank(self, other: Self) -> Self;
    }

    impl Rank for InjectionAction {
        fn max_rank(self, other: Self) -> Self {
            let rank = |a: InjectionAction| match a {
                InjectionAction::Allow => 0,
                InjectionAction::Warn => 1,
                InjectionAction::Block => 2,
            };
            if rank(self) >= rank(other) {
                self
            } else {
                other
            }
        }
    }

    #[test]
    fn default_policy_matches_the_security_policy_table() {
        let policy = PolicyEngine::new(&SecurityConfig::default()).unwrap();
        assert_eq!(
            policy.decide(&findings(&[Severity::Medium])),
            PolicyOutcome::Warn
        );
        assert_eq!(
            policy.decide(&findings(&[Severity::Low])),
            PolicyOutcome::Safe
        );
        assert_eq!(policy.warn_handling(), WarnHandling::Store);
        assert_eq!(policy.policy_version().len(), 12);
    }

    #[test]
    fn low_confidence_never_changes_the_decision() {
        let policy = PolicyEngine::new(&SecurityConfig::default()).unwrap();
        let mut only_low_confidence = findings(&[]);
        only_low_confidence.low_confidence_count = 7;
        assert_eq!(policy.decide(&only_low_confidence), PolicyOutcome::Safe);
    }

    #[test]
    fn decision_ignores_the_max_severity_field() {
        // `max_severity` is derived; the decision reads the findings themselves.
        let policy = PolicyEngine::new(&SecurityConfig::default()).unwrap();
        let mut forged = findings(&[Severity::Critical]);
        forged.max_severity = None;
        assert_eq!(
            policy.decide(&forged),
            PolicyOutcome::Block(BlockReason::PromptInjection)
        );
    }

    #[test]
    fn new_refuses_failure_policy_allow() {
        for value in ["allow", "warn", "", "BLOCK", "block "] {
            let mut security = SecurityConfig::default();
            security.scanner.failure_policy = value.into();
            assert!(
                matches!(
                    PolicyEngine::new(&security),
                    Err(PolicyError::FailurePolicy(_))
                ),
                "{value:?} accepted"
            );
        }
    }

    #[test]
    fn new_refuses_weakened_critical_or_high() {
        for weak in [InjectionAction::Allow, InjectionAction::Warn] {
            let mut security = SecurityConfig::default();
            security.injection.critical = weak;
            assert!(matches!(
                PolicyEngine::new(&security),
                Err(PolicyError::MustBlock("critical"))
            ));
            let mut security = SecurityConfig::default();
            security.injection.high = weak;
            assert!(matches!(
                PolicyEngine::new(&security),
                Err(PolicyError::MustBlock("high"))
            ));
        }
    }

    #[test]
    fn policy_version_matches_the_config() {
        let mut config = secure_web_core::config::Config::default();
        config.security.warn_handling = WarnHandling::Quarantine;
        let policy = PolicyEngine::new(&config.security).unwrap();
        assert_eq!(policy.policy_version(), config.policy_version().unwrap());
        assert_eq!(policy.warn_handling(), WarnHandling::Quarantine);
    }

    #[test]
    fn every_scan_error_blocks_as_scanner_failure() {
        for err in [
            ScanError::Unavailable(VersionError::NotFound),
            ScanError::NotFound,
            ScanError::Spawn(std::io::ErrorKind::PermissionDenied),
            ScanError::InputTooLarge { bytes: 2, limit: 1 },
            ScanError::Io(std::io::ErrorKind::BrokenPipe),
            ScanError::Timeout(Duration::from_secs(2)),
            ScanError::Crashed { code: None },
            ScanError::Crashed { code: Some(2) },
            ScanError::InvalidOutput(InvalidOutput::Malformed),
            ScanError::OutputTooLarge { limit: 1 },
            ScanError::StderrTooLarge { limit: 1 },
        ] {
            assert_eq!(
                decide_error(&err),
                PolicyOutcome::Block(BlockReason::ScannerFailure),
                "{err:?}"
            );
        }
    }

    #[test]
    fn outcome_maps_to_the_contract_decision() {
        assert_eq!(PolicyOutcome::Safe.decision(), SecurityDecision::Safe);
        assert_eq!(PolicyOutcome::Warn.decision(), SecurityDecision::Warn);
        assert_eq!(
            PolicyOutcome::Block(BlockReason::ScannerFailure).decision(),
            SecurityDecision::Block
        );
        assert_eq!(
            serde_json::to_value(PolicyOutcome::Block(BlockReason::PromptInjection)).unwrap(),
            serde_json::json!({ "BLOCK": "PROMPT_INJECTION" })
        );
    }
}
