//! Risk decision module — translates ForensicResult + sandbox verdict
//! into actionable decisions using thresholds from aegis.toml.

use crate::config::RiskConfig;
use crate::scanner::ForensicResult;
use crate::sandbox::Verdict;

/// Final download decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// File is clean — release to Downloads folder.
    Release,
    /// Score is in the sandbox zone — detonate before deciding.
    Sandbox,
    /// Score is above block threshold — block outright, notify user.
    Block,
    /// File exceeds max_detonation_size — static-only verdict with warning.
    TooLargeToSandbox,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Release => write!(f, "RELEASE"),
            Decision::Sandbox => write!(f, "SANDBOX"),
            Decision::Block => write!(f, "BLOCK"),
            Decision::TooLargeToSandbox => write!(f, "TOO_LARGE_TO_SANDBOX"),
        }
    }
}

/// Compute the risk-based decision from a forensic scan result.
pub fn decide(result: &ForensicResult, config: &RiskConfig) -> Decision {
    let score = result.risk_score;

    if score >= config.block_threshold {
        Decision::Block
    } else if score >= config.sandbox_threshold {
        Decision::Sandbox
    } else {
        Decision::Release
    }
}

/// Compute the final decision after sandbox detonation.
pub fn decide_after_sandbox(sandbox_verdict: &Verdict) -> Decision {
    match sandbox_verdict {
        Verdict::Clean => Decision::Release,
        Verdict::Suspicious | Verdict::Malicious => Decision::Block,
    }
}

/// Accumulate risk scores from multiple chunk scans into a single aggregate.
/// Uses the maximum observed risk score (conservative) plus a small bonus
/// for the number of flagged chunks (many small signals = higher overall risk).
pub fn aggregate_risk(chunk_scores: &[f32]) -> f32 {
    if chunk_scores.is_empty() {
        return 0.0;
    }
    let max_score = chunk_scores
        .iter()
        .cloned()
        .fold(0.0f32, f32::max);
    let flagged_count = chunk_scores.iter().filter(|&&s| s > 0.0).count();
    let multi_chunk_bonus = (flagged_count as f32 * 0.05).min(0.2);
    (max_score + multi_chunk_bonus).min(1.0)
}
