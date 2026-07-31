//! Risk decision module — turns a [`ForensicResult`] into the one decision
//! that matters: does this file reach the user's Downloads folder?
//!
//! Thresholds come from `aegis.toml`. There is no behavioural input here and
//! no detonation stage: every signal feeding this decision is static, gathered
//! without running the file. See DECISIONS.md ("Detonation dropped").

#![allow(dead_code)]

use crate::config::RiskConfig;
use crate::scanner::ForensicResult;

/// Final download decision.
///
/// Three outcomes, and the middle one is not a weaker version of `Block` — it
/// is a different statement about the file, which is why it has its own name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Nothing of concern found — release to the Downloads folder.
    Release,
    /// Signals present, but below the threshold for a confirmed detection.
    ///
    /// The file is **not** released: Aegis fails closed, and it does not
    /// execute downloads to gather more evidence, so the analysis ends here.
    /// But it is not a detection either, and the user-facing message must say
    /// "could not clear this" rather than "this is malware".
    ///
    /// Formerly `Sandbox`, when this band triggered a detonation stage. That
    /// stage was removed — see DECISIONS.md ("Detonation dropped") — and the
    /// name changed with it so the code stops describing a step that no longer
    /// exists.
    Inconclusive,
    /// At or above the block threshold — a confirmed detection.
    Block,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Release => write!(f, "RELEASE"),
            Decision::Inconclusive => write!(f, "INCONCLUSIVE"),
            Decision::Block => write!(f, "BLOCK"),
        }
    }
}

/// Compute the risk-based decision from a forensic scan result.
///
/// Only `Release` delivers the file. Both other outcomes hold it — the
/// difference between them is what the user is told, not what happens to the
/// download.
pub fn decide(result: &ForensicResult, config: &RiskConfig) -> Decision {
    let score = result.risk_score;

    if score >= config.block_threshold {
        Decision::Block
    } else if score >= config.sandbox_threshold {
        Decision::Inconclusive
    } else {
        Decision::Release
    }
}

/// Collapse per-chunk scores into one score for the whole streaming pass.
///
/// The **maximum**, and nothing else.
///
/// This used to add a bonus of 0.05 per flagged chunk, on the reasoning that
/// many small signals add up to a larger one. They do not, because the chunks
/// are not independent observations: a large binary that mentions
/// `IsDebuggerPresent` mentions it in whichever chunk that string lands in, and
/// if the file is big enough the same handful of strings flag chunk after
/// chunk. That is one fact counted repeatedly, not accumulating evidence.
///
/// It also silently defeated the cap in `intent.rs`. That cap exists to keep
/// string matches below `sandbox_threshold`, so API names alone cannot stop a
/// file being delivered — and then this added 0.05 on top and pushed the total
/// back over the line. `notepad.exe` scored exactly 0.40 against a 0.40
/// threshold, entirely because of this bonus.
///
/// Genuinely independent signals are combined in `scanner::combine`, which is
/// the right place for it: there the inputs really are different observations.
pub fn aggregate_risk(chunk_scores: &[f32]) -> f32 {
    chunk_scores.iter().cloned().fold(0.0f32, f32::max).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RiskConfig {
        RiskConfig {
            sandbox_threshold: 0.4,
            block_threshold: 0.85,
        }
    }

    fn at(score: f32) -> ForensicResult {
        ForensicResult {
            risk_score: score,
            ..Default::default()
        }
    }

    /// The band boundaries are inclusive at the bottom, so a score sitting
    /// exactly on a threshold takes the more cautious side.
    #[test]
    fn thresholds_are_inclusive_and_ordered() {
        assert_eq!(decide(&at(0.0), &cfg()), Decision::Release);
        assert_eq!(decide(&at(0.39), &cfg()), Decision::Release);
        assert_eq!(decide(&at(0.4), &cfg()), Decision::Inconclusive);
        assert_eq!(decide(&at(0.84), &cfg()), Decision::Inconclusive);
        assert_eq!(decide(&at(0.85), &cfg()), Decision::Block);
        assert_eq!(decide(&at(1.0), &cfg()), Decision::Block);
    }

    /// The safety property, stated as a test: exactly one decision delivers
    /// the file. If a fourth variant is ever added, this fails until someone
    /// decides deliberately which side it falls on.
    #[test]
    fn only_release_delivers_the_file() {
        for score in [0.0, 0.2, 0.4, 0.6, 0.85, 1.0, 2.0, -1.0] {
            let d = decide(&at(score), &cfg());
            let delivers = d == Decision::Release;
            assert_eq!(
                delivers,
                score < 0.4,
                "score {score} produced {d}, which delivers={delivers}"
            );
        }
    }

    #[test]
    fn aggregate_is_empty_safe_and_bounded() {
        assert_eq!(aggregate_risk(&[]), 0.0);
        assert!(aggregate_risk(&[1.0, 1.0, 1.0, 1.0, 1.0]) <= 1.0);
        assert_eq!(aggregate_risk(&[0.5]), 0.5);
        assert_eq!(aggregate_risk(&[0.2, 0.7, 0.1]), 0.7);
    }

    /// Repeating a weak signal across chunks must not manufacture a strong one.
    ///
    /// This is the regression guard for a real false positive: a large binary
    /// mentions the same handful of API names in chunk after chunk, and the
    /// old per-chunk bonus turned that repetition into risk. It also silently
    /// defeated the cap in `intent.rs`, pushing `notepad.exe` to exactly the
    /// 0.40 threshold and holding a Microsoft-signed file.
    #[test]
    fn repeated_weak_signals_do_not_accumulate() {
        let one = aggregate_risk(&[0.35]);
        let many = aggregate_risk(&[0.35; 200]);
        assert_eq!(
            one, many,
            "the same score repeated across 200 chunks produced {many} instead \
             of {one} — repetition is not new evidence"
        );
        assert!(
            many < 0.4,
            "capped string matches must stay below sandbox_threshold however \
             many chunks they appear in, got {many}"
        );
    }
}
