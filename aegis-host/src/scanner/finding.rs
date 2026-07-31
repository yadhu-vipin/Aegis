//! Structured findings — what was found, and what it means to a person.
//!
//! Scanner output used to be flat strings like
//! `"[risk=0.60] CreateRemoteThread (utf-8): Process injection via remote thread"`.
//! Accurate, and useless to the person whose download just vanished: it names
//! an API without saying what the file was trying to do or why they should
//! care.
//!
//! A finding therefore carries three separate things:
//!
//! * `title` — the headline, in plain language, no jargon
//! * `detail` — what was actually observed, technical, for someone who wants to
//!   verify the claim
//! * `why` — why it matters, in terms of consequences to the user
//!
//! Keeping them apart lets each surface show what suits it: a notification
//! shows the title, the popup shows title + why, and the technical detail sits
//! behind a disclosure for anyone who wants to check the reasoning. Collapsing
//! them into one string forces every surface to show all or nothing.

use serde::Serialize;

/// How serious a single finding is, independent of the aggregate risk score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Near-certain malice. On its own, enough to block.
    Critical,
    /// Strong signal. Blocks in combination, or sends to the sandbox.
    High,
    /// Worth reporting; rarely decisive alone.
    Medium,
    /// Weak corroborating signal.
    Low,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        }
    }
}

/// One thing the scanner found, explained.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Plain-language headline. No API names, no file-format jargon.
    pub title: String,
    /// What was actually observed. Technical on purpose — this is the evidence.
    pub detail: String,
    /// Why it matters, in terms of what could happen to the user.
    pub why: String,
    /// Risk contribution, 0.0–1.0.
    pub risk: f32,
}

impl Finding {
    pub fn new(
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
        why: impl Into<String>,
        risk: f32,
    ) -> Self {
        Self {
            severity,
            title: title.into(),
            detail: detail.into(),
            why: why.into(),
            risk: risk.clamp(0.0, 1.0),
        }
    }

    /// Single-line rendering, for logs and for surfaces that cannot show
    /// structure.
    pub fn one_line(&self) -> String {
        format!("[{}] {}: {}", self.severity.label(), self.title, self.detail)
    }
}

/// Order findings so the most serious explanation is the one a user sees first.
///
/// A notification has room for one line; it must be the worst thing found, not
/// whichever check happened to run first.
pub fn sort_by_severity(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        let rank = |s: Severity| match s {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
        };
        rank(a.severity)
            .cmp(&rank(b.severity))
            .then(b.risk.partial_cmp(&a.risk).unwrap_or(std::cmp::Ordering::Equal))
    });
}

/// Map a risk contribution onto a severity band.
pub fn severity_for(risk: f32) -> Severity {
    if risk >= 0.85 {
        Severity::Critical
    } else if risk >= 0.55 {
        Severity::High
    } else if risk >= 0.3 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_bands_are_ordered() {
        assert_eq!(severity_for(1.0), Severity::Critical);
        assert_eq!(severity_for(0.85), Severity::Critical);
        assert_eq!(severity_for(0.6), Severity::High);
        assert_eq!(severity_for(0.4), Severity::Medium);
        assert_eq!(severity_for(0.1), Severity::Low);
    }

    /// The worst finding must come first — a notification shows one line, and
    /// it has to be the one that matters.
    #[test]
    fn worst_finding_sorts_first() {
        let mut f = vec![
            Finding::new(Severity::Low, "minor", "d", "w", 0.1),
            Finding::new(Severity::Critical, "worst", "d", "w", 1.0),
            Finding::new(Severity::Medium, "middling", "d", "w", 0.4),
        ];
        sort_by_severity(&mut f);
        assert_eq!(f[0].title, "worst");
        assert_eq!(f[2].title, "minor");
    }

    /// Within a severity band, higher risk wins.
    #[test]
    fn equal_severity_orders_by_risk() {
        let mut f = vec![
            Finding::new(Severity::High, "lower", "d", "w", 0.56),
            Finding::new(Severity::High, "higher", "d", "w", 0.8),
        ];
        sort_by_severity(&mut f);
        assert_eq!(f[0].title, "higher");
    }

    #[test]
    fn risk_is_clamped() {
        assert_eq!(Finding::new(Severity::Low, "t", "d", "w", 5.0).risk, 1.0);
        assert_eq!(Finding::new(Severity::Low, "t", "d", "w", -1.0).risk, 0.0);
    }
}
