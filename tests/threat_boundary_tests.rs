// Boundary and property tests for threat classification
// Covers: from_score boundaries, default_response mappings, ThreatMatch

use pipeguard::detection::threat::{ThreatLevel, ThreatMatch, ThreatResponse};

// ─── from_score boundaries ──────────────────────────────────────

#[test]
fn score_0_is_none() {
    assert_eq!(ThreatLevel::from_score(0), ThreatLevel::None);
}

#[test]
fn score_1_is_low() {
    assert_eq!(ThreatLevel::from_score(1), ThreatLevel::Low);
}

#[test]
fn score_6_is_low() {
    assert_eq!(ThreatLevel::from_score(6), ThreatLevel::Low);
}

#[test]
fn score_7_is_medium() {
    assert_eq!(ThreatLevel::from_score(7), ThreatLevel::Medium);
}

#[test]
fn score_8_is_medium() {
    assert_eq!(ThreatLevel::from_score(8), ThreatLevel::Medium);
}

#[test]
fn score_9_is_high() {
    assert_eq!(ThreatLevel::from_score(9), ThreatLevel::High);
}

#[test]
fn score_10_is_high() {
    assert_eq!(ThreatLevel::from_score(10), ThreatLevel::High);
}

#[test]
fn score_above_10_is_high() {
    assert_eq!(ThreatLevel::from_score(11), ThreatLevel::High);
    assert_eq!(ThreatLevel::from_score(100), ThreatLevel::High);
    assert_eq!(ThreatLevel::from_score(u8::MAX), ThreatLevel::High);
}

// All boundary transitions
#[test]
fn all_scores_covered() {
    for score in 0..=255u8 {
        let level = ThreatLevel::from_score(score);
        match score {
            0 => assert_eq!(level, ThreatLevel::None),
            1..=6 => assert_eq!(level, ThreatLevel::Low),
            7..=8 => assert_eq!(level, ThreatLevel::Medium),
            _ => assert_eq!(level, ThreatLevel::High),
        }
    }
}

// ─── default_response ───────────────────────────────────────────

#[test]
fn none_default_response_is_allow() {
    assert_eq!(ThreatLevel::None.default_response(), ThreatResponse::Allow);
}

#[test]
fn low_default_response_is_warn() {
    assert_eq!(ThreatLevel::Low.default_response(), ThreatResponse::Warn);
}

#[test]
fn medium_default_response_is_prompt() {
    assert_eq!(
        ThreatLevel::Medium.default_response(),
        ThreatResponse::Prompt
    );
}

#[test]
fn high_default_response_is_block() {
    assert_eq!(ThreatLevel::High.default_response(), ThreatResponse::Block);
}

// ─── ThreatLevel Display ────────────────────────────────────────

#[test]
fn threat_level_display() {
    assert_eq!(ThreatLevel::None.to_string(), "None");
    assert_eq!(ThreatLevel::Low.to_string(), "Low");
    assert_eq!(ThreatLevel::Medium.to_string(), "Medium");
    assert_eq!(ThreatLevel::High.to_string(), "High");
}

// ─── ThreatMatch ────────────────────────────────────────────────

#[test]
fn threat_match_accessors() {
    let m = ThreatMatch::new("test_rule", 7, "Test description");
    assert_eq!(m.rule_name(), "test_rule");
    assert_eq!(m.severity(), 7);
    assert_eq!(m.description(), "Test description");
}

#[test]
fn threat_match_empty_fields() {
    let m = ThreatMatch::new("", 0, "");
    assert_eq!(m.rule_name(), "");
    assert_eq!(m.severity(), 0);
    assert_eq!(m.description(), "");
}

#[test]
fn threat_match_max_score_empty() {
    assert_eq!(ThreatMatch::max_score(&[]), 0);
}

#[test]
fn threat_match_max_score_single() {
    let matches = vec![ThreatMatch::new("r1", 5, "d1")];
    assert_eq!(ThreatMatch::max_score(&matches), 5);
}

#[test]
fn threat_match_max_score_multiple() {
    let matches = vec![
        ThreatMatch::new("r1", 3, "d1"),
        ThreatMatch::new("r2", 9, "d2"),
        ThreatMatch::new("r3", 6, "d3"),
    ];
    assert_eq!(ThreatMatch::max_score(&matches), 9);
}

#[test]
fn threat_match_max_score_all_same() {
    let matches = vec![
        ThreatMatch::new("r1", 5, "d1"),
        ThreatMatch::new("r2", 5, "d2"),
    ];
    assert_eq!(ThreatMatch::max_score(&matches), 5);
}

#[test]
fn threat_match_max_score_with_zero() {
    let matches = vec![
        ThreatMatch::new("r1", 0, "d1"),
        ThreatMatch::new("r2", 0, "d2"),
    ];
    assert_eq!(ThreatMatch::max_score(&matches), 0);
}

// ─── Serde roundtrip ────────────────────────────────────────────

#[test]
fn threat_level_serde_roundtrip() {
    for level in [
        ThreatLevel::None,
        ThreatLevel::Low,
        ThreatLevel::Medium,
        ThreatLevel::High,
    ] {
        let json = serde_json::to_string(&level).unwrap();
        let deserialized: ThreatLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, deserialized);
    }
}

#[test]
fn threat_response_serde_roundtrip() {
    for response in [
        ThreatResponse::Allow,
        ThreatResponse::Warn,
        ThreatResponse::Prompt,
        ThreatResponse::Block,
    ] {
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ThreatResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response, deserialized);
    }
}

#[test]
fn threat_level_serde_lowercase() {
    assert_eq!(
        serde_json::to_string(&ThreatLevel::None).unwrap(),
        "\"none\""
    );
    assert_eq!(
        serde_json::to_string(&ThreatLevel::High).unwrap(),
        "\"high\""
    );
}
