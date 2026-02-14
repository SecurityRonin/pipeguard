use pipeguard::detection::threat::{ThreatLevel, ThreatMatch, ThreatResponse};

#[test]
fn threat_level_from_score_low() {
    // Scores 1-6 should be Low threat
    assert_eq!(ThreatLevel::from_score(1), ThreatLevel::Low);
    assert_eq!(ThreatLevel::from_score(6), ThreatLevel::Low);
}

#[test]
fn threat_level_from_score_medium() {
    // Scores 7-8 should be Medium threat
    assert_eq!(ThreatLevel::from_score(7), ThreatLevel::Medium);
    assert_eq!(ThreatLevel::from_score(8), ThreatLevel::Medium);
}

#[test]
fn threat_level_from_score_high() {
    // Scores 9-10 should be High threat
    assert_eq!(ThreatLevel::from_score(9), ThreatLevel::High);
    assert_eq!(ThreatLevel::from_score(10), ThreatLevel::High);
}

#[test]
fn threat_level_zero_is_none() {
    // Score 0 means no threat detected
    assert_eq!(ThreatLevel::from_score(0), ThreatLevel::None);
}

#[test]
fn threat_level_default_response() {
    // Low -> Warn, Medium -> Prompt, High -> Block
    assert_eq!(ThreatLevel::Low.default_response(), ThreatResponse::Warn);
    assert_eq!(
        ThreatLevel::Medium.default_response(),
        ThreatResponse::Prompt
    );
    assert_eq!(ThreatLevel::High.default_response(), ThreatResponse::Block);
    assert_eq!(ThreatLevel::None.default_response(), ThreatResponse::Allow);
}

#[test]
fn threat_match_aggregates_scores() {
    // Multiple matches should aggregate to highest score
    let matches = vec![
        ThreatMatch::new("base64_obfuscation", 5, "Base64 encoded payload"),
        ThreatMatch::new("reverse_shell", 10, "Reverse shell pattern"),
        ThreatMatch::new("env_harvest", 6, "Environment harvesting"),
    ];

    let max_score = ThreatMatch::max_score(&matches);
    assert_eq!(max_score, 10);
}

#[test]
fn threat_match_empty_returns_zero() {
    let matches: Vec<ThreatMatch> = vec![];
    assert_eq!(ThreatMatch::max_score(&matches), 0);
}

#[test]
fn threat_match_contains_rule_info() {
    let m = ThreatMatch::new("amos_stealer", 10, "AMOS infostealer IOC detected");
    assert_eq!(m.rule_name(), "amos_stealer");
    assert_eq!(m.severity(), 10);
    assert_eq!(m.description(), "AMOS infostealer IOC detected");
}
