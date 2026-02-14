//! Exhaustive tests for threat level classification and scoring.

use pipeguard::detection::threat::{ThreatLevel, ThreatMatch, ThreatResponse};

// =============================================================================
// ThreatLevel::from_score boundary tests
// =============================================================================

#[test]
fn score_0_is_none() {
    assert_eq!(ThreatLevel::from_score(0), ThreatLevel::None);
}

#[test]
fn score_1_is_low() {
    assert_eq!(ThreatLevel::from_score(1), ThreatLevel::Low);
}

#[test]
fn score_2_is_low() {
    assert_eq!(ThreatLevel::from_score(2), ThreatLevel::Low);
}

#[test]
fn score_3_is_low() {
    assert_eq!(ThreatLevel::from_score(3), ThreatLevel::Low);
}

#[test]
fn score_4_is_low() {
    assert_eq!(ThreatLevel::from_score(4), ThreatLevel::Low);
}

#[test]
fn score_5_is_low() {
    assert_eq!(ThreatLevel::from_score(5), ThreatLevel::Low);
}

#[test]
fn score_6_is_low_boundary() {
    assert_eq!(ThreatLevel::from_score(6), ThreatLevel::Low);
}

#[test]
fn score_7_is_medium_boundary() {
    assert_eq!(ThreatLevel::from_score(7), ThreatLevel::Medium);
}

#[test]
fn score_8_is_medium() {
    assert_eq!(ThreatLevel::from_score(8), ThreatLevel::Medium);
}

#[test]
fn score_9_is_high_boundary() {
    assert_eq!(ThreatLevel::from_score(9), ThreatLevel::High);
}

#[test]
fn score_10_is_high() {
    assert_eq!(ThreatLevel::from_score(10), ThreatLevel::High);
}

#[test]
fn score_11_is_still_high() {
    assert_eq!(ThreatLevel::from_score(11), ThreatLevel::High);
}

#[test]
fn score_255_is_high() {
    assert_eq!(ThreatLevel::from_score(255), ThreatLevel::High);
}

// =============================================================================
// ThreatLevel::default_response tests
// =============================================================================

#[test]
fn none_response_is_allow() {
    assert_eq!(ThreatLevel::None.default_response(), ThreatResponse::Allow);
}

#[test]
fn low_response_is_warn() {
    assert_eq!(ThreatLevel::Low.default_response(), ThreatResponse::Warn);
}

#[test]
fn medium_response_is_prompt() {
    assert_eq!(
        ThreatLevel::Medium.default_response(),
        ThreatResponse::Prompt
    );
}

#[test]
fn high_response_is_block() {
    assert_eq!(ThreatLevel::High.default_response(), ThreatResponse::Block);
}

// =============================================================================
// ThreatLevel equality and ordering
// =============================================================================

#[test]
fn threat_levels_are_equal_to_themselves() {
    assert_eq!(ThreatLevel::None, ThreatLevel::None);
    assert_eq!(ThreatLevel::Low, ThreatLevel::Low);
    assert_eq!(ThreatLevel::Medium, ThreatLevel::Medium);
    assert_eq!(ThreatLevel::High, ThreatLevel::High);
}

#[test]
fn threat_levels_are_not_equal_to_others() {
    assert_ne!(ThreatLevel::None, ThreatLevel::Low);
    assert_ne!(ThreatLevel::Low, ThreatLevel::Medium);
    assert_ne!(ThreatLevel::Medium, ThreatLevel::High);
    assert_ne!(ThreatLevel::None, ThreatLevel::High);
}

#[test]
fn threat_level_can_be_cloned() {
    let level = ThreatLevel::High;
    let cloned = {
        // Explicitly test the Clone impl (not just Copy)
        #[allow(clippy::clone_on_copy)]
        let c = level.clone();
        c
    };
    assert_eq!(level, cloned);
}

#[test]
fn threat_level_can_be_copied() {
    let level = ThreatLevel::Medium;
    let copied: ThreatLevel = level;
    assert_eq!(level, copied);
}

#[test]
fn threat_level_debug_format() {
    assert_eq!(format!("{:?}", ThreatLevel::None), "None");
    assert_eq!(format!("{:?}", ThreatLevel::Low), "Low");
    assert_eq!(format!("{:?}", ThreatLevel::Medium), "Medium");
    assert_eq!(format!("{:?}", ThreatLevel::High), "High");
}

// =============================================================================
// ThreatResponse tests
// =============================================================================

#[test]
fn response_allow_equals_allow() {
    assert_eq!(ThreatResponse::Allow, ThreatResponse::Allow);
}

#[test]
fn response_warn_equals_warn() {
    assert_eq!(ThreatResponse::Warn, ThreatResponse::Warn);
}

#[test]
fn response_prompt_equals_prompt() {
    assert_eq!(ThreatResponse::Prompt, ThreatResponse::Prompt);
}

#[test]
fn response_block_equals_block() {
    assert_eq!(ThreatResponse::Block, ThreatResponse::Block);
}

#[test]
fn response_can_be_cloned() {
    let response = ThreatResponse::Block;
    assert_eq!(response.clone(), ThreatResponse::Block);
}

#[test]
fn response_can_be_copied() {
    let response = ThreatResponse::Prompt;
    let copied: ThreatResponse = response;
    assert_eq!(response, copied);
}

#[test]
fn response_debug_format() {
    assert_eq!(format!("{:?}", ThreatResponse::Allow), "Allow");
    assert_eq!(format!("{:?}", ThreatResponse::Warn), "Warn");
    assert_eq!(format!("{:?}", ThreatResponse::Prompt), "Prompt");
    assert_eq!(format!("{:?}", ThreatResponse::Block), "Block");
}

// =============================================================================
// ThreatMatch tests
// =============================================================================

#[test]
fn threat_match_stores_rule_name() {
    let m = ThreatMatch::new("test_rule", 5, "Test description");
    assert_eq!(m.rule_name(), "test_rule");
}

#[test]
fn threat_match_stores_severity() {
    let m = ThreatMatch::new("test_rule", 7, "Test description");
    assert_eq!(m.severity(), 7);
}

#[test]
fn threat_match_stores_description() {
    let m = ThreatMatch::new("test_rule", 5, "My custom description");
    assert_eq!(m.description(), "My custom description");
}

#[test]
fn threat_match_with_empty_name() {
    let m = ThreatMatch::new("", 5, "Empty name");
    assert_eq!(m.rule_name(), "");
}

#[test]
fn threat_match_with_empty_description() {
    let m = ThreatMatch::new("rule", 5, "");
    assert_eq!(m.description(), "");
}

#[test]
fn threat_match_with_unicode_name() {
    let m = ThreatMatch::new("règle_détection", 5, "Unicode rule");
    assert_eq!(m.rule_name(), "règle_détection");
}

#[test]
fn threat_match_with_unicode_description() {
    let m = ThreatMatch::new("rule", 5, "检测到恶意代码");
    assert_eq!(m.description(), "检测到恶意代码");
}

#[test]
fn threat_match_with_long_name() {
    let long_name = "a".repeat(1000);
    let m = ThreatMatch::new(&long_name, 5, "Long name");
    assert_eq!(m.rule_name(), long_name);
}

#[test]
fn threat_match_with_long_description() {
    let long_desc = "b".repeat(10000);
    let m = ThreatMatch::new("rule", 5, &long_desc);
    assert_eq!(m.description(), long_desc);
}

#[test]
fn threat_match_severity_zero() {
    let m = ThreatMatch::new("rule", 0, "Zero severity");
    assert_eq!(m.severity(), 0);
}

#[test]
fn threat_match_severity_max() {
    let m = ThreatMatch::new("rule", 255, "Max severity");
    assert_eq!(m.severity(), 255);
}

#[test]
fn threat_match_can_be_cloned() {
    let m = ThreatMatch::new("rule", 5, "desc");
    let cloned = m.clone();
    assert_eq!(m.rule_name(), cloned.rule_name());
    assert_eq!(m.severity(), cloned.severity());
    assert_eq!(m.description(), cloned.description());
}

// =============================================================================
// ThreatMatch::max_score tests
// =============================================================================

#[test]
fn max_score_empty_vec() {
    let matches: Vec<ThreatMatch> = vec![];
    assert_eq!(ThreatMatch::max_score(&matches), 0);
}

#[test]
fn max_score_single_match() {
    let matches = vec![ThreatMatch::new("rule", 7, "desc")];
    assert_eq!(ThreatMatch::max_score(&matches), 7);
}

#[test]
fn max_score_two_matches_first_higher() {
    let matches = vec![
        ThreatMatch::new("rule1", 8, "desc1"),
        ThreatMatch::new("rule2", 5, "desc2"),
    ];
    assert_eq!(ThreatMatch::max_score(&matches), 8);
}

#[test]
fn max_score_two_matches_second_higher() {
    let matches = vec![
        ThreatMatch::new("rule1", 3, "desc1"),
        ThreatMatch::new("rule2", 9, "desc2"),
    ];
    assert_eq!(ThreatMatch::max_score(&matches), 9);
}

#[test]
fn max_score_equal_severities() {
    let matches = vec![
        ThreatMatch::new("rule1", 5, "desc1"),
        ThreatMatch::new("rule2", 5, "desc2"),
    ];
    assert_eq!(ThreatMatch::max_score(&matches), 5);
}

#[test]
fn max_score_many_matches() {
    let matches = vec![
        ThreatMatch::new("rule1", 1, "desc1"),
        ThreatMatch::new("rule2", 3, "desc2"),
        ThreatMatch::new("rule3", 10, "desc3"),
        ThreatMatch::new("rule4", 2, "desc4"),
        ThreatMatch::new("rule5", 7, "desc5"),
    ];
    assert_eq!(ThreatMatch::max_score(&matches), 10);
}

#[test]
fn max_score_all_zero() {
    let matches = vec![
        ThreatMatch::new("rule1", 0, "desc1"),
        ThreatMatch::new("rule2", 0, "desc2"),
    ];
    assert_eq!(ThreatMatch::max_score(&matches), 0);
}

#[test]
fn max_score_with_255() {
    let matches = vec![
        ThreatMatch::new("rule1", 10, "desc1"),
        ThreatMatch::new("rule2", 255, "desc2"),
    ];
    assert_eq!(ThreatMatch::max_score(&matches), 255);
}

// =============================================================================
// Combined scenario tests
// =============================================================================

#[test]
fn full_flow_no_matches() {
    let matches: Vec<ThreatMatch> = vec![];
    let max = ThreatMatch::max_score(&matches);
    let level = ThreatLevel::from_score(max);
    let response = level.default_response();

    assert_eq!(max, 0);
    assert_eq!(level, ThreatLevel::None);
    assert_eq!(response, ThreatResponse::Allow);
}

#[test]
fn full_flow_low_threat() {
    let matches = vec![ThreatMatch::new("base64", 5, "Base64 obfuscation")];
    let max = ThreatMatch::max_score(&matches);
    let level = ThreatLevel::from_score(max);
    let response = level.default_response();

    assert_eq!(max, 5);
    assert_eq!(level, ThreatLevel::Low);
    assert_eq!(response, ThreatResponse::Warn);
}

#[test]
fn full_flow_medium_threat() {
    let matches = vec![
        ThreatMatch::new("staged", 7, "Staged download"),
        ThreatMatch::new("obfuscation", 4, "Obfuscation"),
    ];
    let max = ThreatMatch::max_score(&matches);
    let level = ThreatLevel::from_score(max);
    let response = level.default_response();

    assert_eq!(max, 7);
    assert_eq!(level, ThreatLevel::Medium);
    assert_eq!(response, ThreatResponse::Prompt);
}

#[test]
fn full_flow_high_threat() {
    let matches = vec![
        ThreatMatch::new("reverse_shell", 10, "Reverse shell"),
        ThreatMatch::new("persistence", 8, "Persistence"),
        ThreatMatch::new("obfuscation", 5, "Obfuscation"),
    ];
    let max = ThreatMatch::max_score(&matches);
    let level = ThreatLevel::from_score(max);
    let response = level.default_response();

    assert_eq!(max, 10);
    assert_eq!(level, ThreatLevel::High);
    assert_eq!(response, ThreatResponse::Block);
}
