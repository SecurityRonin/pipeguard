/*
 * PipeGuard YARA Rules — AMOS/ClickFix IOCs
 * Severity: 10
 * Rules: 2
 */

rule amos_stealer_indicators {
    meta:
        severity = 10
        description = "AMOS Stealer indicators"
        category = "amos"
    strings:
        $amos1 = "Atomic macOS Stealer" nocase
        $amos2 = "atomicstealer" nocase
        $amos3 = /keychain.{0,32}dump/i
        $amos4 = "security find-generic-password"
        $amos5 = "security dump-keychain"
    condition:
        any of them
}

rule clickfix_indicators {
    meta:
        severity = 10
        description = "ClickFix campaign indicators"
        category = "clickfix"
    strings:
        $cf1 = "I'm not a robot" nocase
        $cf2 = "verify you are human" nocase
        $cf3 = "press and hold" nocase
        $cf4 = "Windows + R" nocase
        $copy_paste = /copy.*paste|paste.*terminal/i
    condition:
        any of ($cf*) or $copy_paste
}
