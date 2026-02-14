/*
 * PipeGuard YARA Rules — Quarantine Bypass
 * Severity: 9
 * Rules: 2
 */

rule quarantine_bypass_xattr {
    meta:
        severity = 9
        description = "Gatekeeper quarantine attribute removal"
        category = "quarantine_bypass"
    strings:
        $xattr = "xattr"
        $quarantine = "com.apple.quarantine"
        $delete = "-d"
        $recursive = "-r"
    condition:
        $xattr and $quarantine and ($delete or $recursive)
}

rule quarantine_bypass_spctl {
    meta:
        severity = 9
        description = "Gatekeeper disable via spctl"
        category = "quarantine_bypass"
    strings:
        $spctl = "spctl"
        $disable = "--master-disable"
        $add = "--add"
    condition:
        $spctl and ($disable or $add)
}
