/*
 * PipeGuard YARA Rules — Privilege Escalation
 * Severity: 7-8
 * Rules: 3
 */

rule privesc_sudo_stdin {
    meta:
        severity = 7
        description = "Sudo password from stdin"
        category = "privilege_escalation"
    strings:
        $sudo_s = "sudo -S"
        $echo_sudo = /echo.{0,64}\|.{0,64}sudo/
    condition:
        any of them
}

rule privesc_osascript_admin {
    meta:
        severity = 7
        description = "AppleScript admin privilege request"
        category = "privilege_escalation"
    strings:
        $osascript = "osascript"
        $admin = "administrator privileges"
        $password = "with prompt"
    condition:
        $osascript and ($admin or $password)
}

rule privesc_dscl {
    meta:
        severity = 8
        description = "User account manipulation via dscl"
        category = "privilege_escalation"
    strings:
        $dscl = "dscl"
        $create = "create"
        $admin = "admin"
    condition:
        $dscl and $create and $admin
}
