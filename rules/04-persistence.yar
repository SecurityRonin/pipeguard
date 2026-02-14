/*
 * PipeGuard YARA Rules — Persistence Mechanisms
 * Severity: 7-8
 * Rules: 4
 */

rule persistence_launchagent {
    meta:
        severity = 8
        description = "macOS LaunchAgent persistence"
        category = "persistence"
    strings:
        $la_path1 = "~/Library/LaunchAgents"
        $la_path2 = "/Library/LaunchAgents"
        $la_path3 = "LaunchAgents/"
        $plist = ".plist"
    condition:
        any of ($la_path*) and $plist
}

rule persistence_crontab {
    meta:
        severity = 8
        description = "Crontab persistence"
        category = "persistence"
    strings:
        // Match write operations: crontab file, crontab -e/-r, crontab - (stdin)
        // Excludes: crontab -l (list)
        $cron_write = /crontab\s+[^-l\s]|crontab\s+-[erw]|crontab\s+-\s*$/
        $cron_pipe = /\|\s*crontab\s*-?\s*$/
        $cron_etc = "/etc/crontab"
        $cron_spool = "/var/spool/cron"
    condition:
        any of them
}

rule persistence_bashrc {
    meta:
        severity = 7
        description = "Shell RC file modification"
        category = "persistence"
    strings:
        $rc1 = ".bashrc"
        $rc2 = ".zshrc"
        $rc3 = ".profile"
        $rc4 = ".bash_profile"
        $write = />>|echo.*>>/
    condition:
        any of ($rc*) and $write
}

rule persistence_login_hook {
    meta:
        severity = 8
        description = "macOS login hook persistence"
        category = "persistence"
    strings:
        $hook = "LoginHook"
        $defaults = "defaults write"
    condition:
        $hook or ($defaults and /loginwindow/)
}
