/*
 * PipeGuard YARA Rules — Staged Downloads
 * Severity: 7-8
 * Rules: 3
 */

rule staged_download_pipe {
    meta:
        severity = 7
        description = "Script downloads and pipes to shell interpreter"
        category = "staged"
    strings:
        $dl1 = "curl" nocase
        $dl2 = "wget" nocase
        $dl3 = "fetch" nocase
        $dl4 = "aria2c" nocase
        $dl5 = "axel" nocase
        $dl6 = "httpie" nocase
        $pipe1 = "| bash"
        $pipe2 = "| sh"
        $pipe3 = "| zsh"
        $pipe4 = "| python"
        $pipe5 = "| perl"
    condition:
        any of ($dl*) and any of ($pipe*)
}

rule staged_download_exec {
    meta:
        severity = 7
        description = "Script downloads file then executes it"
        category = "staged"
    strings:
        $dl1 = "curl" nocase
        $dl2 = "wget" nocase
        $dl3 = "fetch" nocase
        $dl4 = "aria2c" nocase
        $dl5 = "axel" nocase
        $dl6 = "httpie" nocase
        $dl7 = "scp" nocase
        $dl8 = "rsync" nocase
        $exec1 = "&& bash"
        $exec2 = "&& sh"
        $exec3 = "&& zsh"
        $exec4 = "; bash"
        $exec5 = "; sh"
        $exec6 = "; zsh"
        $exec7 = "&& chmod +x"
        $exec8 = "; chmod +x"
        $exec9 = "&& ./"
        $exec10 = "; ./"
    condition:
        any of ($dl*) and any of ($exec*)
}

rule multi_stage_download {
    meta:
        severity = 8
        description = "Multiple download commands suggesting staged attack"
        category = "staged"
    strings:
        $dl = /curl|wget|fetch|aria2c|axel|httpie|scp|rsync/ nocase
    condition:
        #dl >= 3
}
