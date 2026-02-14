/*
 * PipeGuard YARA Rules — npm Supply Chain Attacks
 * Severity: 8
 * Rules: 2
 */

rule npm_malicious_install_script {
    meta:
        severity = 8
        description = "npm install script with malicious command"
        category = "supply_chain"
    strings:
        $scripts = "\"scripts\""
        $postinstall = "postinstall" nocase
        $preinstall = "preinstall" nocase
        $curl = "curl" nocase
        $wget = "wget" nocase
        $aria2c = "aria2c" nocase
        $axel = "axel" nocase
        $bash = /\|\s*bash/
        $sh = /\|\s*sh/
    condition:
        $scripts and ($postinstall or $preinstall) and ($curl or $wget or $aria2c or $axel) and ($bash or $sh)
}

rule npm_node_exec_injection {
    meta:
        severity = 8
        description = "npm node -e with command injection"
        category = "supply_chain"
    strings:
        $node_e = /node\s+-e/
        $child_process = "child_process"
        $exec = ".exec"
        $curl = "curl" nocase
        $wget = "wget" nocase
        $aria2c = "aria2c" nocase
        $eval = "eval"
    condition:
        $node_e and ($child_process and $exec) or ($node_e and ($curl or $wget or $aria2c) and $eval)
}
