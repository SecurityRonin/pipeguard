/*
 * PipeGuard YARA Rules — Base64 Obfuscation
 * Severity: 5
 * Rules: 2
 */

rule base64_decode_execute {
    meta:
        severity = 5
        description = "Base64 encoded payload with execution"
        category = "obfuscation"
    strings:
        $decode1 = "base64 -d" nocase
        $decode2 = "base64 --decode" nocase
        $decode3 = "openssl base64 -d" nocase
        $exec1 = "| bash"
        $exec2 = "| sh"
        $exec3 = "| zsh"
        $exec4 = "eval $("
        $exec5 = "eval \"$("
    condition:
        any of ($decode*) and any of ($exec*)
}

rule large_base64_blob {
    meta:
        severity = 5
        description = "Large Base64 encoded data block"
        category = "obfuscation"
    strings:
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $b64
}
