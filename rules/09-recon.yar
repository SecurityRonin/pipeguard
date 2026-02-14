/*
 * PipeGuard YARA Rules — Environment/Credential Harvesting
 * Severity: 6-8
 * Rules: 2
 */

rule env_harvesting {
    meta:
        severity = 6
        description = "Environment variable harvesting"
        category = "recon"
    strings:
        $env1 = "printenv"
        $env2 = "$HOME"
        $env3 = "$USER"
        $env4 = "$PATH"
        $env5 = "env |"
        $send = /curl|wget|nc|aria2c|axel|httpie/
    condition:
        2 of ($env*) and $send
}

rule credential_harvesting {
    meta:
        severity = 8
        description = "Credential file access"
        category = "recon"
    strings:
        $aws = ".aws/credentials"
        $ssh = ".ssh/"
        $gpg = ".gnupg/"
        $npm = ".npmrc"
        $docker = ".docker/config.json"
        $kube = ".kube/config"
    condition:
        any of them
}
