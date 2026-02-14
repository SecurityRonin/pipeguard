/*
 * PipeGuard YARA Rules — Crypto Wallet Targeting
 * Severity: 9
 * Rules: 2
 */

rule crypto_wallet_theft {
    meta:
        severity = 9
        description = "Cryptocurrency wallet targeting"
        category = "crypto_theft"
    strings:
        $wallet1 = "wallet.dat" nocase
        $wallet2 = "keystore" nocase
        $wallet3 = "electrum" nocase
        $wallet4 = "exodus" nocase
        $wallet5 = "atomic" nocase
        $wallet6 = "metamask" nocase
        $wallet7 = "phantom" nocase
        $wallet8 = "solflare" nocase
        $seed = "seed" nocase
        $mnemonic = "mnemonic" nocase
    condition:
        any of ($wallet*) or ($seed and $mnemonic)
}

rule crypto_browser_extension {
    meta:
        severity = 9
        description = "Browser crypto extension targeting"
        category = "crypto_theft"
    strings:
        $ext_path = "Extensions"
        $chrome = "Google/Chrome"
        $brave = "BraveSoftware"
        $ext_id1 = "nkbihfbeogaeaoehlefnkodbefgpgknn"  // MetaMask
        $ext_id2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa"  // Phantom
    condition:
        $ext_path and (any of ($chrome, $brave) or any of ($ext_id*))
}
