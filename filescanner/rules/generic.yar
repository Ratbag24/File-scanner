// Bundled YARA rules. Drop more .yar files into this folder, or point the
// FILESCANNER_RULES environment variable at a folder of community rules
// (for example https://github.com/Yara-Rules/rules or https://github.com/Neo23x0/signature-base).
//
// Supported meta fields:
//   severity    = info | low | medium | high | critical
//   category    = malware | hacktool | heuristic
//   description = text shown to the user

rule Base64_Encoded_Program
{
    meta:
        description = "Contains a Windows program hidden as base64 text"
        severity = "high"
        category = "heuristic"
    strings:
        $mz1 = "TVqQAAMAAAAEAAAA"
        $mz2 = "TVpQAAIAAAAEAA8A"
        $mz3 = "TVoAAAAAAAAAAAAA"
        $mz4 = "TVpBUlVIieVIgewgAAAA"
    condition:
        not uint16(0) == 0x5A4D and any of them
}

rule Browser_Credential_Theft
{
    meta:
        description = "Reads saved browser passwords and cookies (info-stealer behaviour)"
        severity = "high"
        category = "heuristic"
    strings:
        $p1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii wide nocase
        $p2 = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" ascii wide nocase
        $p3 = "\\BraveSoftware\\Brave-Browser\\User Data" ascii wide nocase
        $p4 = "logins.json" ascii wide
        $p5 = "\\Local State" ascii wide
        $k1 = "encrypted_key" ascii wide
        $k2 = "CryptUnprotectData" ascii wide
    condition:
        2 of ($p*) and 1 of ($k*)
}

rule Discord_Token_Grabber
{
    meta:
        description = "Steals Discord login tokens"
        severity = "high"
        category = "heuristic"
    strings:
        $d1 = "\\discord\\Local Storage\\leveldb" ascii wide nocase
        $d2 = "discordapp.com/api/webhooks" ascii wide nocase
        $d3 = "discord.com/api/webhooks" ascii wide nocase
        $d4 = "dQw4w9WgXcQ:" ascii wide
    condition:
        $d1 and ($d2 or $d3 or $d4)
}

rule Crypto_Wallet_Theft
{
    meta:
        description = "Looks for cryptocurrency wallets to steal"
        severity = "high"
        category = "heuristic"
    strings:
        $w1 = "\\Exodus\\exodus.wallet" ascii wide nocase
        $w2 = "\\Electrum\\wallets" ascii wide nocase
        $w3 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide   // MetaMask extension id
        $w4 = "\\Ethereum\\keystore" ascii wide nocase
        $w5 = "\\atomic\\Local Storage\\leveldb" ascii wide nocase
    condition:
        2 of them
}

rule Reverse_Shell
{
    meta:
        description = "Opens a remote-control connection back to an attacker"
        severity = "high"
        category = "heuristic"
    strings:
        $s1 = "/bin/sh -i" ascii
        $s2 = "bash -i >& /dev/tcp/" ascii
        $s3 = "New-Object System.Net.Sockets.TCPClient" ascii wide nocase
        $s4 = "socket.socket(socket.AF_INET" ascii
        $e1 = "GetStream()" ascii wide
        $e2 = "subprocess" ascii
        $e3 = "dup2" ascii
    condition:
        $s2 or ($s3 and $e1) or ($s4 and ($e2 or $e3) and $s1)
}

rule Autorun_Inf
{
    meta:
        description = "USB autorun file that starts a program automatically"
        severity = "medium"
        category = "heuristic"
    strings:
        $a = "[autorun]" ascii nocase
        $b = /open\s*=/ ascii nocase
        $c = /shellexecute\s*=/ ascii nocase
    condition:
        filesize < 10KB and $a and ($b or $c)
}

rule Hacktool_Game_Cheat
{
    meta:
        description = "Game cheat / trainer (often bundled with malware)"
        severity = "medium"
        category = "hacktool"
    strings:
        $c1 = "aimbot" ascii wide nocase
        $c2 = "wallhack" ascii wide nocase
        $c3 = "esp_enabled" ascii wide nocase
        $c4 = "triggerbot" ascii wide nocase
        $c5 = "Cheat Engine" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
