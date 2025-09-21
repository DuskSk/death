import "pe"

rule MAL_WIN_AsyncRat_Trojan_PE
{
  meta:
    description = "Detects a variant of Asyncrat Remote Access Trojan"
    author = "Lucas Matias"
    date = "2025-09-21"
    reference = "https://www.esentire.com/blog/exploring-asyncrat-and-infostealer-plugin-delivery-through-phishing-emails"
    hash = "8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb"

  strings:
    // commandline related 
    $cmd1 = "root\\SecurityCenter2"
    $cmd2 = "Select * from AntivirusProduct"
    $cmd3 = "/c taskkill.exe /im chrome.exe /f"
    $cmd4 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii wide // "Software\\Microsoft\\Windows\\CurrentVersion\\Run" invertido
    $cmd5 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" ascii wide
    $cmd6 = "127.0.0.1" ascii wide
    $cmd7 = "Reset Hosts succeeded!"

    //  browser extensions / paths 
    $ext1  = "\extensions\webextension@metamask.io.xpi"  wide ascii
    $ext2  = "\\Mozilla\\Firefox\\Profiles" wide ascii
    $ext3  = "fhbohimaelbohpjbbldcngcnapndodjp"  wide ascii
    $ext4  = "fhbohimaelbohpjbbldcngcnapndodjp"  wide ascii
    $ext5  = "ibnejdfjmmkpcnlpebklmnkoeoihofec" wide ascii
    $ext6  = "jiidiaalihmmhddjgbnbgdfflelocpak" wide ascii
    $ext7  = "hnfanknocfeofbddgcijnmhnfnkdnaad" wide ascii
    $ext8  = "fnjhmkhhmkbjkkabndcnnogagogbneec" wide ascii
    $ext9  = "egjidjbpglichdcondbcbdnbeeppgdph" wide ascii
    $ext10 = "jkjgekcefbkpogohigkgooodolhdgcda" wide ascii
    $ext11 = "bhghoamapcdpbohphigoooaddinpkbai" wide ascii
    $ext12 = "bhghoamapcdpbohphigoooaddinpkbai" wide ascii
    $ext13 = "ocglkepbibnalbgmbachknglpdipeoio" wide ascii

    // function names / MISC
    $fn1  = "WHKEYBOARDLL"
    $fn2  = "WM_KEYDOWN"
    $fn3  = "LASTINPUTINFO"
    $fn4  = "SetWindowsHookEx"
    $fn5  = "CreateMutex"
    $fn6  = "CreateSubKey"
    $fn7  = "DeleteSubKey"
    $fn8  = "OpenSubKey"
    $fn9  = "RegistryKey"
    $fn10 = "DetectSandboxie"
    $fn11 = "CheckRemoteDebuggerPresent"
    $fn12 = "isDebuggerPresent"
    $fn13 = "HMACSHA256"
    $fn14 = "FromBase64String"
    $fn15 = "ToBase64String"
    $fn16 = "ReadString"
    $fn17 = "DownloadString"
    $fn18 = "DownloadFile"
    $fn19 = "InstallFile"
    $fn20 = "DecodeFromFile"
    $fn21 = "SaveBytesToFile"
    $fn22 = "WebBrowserPass"
    $fn23 = "DicordTokens"

    // AsyncRAT getters/setters 
    $gs1  = "get_SslClient"
    $gs2  = "set_SslClient"
    $gs3  = "get_TcpClient"
    $gs4  = "set_TcpClient"
    $gs5  = "get_Offset"
    $gs6  = "set_Offset"
    $gs7  = "set_UseShellExecute"
    $gs8  = "get_Connected"
    $gs9  = "get_IsConnected"
    $gs10 = "set_IsConnected"
    $gs11 = "get_FileName"
    $gs12 = "set_FileName"
    $gs13 = "get_MachineName"
    $gs14 = "get_OSFullName"
    $gs15 = "get_FullName"
    $gs16 = "get_UserName"
    $gs17 = "get_ProcessName"

    // backing fields 
    $bk1  = "<SendSync>k__BackingField"
    $bk2  = "<IsConnected>k__BackingField"
    $bk3  = "<KeepAlive>k__BackingField"
    $bk4  = "<HeaderSize>k__BackingField"
    $bk5  = "<Ping>k__BackingField"
    $bk6  = "<ActivatePong>k__BackingField"
    $bk7  = "<Interval>k__BackingField"
    $bk8  = "<Buffer>k__BackingField"
    $bk9  = "<Offset>k__BackingField"
    $bk10 = "<SslClient>k__BackingField"
    $bk11 = "<TcpClient>k__BackingField"

    //  crypto wallet names 
    $wal1  = "Meta_Firefox" ascii wide
    $wal2  = "MetaFirefox" ascii wide
    $wal3  = "Meta_Chrome" ascii wide
    $wal4  = "MetaChrome" ascii wide
    $wal5  = "Meta_Brave" ascii wide
    $wal6  = "Meta_Opera" ascii wide
    $wal7  = "Meta_OperaGX" ascii wide
    $wal8  = "MetaOperaGX" ascii wide
    $wal9  = "Phantom_Chrome" ascii wide
    $wal10 = "PhantomChrome" ascii wide
    $wal11 = "Phantom_Brave" ascii wide
    $wal12 = "PhantomBrave" ascii wide
    $wal13 = "BitPay_Chrome" ascii wide
    $wal14 = "BitPayChrome" ascii wide
    $wal15 = "Binance_Chrome" ascii wide
    $wal16 = "BinanceChrome" ascii wide
    $wal17 = "Binance_Edge" ascii wide
    $wal18 = "BinanceEdge" ascii wide
    $wal19 = "TronLinkChrome" ascii wide
    $wal20 = "Exodus_Chrome" ascii wide
    $wal21 = "BitKeep_Chrome" ascii wide
    $wal22 = "BitKeepChrome" ascii wide
    $wal23 = "Coinbase_Chrome" ascii wide
    $wal24 = "CoinbaseChrome" ascii wide
    $wal25 = "Ronin_Chrome" ascii wide
    $wal26 = "RoninChrome" ascii wide
    $wal27 = "Trust_Chrome" ascii wide
    $wal28 = "TrustChrome" ascii wide
    $wal29 = "F2a_Chrome" ascii wide
    $wal30 = "Ergo_Wallet" ascii wide
    $wal31 = "ErgoWallet" ascii wide
    $wal32 = "\\Ledger Live" ascii wide
    $wal33 = "Ledger_Live" ascii wide
    $wal34 = "LedgerLive" ascii wide
    $wal35 = "Bitcoin_Core" ascii wide
    $wal36 = "Bitcoin Core" ascii wide
    $wal37 = "BoolWallets" ascii wide

    // UTF-16-only 
    $u1  = "%AppData%" wide
    $u2  = "START \"\" \"" wide
    $u3  = "DEL \"" wide
    $u4  = "SbieDll.dll" wide
    $u5  = "cmd.exe" wide
    $u6  = " Blocked!" wide
    $u7  = "[SPACE]" wide
    $u8  = "[ENTER]" wide
    $u9  = "[ESC]" wide
    $u10 = "[CTRL]" wide
    $u11 = "[Shift]" wide
    $u12 = "[Back]" wide
    $u13 = "[WIN]" wide
    $u14 = "[Tab]" wide
    $u15 = "[CAPSLOCK: OFF]" wide
    $u16 = "[CAPSLOCK: ON]" wide
    $u17 = "\\Log.tmp" wide
    $u18 = "\\drivers\\etc" wide
    $u19 = "\\hosts.backup" wide
    $u20 = "\\hosts" wide
    $u21 = "Stub.exe" wide
    $u22 = "masterKey can not be null or empty." wide

    // regex (SHA256)
    $re1 = /[a-fA-F0-9]{64}/

  condition:
    pe.is_pe and
    filesize < 100KB and
    1 of ($cmd*) and
    2 of ($ext*) and
    3 of ($fn*) and
    1 of ($gs*) and
    1 of ($bk*) and
    1 of ($wal*) and
    3 of ($u*) and
    (#re1 > 0 or true)   // regex optional
}
