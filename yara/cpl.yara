import "pe"

rule MAL_WIN_Matanbuhchus_Loader_PE
{
    meta:   
        description = "My first rule detects a masqueraded CPL file Matanbuchus used recently"
        author = "Lucas Matias"
        date = "20-09-2025"
        reference = "https://github.com/pr0xylife/Matanbuchus/blob/main/Matanbuchus_07.03_2024.txt"
        hash = "1ca1315f03f4d1bca5867ad1c7a661033c49bbb16c4b84bea72caa9bc36bd98b"
    strings:
        $s1 = "AVtype_info"
        $s2 = "IsDebuggerPresent"
        $s3 = "DllRegisterServer"
        $s4 = "DllUnregisterServer"
        $s5 = "_RegisterDll@12"
        $s6 = "_UnregisterDll@4"
        $s7 = "operator<=>" fullword
        $s8 = "operator co_await"
        $s9 = "** CHOSEN_DATA_PUM"
        $s10 = "** GET_CHECKSUM **"
        $s11 = "AppPolicyGetProcessTerminationMethod"
        $s12 = "SHLWAPI.dll" fullword
        $s13 = "** StartIdle **"
        $s14 = "EmulateCallWaiting"
        //UTF16
        $s15 = "Start Monitoring A" wide
        $s16 = "WINAC_EC_CONNECTED" wide
        $s17 = "** GET_MSG_BODY **" wide
        $s18 = "Receiver - Got NAK" wide
        $s19 = "MohOverrideActionF" wide
        $s20 = "ModemControl(RKCTL" wide
    condition:
        pe.is_pe and
        filesize < 750KB and
        pe.imports("KERNEL32.dll", "IsDebuggerPresent") and
        pe.exports("DllRegisterServer") and
        all of ($s*)

}


