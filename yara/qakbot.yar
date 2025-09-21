
import "pe"

rule MAL_WIN_Qakbot_Keylogger_PE
{
    meta:   
        description = "Detects a variant of Qakbot Keylogger"
        author = "Lucas Matias"
        date = "20-09-2025"
        reference = "https://securelist.com/qbot-banker-business-correspondence/109535/ - https://securelist.com/qakbot-technical-analysis/103931"                    
        hash = "6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59"
    strings:        
         
        $s1  = "GetSystemDirectoryA"
        $s2  = "GetActiveWindow" 
        $s3  = "GetKeyState" 
        $s4  = "ProcessIdToSessionId" 
        $s5  = "SetClipboardData" 
        $s6  = "GetClipboardData" 
        $s7  = "GlobalAlloc" 
        $s8  = "VirtualProtect" 
        $s9  = "MapVirtualKeyA" 
        $s10 = "GetCurrentProces" 
        $s11 = "GetModuleHandleA" 
        $s12 = "GetModuleFileNameA" 
        $s13 = "GetFileAttributesExW"          
        $s14 = "v@TrackMouseEvent" 
        
        $s_misc_1 = "Terminate_Server"
        $s_misc_2 = "Failed to install clipboard viewer"
        $s_misc_3 = "Core Pointer"
        $s_misc_4 = "g_list_find (iw->windows, window) != NULL"
        $s_misc_5 = "DROPFILES_DND"
        $s_misc_6 = "text/uri-list"
        $s_misc_7 = "Argument domain error (DOMAIN)"
        $s_misc_8 = "Argument singularity (SIGN)"
        $s_misc_9 = "Overflow range error (OVERFLOW)"
        $s_misc_10 = "bugzilla.gnome.org"        
        
        //UTF16
        $s_utf_1 = "The GTK developer community" wide
        $s_utf_2 = "GIMP Drawing Kit" wide       
        
        
    condition:
        pe.is_pe and
        filesize < 850KB and
		(pe.imports("KERNEL32.dll", "GlobalAlloc") or pe.imports("KERNEL32.dll", "Sleep")) and
        pe.exports("Updt") and
        10 of ($s*) and
        8 of ($s_misc_*) and
        any of ($s_utf_1)

}
