
import "pe"

rule MAL_WIN_Darkgate_Loader_PE
{
    meta:   
        description = "Detects a variant of Darkgate Loader"
        author = "Lucas Matias"
        date = "25-09-2025"
        reference = "https://www.splunk.com/en_us/blog/security/enter-the-gates-an-analysis-of-the-darkgate-autoit-loader.html"                   
        hash = "0efb25b41efef47892a1ed5dfbea4a8374189593217929ef6c46724d0580db23"
    strings:        
         
        /*  Function names  */
        $fn1  = "GetCommandLineA" ascii
        $fn2  = "TerminateProcess" ascii
        $fn3  = "GetCurrentProcess" ascii
        $fn4  = "GetProcAddress" ascii
        $fn5  = "GetModuleHandleW" ascii 
        $fn6  = "WriteProcessMemory" ascii


        $fnet1 = "WinHttpQueryDataAvailable" ascii
        $fnet2 = "WinHttpConnect" ascii
        $fnet3 = "WinHttpSendRequest" ascii
        $fnet4 = "WinHttpCloseHandle" ascii
        $fnet5 = "WinHttpOpenRequest" ascii
        $fnet6 = "WinHttpReadData" ascii
        $fnet7 = "WinHttpOpen" ascii
        $fnet8 = "WinHttpReceiveResponse" ascii

        /*  Network related  */
        $net1  = "WinHTTP Example/1.0" ascii
        $net2  = "WINHTTP.dll" ascii
               

        /*  Anti-debug related  */
        $db_prefix = "[AntiDebug] "
        $adb1  = "[AntiDebug] [specs_check()] [ERROR]:" ascii
        $adb2  = "[AntiDebug] [user_check()] Username:" ascii
        $adb3  = "[AntiDebug] [user_check()] Username check passed!" ascii
        $adb4  = "[AntiDebug] [hwid_check()] [ERROR]:" ascii
        $adb5  = "[AntiDebug] [name_check()] Computer Name:" ascii
        $adb6  = "[AntiDebug] [name_check()] Computer Name check passed!" ascii
        $adb7  = "[AntiDebug] [name_check()] [ERROR]:" ascii
        $adb8  = "[AntiDebug] [dll_check()] [ERROR]: Virtual Machine Detected: VMWare: from" ascii
        $adb9  = "[AntiDebug] [dll_check()] DLL Check for VMWare passed!" ascii
        $adb10 = "[AntiDebug] [dll_check()] [ERROR]: Virtual Machine Detected: VirtualBox: from" ascii
        $adb11 = "[AntiDebug] [dll_check()] DLL Check for VirtualBox passed]" ascii
        $adb12 = "[AntiDebug] [dll_check()] [ERROR]:" ascii
        $adb13 = "[AntiDebug] [specs_check()] [ERROR]: Invalid RAM Amount" ascii
        $adb14 = "[AntiDebug] [specs_check()] Ram check passed!" ascii
        $adb15 = "[AntiDebug] [specs_check()] [ERROR]: Invalid CPU Count" ascii
        $adb16 = "[AntiDebug] [specs_check()] CPU check passed!" ascii
        $adb17 = "[AntiDebug] [specs_check()] [ERROR]:" ascii

        /*  PC names  */
        $pc1  = "ORELEEPCI" ascii
        $pc2  = "JULIA-PCI" ascii
        $pc3  = "LUCAS-PCI" ascii
        $pc4  = "NETTYPC" ascii
        $pc5  = "DESKTOP-BUGIO" ascii
        $pc6  = "DESKTOP-CBGPFEE" ascii
        $pc7  = "SERVER-PC" ascii
        $pc8  = "TIQIYLA9TW5M" ascii
        $pc9  = "DESKTOP-KALVINO" ascii
        $pc10 = "COMPNAME_4047" ascii
        $pc11 = "DESKTOP-19OLLTD" ascii
        $pc12 = "DESKTOP-DE369SE" ascii
        $pc13 = "EA8C2E2A-D017-4" ascii
        $pc14 = "AIDANPC" ascii
        $pc15 = "ACEPC" ascii
        $pc16 = "MIKE-PC" ascii
        $pc17 = "DESKTOP-IAPKN1P" ascii
        $pc18 = "DESKTOP-NTU7VUO" ascii
        $pc19 = "LOUISE-PC" ascii
        $pc20 = "T00917" ascii
        $pc21 = "test42" ascii
        $pc22 = "DESKTOP-CM0DAW8" ascii

        /*  Possible Usernames  */
        $user1  = "BEE7370C-8C0C-4" ascii
        $user2  = "DESKTOP-NAKFFMT" ascii
        $user3  = "WIN-5E07COS9ALR" ascii
        $user4  = "B30F0242-1C6A-4" ascii
        $user5  = "DESKTOP-VRSQLAG" ascii
        $user6  = "Q9IATRKPRH" ascii
        $user7  = "XC64ZB" ascii
        $user8  = "DESKTOP-D019GDM" ascii
        $user9  = "DESKTOP-WI8CLET" ascii
        $user10 = "SERVER1" ascii
        $user11 = "LISA-PC" ascii
        $user12 = "JOHN-PC" ascii
        $user13 = "DESKTOP-B0T93D6" ascii
        $user14 = "DESKTOP-1PYKP29" ascii
        $user15 = "DESKTOP-1Y2433R" ascii
        $user16 = "WILEYPC" ascii
        $user17 = "6C4E733F-C2D9-4" ascii
        $user18 = "RALPHS-PC" ascii
        $user19 = "DESKTOP-WG3MYJS" ascii
        $user20 = "DESKTOP-7XC6GEZ" ascii
        $user21 = "DESKTOP-5OV9S0O" ascii
        $user22 = "QarZhrdBpj" ascii
        $user23 = "ARCHIBALDPC" ascii
        $user24 = "d1bnJkfVlH" ascii
        $user25 = "WDAGUtilityAccount" ascii
        $user26 = "patex" ascii
        $user27 = "RDhJ0CNFevzX" ascii
        $user28 = "kEecfMwgj" ascii
        $user29 = "Frank" ascii
        $user30 = "8Nl0ColNQ5bq" ascii
        $user31 = "george" ascii
        $user32 = "PxmdUOpVyx" ascii
        $user33 = "8VizSM" ascii
        $user34 = "w0fjuOVmCcP5A" ascii
        $user35 = "PqONjHVwexsS" ascii
        $user36 = "3u2v9m8" ascii
        $user37 = "Julia" ascii
        $user38 = "HEUeRzl" ascii
        $user39 = "server" ascii
        $user40 = "BvJChRPnsxn" ascii
        $user41 = "Harry Johnson" ascii
        $user42 = "SqgFOf3G" ascii
        $user43 = "Lucas" ascii
        $user44 = "PateX" ascii
        $user45 = "h7dk1xPr" ascii
        $user46 = "Louise" ascii
        $user47 = "User01" ascii
        $user48 = "RGzcBUyrznReg" ascii
        $user49 = "OgJb6GqgK0O" ascii

        /*  File paths  */
        $path1  = "C:\\Users\\Alex\\Documents\\repos\\repos\\t34_new\\users\\MAGA\\cryptbase_meow\\x64\\Release\\cryptbase.pdb" ascii nocase
        $path2  = "C:\\Users\\Alex\\Documents\\repos\\repos\\t34_new\\users\\my\\selfupdate\\Dropper\\wldp\\x64\\Release\\wldp.pd" ascii nocase
        $path3  = "-SilentCleanup.xml.txt" ascii        
        $path4  = "rundll32 cleanhelper.dll T34 /k funtic321 1" ascii
        $path5  = "abdwufkw/modules/legacy_l1.png" ascii
        $path6  = "abdwufkw/modules/cleanhelper.png" ascii
        $path7  = "abdwufkw/modules/runsysclean.png" ascii
        $path8 = "\\..\\Local\\Microsoft\\WindowsApps\\cryptbase.dll" ascii wide nocase
        $path9 = "\\..\\Local\\Microsoft\\WindowsApps\\wldp.dll" ascii wide nocase
        $path10 = "\\..\\Local\\Microsoft\\WindowsApps\\api-ms-win-core-kernel32-legacy-l1.dll" ascii wide nocase
        $path11 = "\\..\\Local\\Microsoft\\WindowsApps\\cleanhelper.dll" ascii wide nocase
        $path12 = "\\..\\Local\\Microsoft\\WindowsApps\\api-ms-win-core-kernel32-legacy-l1-1-1.dll" ascii wide nocase
        $path13 = "\\..\\Local\\Microsoft\\WindowsApps\\runsysclean.dll" ascii wide nocase
        $path14 = "\\..\\Local\\Microsoft\\WindowsApps\\cleanhelper.pdf" ascii wide nocase
        $path15 = "minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h" ascii wide

        /*  Miscellaneous / other strings  */
        $misc1  = "Meow-meow!" ascii
        $misc2  = "Good luck!" ascii
        $misc3  = "Not compatable!" ascii            
        $misc4 = "ApiSet Stub DLL" ascii
        $misc5 = "Failed to get appdata variable" ascii 
        $misc6 = "Washington1" ascii        
        $misc7  = "20180914093837Z" ascii
        $misc8  = "20180915093837Z0w0=" ascii



                
    condition:
        pe.is_pe and
        filesize < 1300KB and 
        pe.imports("WINHTTP.dll") and
        1 of ($pc*, $user*) and
        ( #db_prefix > 1 or any of ($adb*) ) and
        any of ($path*) and
        any of ($net*, $fnet*) and
        (1 of ($fn*) or 1 of ($misc*))
		
        

}
