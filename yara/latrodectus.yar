import "pe"

rule MAL_WIN_Latrodectus_Backdoor_PE
{
    meta:   
        description = "Detects a variant of Latrodectus Backdoor"
        author = "Lucas Matias"
        date = "26-09-2025"
        reference = ""                   
        hash = "aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c"
    strings:
        /*  Registry functions   */
        $regfn1  = "RrCreateKey" ascii wide
        $regfn2  = "RrGetSubKeys" ascii wide
        $regfn3  = "RrGetValueCount" ascii wide
        $regfn4  = "RrGetSubkeyCount" ascii wide
        $regfn5  = "RrEnumerateSubkey" ascii wide
        $regfn6  = "RrOpenKey" ascii wide
        $regfn7  = "RrGetValue" ascii wide
        $regfn8  = "RrOpenHive" ascii wide
        $regfn9  = "RrOpenKeyWithHive" ascii wide
        $regfn10 = "RrGetSubKeysWithMetaData" ascii wide
        $regfn11 = "RrInitialize" ascii wide
        $regfn12 = "RrReferenceHive" ascii wide
        $regfn13 = "RrSetFiles" ascii wide
        $regfn14 = "RrDestroyHiveList on gHiveList" ascii wide
        $regfn15 = "RrHiveAllocAndInit" ascii wide
        $regfn16 = "RrKeyAllocAndInit" ascii wide
        $regfn17 = "RrRecDoOperationOnSubkeys" ascii wide
        $regfn18 = "RrCloseHiveHandle" ascii wide
        $regfn19 = "RrOpenHiveHandle" ascii wide
        $regfn20 = "RrKeyInit" ascii wide
        $regfn21 = "RrFindKey" ascii wide
        $regfn22 = "RrReadHeader" ascii wide
        $regfn23 = "RrReadFromHive" ascii wide
        $regfn24 = "RrReadValueKeyFromOffset" ascii wide
        $regfn25 = "RrReadValueKeyFromOffsetWithoutData" ascii wide
        $regfn26 = "RrReadDataBlockKeyFromOffset" ascii wide
        $regfn27 = "RrGetKeyElem" ascii wide
        $regfn28 = "RrHiveHandleInit" ascii wide
        $regfn29 = "RrHiveInit" ascii wide
        $regfn30 = "RrCheckHeader" ascii wide
        $regfn31 = "RrSendOpenedHiveToKernel" ascii wide
        $regfn32 = "RrSendHiveToCloseToKernel" ascii wide         
        

        /*  Network related / IPC  */
        $net1 = "Init client communication port for avc3 communication" ascii
        $net2 = "_PortAvailable" ascii
        $net3 = "_SrvRequestPresent" ascii
        $net4 = "_InitSrvRequest" ascii
        $net5 = "_ResponseGiven" ascii
        $net6 = "_clientDisconnected" ascii
        $net7 = "_srvToClient" ascii
        $net8 = "_clientToSrv" ascii
        $net9 = "_TearDown" ascii

        /*  Paths  */
        $path1  = "E:\\builds\\ARK23181_2\\trufos_dll\\decrypt.c" ascii wide nocase
        $path2  = "E:\\builds\\ARK23181_2\\trufos_dll\\fileLists.c" ascii wide nocase
        $path3  = "E:\\builds\\ARK23181_2\\trufos_dll\\fileTable.c" ascii wide nocase
        $path4  = "E:\\builds\\ARK23181_2\\trufos_dll\\fileWalk.c" ascii wide nocase
        $path5  = "E:\\builds\\ARK23181_2\\trufos_dll\\hiddenContent.c" ascii wide nocase
        $path6  = "E:\\builds\\ARK23181_2\\trufos_dll\\hiddenFiles.c" ascii wide nocase
        $path7  = "E:\\builds\\ARK23181_2\\trufos_dll\\hiddenFilesRaw.c" ascii wide nocase
        $path8  = "E:\\builds\\ARK23181_2\\trufos_dll\\hiddenStreams.c" ascii wide nocase
        $path9  = "E:\\builds\\ARK23181_2\\trufos_dll\\hiddenTrfRawContent.c" ascii wide nocase
        $path10 = "E:\\builds\\ARK23181_2\\trufos_dll\\impthread.c" ascii wide nocase
        $path11 = "E:\\builds\\ARK23181_2\\trufos_dll\\invName.c" ascii wide nocase
        $path12 = "E:\\builds\\ARK23181_2\\trufos_dll\\killFile.c" ascii wide nocase
        $path13 = "E:\\builds\\ARK23181_2\\trufos_dll\\lockFile.c" ascii wide nocase
        $path14 = "E:\\builds\\ARK23181_2\\trufos_dll\\misc.c" ascii wide nocase
        $path15 = "E:\\builds\\ARK23181_2\\trufos_dll\\miscCommon.c" ascii wide nocase
        $path16 = "E:\\builds\\ARK23181_2\\trufos_dll\\prflibmain.c" ascii wide nocase
        $path17 = "E:\\builds\\ARK23181_2\\trufos_dll\\rebcmd.c" ascii wide nocase
        $path18 = "E:\\builds\\ARK23181_2\\trufos_dll\\registry.c" ascii wide nocase
        $path19 = "E:\\builds\\ARK23181_2\\trufos_dll\\rwsect.c" ascii wide nocase
        $path20 = "E:\\builds\\ARK23181_2\\trufos_dll\\tdlist.c" ascii wide nocase
        $path21 = "E:\\builds\\ARK23181_2\\trufos_dll\\trufos_dll.c" ascii wide nocase
        $path22 = "E:\\builds\\ARK23181_2\\trufos_dll\\volinfo.c" ascii wide nocase
        $path23 = "E:\\builds\\ARK23181_2\\rawregistry\\rrRawRegistry.c" ascii wide nocase
        $path24 = "E:\\builds\\ARK23181_2\\rawregistry\\rrKey.c" ascii wide nocase
        $path25 = "E:\\builds\\ARK23181_2\\rawregistry\\rrHive.c" ascii wide nocase
        $path26 = "E:\\builds\\ARK23181_2\\bin_win7\\x64\\Release\\trufos.pdb" ascii wide nocase
        $path27 = "D:\\Build\\PETRU-DEFAULT-SOURCES\\inc\\ptportmisc.h" ascii wide nocase

        /*  Registry related  */
        $reg1 = "cmdRegModifyValue:" ascii
        $reg2 = "cmdRegDeleteValue:" ascii
        $reg3 = "cmdRegDeleteKey:" ascii
        $reg4 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" ascii wide nocase

        /*  Crypto key related   */
        $crypt1 = "Acquire user private key" ascii
        $crypt2 = "Import key" ascii
        $crypt3 = "Decrypt file" ascii
        $crypt4 = "Set crypt param" ascii
        $crypt5 = "Build invisible path" ascii

        /*  Misc *//
        $misc1 = "Trufos API" ascii wide
        $misc2 = "TRUFOS.DLL" ascii wide
        $misc3 = "Trufos" ascii wide
        $misc4 = "Init client communication port for avc3 communication" ascii         wide
        $misc5 = "RrDestroyHiveList on gHiveList" ascii  wide
        $misc6 = "Set crypt param" ascii wide
        $misc7 = "Build invisible path" ascii wide 
        


    condition:

        pe.is_pe and
        filesize < 1000KB and
        pe.exports("vgml") and
        (2 of ($regfn*) or (1 of ($regfn*) and 1 of ($reg*)) ) and
        1 of ($net*) and
        1 of ($path*) and
        any of ( $crypt*, $misc*)


}


