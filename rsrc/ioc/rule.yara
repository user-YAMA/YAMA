rule APT10_ANEL_InitRoutine {
      meta:
        description = "ANEL malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "2371f5b63b1e44ca52ce8140840f3a8b01b7e3002f0a7f0d61aecf539566e6a1"

    	strings:
    		$GetAddress = { C7 45 ?? ?? 69 72 74 C7 45 ?? 75 61 6C 50 C7 45 ?? 72 6F 74 65 66 C7 45 ?? 63 74 [3-4] C7 45 ?? ?? 65 72 6E C7 45 ?? 65 6C 33 32 C7 45 ?? 2E 64 6C 6C [3-4] FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? }

    	condition:
    		$GetAddress
}

rule APT10_redleaves_strings {
      meta:
        description = "RedLeaves malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "ff0b79ed5ca3a5e1a9dabf8e47b15366c1d0783d0396af2cbba8e253020dbb34"

    	strings:
    		$v1a = "red_autumnal_leaves_dllmain.dll"
        $w1a = "RedLeavesCMDSimulatorMutex" wide

    	condition:
    		$v1a or $w1a
}

rule APT10_redleaves_dropper1 {
      meta:
        description = "RedLeaves dropper"
        author = "JPCERT/CC Incident Response Group"
        hash = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481"

     strings:
        $v1a = ".exe"
        $v1b = ".dll"
        $v1c = ".dat"
        $a2a = {E8 ?? ?? FF FF 68 ?? 08 00 00 FF}
        $d2a = {83 C2 02 88 0E 83 FA 08}
        $d2b = {83 C2 02 88 0E 83 FA 10}

     condition:
        all of them
}

rule APT10_redleaves_dropper2 {
      meta:
        description = "RedLeaves dropper"
        author = "JPCERT/CC Incident Response Group"
        hash = "3f5e631dce7f8ea555684079b5d742fcfe29e9a5cea29ec99ecf26abc21ddb74"

     strings:
        $v1a = ".exe"
        $v1b = ".dll"
        $v1c = ".dat"
        $c2a = {B8 CD CC CC CC F7 E1 C1 EA 03}
        $c2b = {68 80 00 00 00 6A 01 6A 01 6A 01 6A 01 6A FF 50}

     condition:
        all of them
}

rule APT10_redleaves_dll {
      meta:
        description = "RedLeaves loader dll"
        author = "JPCERT/CC Incident Response Group"
        hash = "3938436ab73dcd10c495354546265d5498013a6d17d9c4f842507be26ea8fafb"

     strings:
        $a2a = {40 3D ?? ?? 06 00 7C EA 6A 40 68 00 10 00 00 68 ?? ?? 06 00 6A 00 FF 15 ?? ?? ?? ?? 85 C0}

     condition:
        all of them
}

rule APT10_Himawari_strings {
      meta:
        description = "detect Himawari(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "https://www.jpcert.or.jp/present/2018/JSAC2018_01_nakatsuru.pdf"
        hash1 = "3938436ab73dcd10c495354546265d5498013a6d17d9c4f842507be26ea8fafb"

      strings:
        $h1 = "himawariA"
        $h2 = "himawariB"
        $h3 = "HimawariDemo"

      condition: all of them
}

rule APT10_Lavender_strings {
      meta:
        description = "detect Lavender(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash1 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"

      strings:
        $a1 = { C7 ?? ?? 4C 41 56 45 }
        $a2 = { C7 ?? ?? 4E 44 45 52 }

      condition: all of them
}

rule APT10_Armadill_strings {
      meta:
        description = "detect Armadill(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"

      strings:
        $a1 = { C7 ?? ?? 41 72 6D 61 }
        $a2 = { C7 ?? ?? 64 69 6C 6C }

      condition: all of them
}

rule APT10_zark20rk_strings {
      meta:
        description = "detect zark20rk(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash1 = "d95ad7bbc15fdd112594584d92f0bff2c348f48c748c07930a2c4cc6502cd4b0"

      strings:
        $a1 = { C7 ?? ?? 7A 61 72 6B }
        $a2 = { C7 ?? ?? 32 30 72 6B }

      condition: all of them
}

rule APT10_HTSrl_signed {
      meta:
        description = "HT Srl signature using APT10"
        author = "JPCERT/CC Incident Response Group"
        hash = "2965c1b6ab9d1601752cb4aa26d64a444b0a535b1a190a70d5ce935be3f91699"

    	strings:
            $c="IT"
            $st="Italy"
            $l="Milan"
            $ou="Digital ID Class 3 - Microsoft Software Validation v2"
            $cn="HT Srl"

    	condition:
        	all of them
}

rule APT10_ChChes_lnk {
      meta:
        description = "LNK malware ChChes downloader"
        author = "JPCERT/CC Incident Response Group"
        hash = "6d910cd88c712beac63accbc62d510820f44f630b8281ee8b39382c24c01c5fe"

    	strings:
    		$v1a = "cmd.exe"
     		$v1b = "john-pc"
    		$v1c = "win-hg68mmgacjc"
        $v1d = "t-user-nb"
        $v1e = "C:\\Users\\suzuki\\Documents\\my\\card.rtf" wide

    	condition:
    		$v1a and ($v1b or $v1c or $v1d) or $v1e
}

rule APT10_ChChes_strings
{
      meta:
        description = "ChChes malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "7d515a46a7f4edfbae11837324f7c56b9a8164020e32aaaa3bef7d38763dd82d "

    	strings:
    		$v1a = "/%r.html"
    		$v1b = "http://"
    		$v1c = "atan2"
    		$v1d = "_hypot"
    		$v1e = "_nextafter"
    		$d1a = { 68 04 E1 00 00 }

    	condition:
    		all of them
}

rule APT10_ChChes_powershell {
      meta:
        description = "ChChes dropper PowerShell based PowerSploit"
        author = "JPCERT/CC Incident Response Group"
        hash = "9fbd69da93fbe0e8f57df3161db0b932d01b6593da86222fabef2be31899156d"

    	strings:
    		$v1a = "Invoke-Shellcode"
    		$v1b = "Invoke-shCdpot"
    		$v1c = "invoke-ExEDoc"

    	condition:
    		$v1c and ($v1a or $v1b)
}

rule APT29_wellmess_pe {
      meta:
        description = "detect WellMess in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash1 = "0322c4c2d511f73ab55bf3f43b1b0f152188d7146cc67ff497ad275d9dd1c20f"
        hash2 = "8749c1495af4fd73ccfc84b32f56f5e78549d81feefb0c1d1c3475a74345f6a8 "

      strings:
        $botlib1 = "botlib.wellMess" ascii
        $botlib2 = "botlib.Command" ascii
        $botlib3 = "botlib.Download" ascii
        $botlib4 = "botlib.AES_Encrypt" ascii
        $dotnet1 = "WellMess" ascii
        $dotnet2 = "<;head;><;title;>" ascii wide
        $dotnet3 = "<;title;><;service;>" ascii wide
        $dotnet4 = "AES_Encrypt" ascii

      condition: (uint16(0) == 0x5A4D) and (all of ($botlib*) or all of ($dotnet*))
}

rule APT29_wellmess_elf {
      meta:
        description = "ELF_Wellmess"
        author = "JPCERT/CC Incident Response Group"
        hash = "00654dd07721e7551641f90cba832e98c0acb030e2848e5efc0e1752c067ec07"

      strings:
        $botlib1 = "botlib.wellMess" ascii
        $botlib2 = "botlib.Command" ascii
        $botlib3 = "botlib.Download" ascii
        $botlib4 = "botlib.AES_Encrypt" ascii

      condition: (uint32(0) == 0x464C457F) and all of ($botlib*)
}

rule APT29_csloader_code {
      meta:
        description = "CobaltStrike loader using APT29"
        author = "JPCERT/CC Incident Response Group"
        hash = "459debf426444ec9965322ba3d61c5ada0d95db54c1787f108d4d4ad2c851098"
        hash = "a0224574ed356282a7f0f2cac316a7a888d432117e37390339b73ba518ba5d88"
        hash = "791c28f482358c952ff860805eaefc11fd57d0bf21ec7df1b9781c7e7d995ba3"

      strings:
        $size = { 41 B8 08 02 00 00 }
        $process = "explorer.exe" wide
        $resource1 = "docx" wide
        $resource2 = "BIN" wide
        $command1 = "C:\\Windows\\System32\\cmd.exe /C ping 8.8.8.8 -n 3  && del /F \"%s\"" wide
        $command2 = "C:\\Windows\\System32\\cmd.exe /k ping 8.8.8.8 -n 3  && del /F \"%s\"" wide
        $pdb = "C:\\Users\\jack\\viewer\\bin\\viewer.pdb" ascii

      condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3c)) == 0x00004550 and
        ((#size >= 4 and $process and 1 of ($command*) and 1 of ($resource*)) or
        $pdb)
}

rule BlackTech_PLEAD_mutex {
    meta:
      description = "PLEAD malware mutex strings"
      author = "JPCERT/CC Incident Response Group"
      hash = "6a49771dbb9830e1bdba45137c3a1a22d7964df26e02c715dd6e606f8da4e275"

    strings:
        $v1a = "1....%02d%02d%02d_%02d%02d...2"
        $v1b = "1111%02d%02d%02d_%02d%02d2222"
        $v1c = "%02d:%02d:%02d"
        $v1d = "%02d-%02d-%02d"

    condition:
        ($v1a or $v1b) and $v1c and $v1d
}

rule BlackTech_PLEAD_elf {
    meta:
        description = "ELF PLEAD"
        author = "JPCERT/CC Incident Response Group"
        hash = "f704303f3acc2fd090145d5ee893914734d507bd1e6161f82fb34d45ab4a164b"

    strings:
        $ioctl = "ioctl TIOCSWINSZ error"
        $class1 = "CPortForwardManager"
        $class2 = "CRemoteShell"
        $class3 = "CFileManager"
        $lzo = { 81 ?? FF 07 00 00 81 ?? 1F 20 00 00 }

    condition:
        3 of them
}

rule BlackTech_TSCookie_rat{
    meta:
      description = "TSCookie malware module"
      author = "JPCERT/CC Incident Response Group"
      hash = "2bd13d63797864a70b775bd1994016f5052dc8fd1fd83ce1c13234b5d304330d"

    strings:
        $w1d = "Date: %s" wide
        $w1a = "[-] Failed to initialize **** API" wide
        $w1b = "IPv6Test" wide

    condition:
        all of them
}

rule BlackTech_TSCookie_UA {
    meta:
      description = "detect TSCookie in memory"
      author = "JPCERT/CC Incident Response Group"
      rule_usage = "memory scan"
      reference = "https://blogs.jpcert.or.jp/en/2018/03/malware-tscooki-7aa0.html"
      hash1 = "6d2f5675630d0dae65a796ac624fb90f42f35fbe5dec2ec8f4adce5ebfaabf75"

    strings:
      $v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
      $b1 = { 68 D4 08 00 00 }
      $d1 = { 68 78 0B 00 00 }
      $v1b = { 68 9C 95 1A 6E }
      $v1c = { 68 E6 17 8F 7B }
      $v1d = { C7 40 7C 92 5A 76 5D }
      $v1e = { C7 ?? ?? ?? ?? ?? 92 5A 76 5D }

    condition:
      ($v1 and ($b1 or $d1)) or ($v1b and $v1c and ($v1d or $v1e))
}

rule BlackTech_TSCookie_loader
{
    meta:
        description = "detect tscookie loader"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "PE file search"
        hash1 = "a800df1b8ffb4fbf42bccb4a8af31c7543de3bdba1207e703d6df464ec4398e6"
        hash2 = "b548a7ad37d241b7a7762bb84a3b0125772c469ef5f8e5e0ea190fa2458a018c"

    strings:
        $rc4key = {C7 [1-6] 92 5A 76 5D}
        $rc4loop = {3D 00 01 00 00}

    condition:
        (uint16(0) == 0x5A4D) and
        (filesize<2MB) and
        all of ($rc4*)
}

rule BlackTech_TSCookie_loader_pdb
{
    meta:
        description = "detect tscookie loader pdb"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "PE file search"
        hash1 = "cc424006225d4dfcb7a6287bccd9c338d570c733b5ffcbf77be8e23a4cc20f6e"
        hash2 = "794f942c3298a43712f873cc20882d8138f75105fb151f99c5802f91f884ef04"

     strings:
        $pdb1 = "D:\\[0]MyATS-TEMP-Loading-"
        $pdb2 = "ATS-TEMP-Loader-"
        $pdb3 = "MyFuckers\\MyFuckers_"
        $pdb4 = "MyFuckersService8\\MyFuckers_"

     condition:
        uint16(0) == 0x5A4D and
        ($pdb1 or $pdb2 or $pdb3 or $pdb4)
}

rule BlackTech_TSCookie_elf {
    meta:
        description = "TSCookie ELF version"
        author = "JPCERT/CC Incident Response Group"
        hash = "698643b4c1b11ff227b3c821a0606025aaff390a46638aeb13ed8477c73f28cc"

     strings:
        $command = { 07 AC 00 72 }
        $senddata = { 0? BC 63 72 }
        $config = { C7 ?? ?? ?? 80 00 00 00 89 ?? ?? ?? C7 ?? ?? ?? 78 0B 00 00 }

     condition:
        (#senddata >= 10 and $command) or $config
}

rule BlackTech_IconDown_pe {
    meta:
        description = "detect IconDown"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "PE file search"
        hash1 = "634839b452e43f28561188a476af462c301b47bddd0468dd8c4f452ae80ea0af"
        hash2 = "2e789fc5aa1318d0286264d70b2ececa15664689efa4f47c485d84df55231ac4"

    strings:
        $dataheader1 = { 91 00 13 87 33 00 90 06 19 00 }
        $dataheader2 = { C6 [2-3] 91 88 [2-3] C6 [2-3] 13 C6 [2-3] 87 C6 [2-3] 33 88 [2-3] C6 [2-3] 90 C6 [2-3] 06 C6 [2-3] 19 }
        $string1 = "/c %s" ascii
        $string2 = /%s\\[A-X]{1,3}%[l]{0,1}X\.TMP/

    condition:
        (uint16(0) == 0x5A4D) and
        (filesize<5MB) and
        1 of ($dataheader*) and all of ($string*)
}

rule BlackTech_IconDown_resource {
    meta:
        description = "detect IconDown"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "f6494698448cdaf6ec0ed7b3555521e75fac5189fa3c89ba7b2ad492188005b4"

    strings:
        $key = {00 13 87 33 00 90 06 19}

    condition:
        (uint16(0) != 0x5A4D) and
        (filesize<5MB) and
        $key
}

rule BlackTech_iam_downloader {
    meta:
        description = "iam downloader malware in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "d8500672e293ef4918ff77708c5b82cf34d40c440d5a4b957a5dbd3f3420fdc4"

     strings:
        $fs30 = { 64 A1 30 00 00 00 8B 40 0C 8B 40 1C 8B 48 08 }
        $com1 = { 81 ?? ?? 58 09 00 00 }
        $com2 = { 81 ?? ?? 5D 09 00 00 }
        $com3 = { 81 ?? ?? 5F 09 00 00 }
        $com4 = { C7 ?? ?? 6E 09 00 00 }
        $send1 = { C7 ?? 6D 09 00 00 }
        $send2 = { C7 ?? ?? 92 5A 76 5D }
        $send3 = { C7 ?? ?? 02 77 00 00 }
        $mutex = "i am mutex!" ascii
        $api1 = { 68 8E 4E 0E EC }
        $api2 = { 68 B0 49 2D DB }
        $api3 = { 68 45 A0 E4 4E }

     condition:
        $fs30 and all of ($com*) or all of ($send*) or ($mutex and all of ($api*))
}

rule BlackTech_HIPO_headercheck {
    meta:
        description = "HIPO_loader malware in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "9cf6825f58f4a4ad261f48f165367040a05af35d2dea27ad8b53b48bf60b09ef"
        hash2 = "abc4b6be1a799e4690a318fe631f28e5c3458c8c0ea30b3f8c9f43ff6b120e1b"

     strings:
        $code1 = { 3D 48 49 50 4F 74 } // HIPO
        $code2 = { 68 22 22 22 22 68 11 11 11 11 56 8B CD E8 } // push 22222222h push 11111111h push esi

     condition:
        all of them
}

rule BlackTech_PLEAD_dummycode {
     meta:
        description = "PLEAD malware dummy code in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "d44b38360499cfc6c892b172707e3ea6e72605ad365994ee31cf6a638e288e8d"
        hash2 = "c825c7e575c97bf7280788147bd00dba732e333266f20eb38bce294d9bff238a"

     strings:
        $dummy1 = "test-%d"
        $dummy2 = "test.ini"
        $dummy3 = "ShellClassInfo.txt"
        $dummy4 = "desktop.ini"
        $dummy5 = "%02d%02d%02d"
        $dummy6 = "%s-%02d-%02d-%02d"

     condition:
        4 of ($dummy*)
}

rule BlackTech_Flagprodownloader_str {
     meta:
        description = "Flagpro downloader in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "e197c583f57e6c560b576278233e3ab050e38aa9424a5d95b172de66f9cfe970"

     strings:
        $msg1 = "download...." ascii wide
        $msg2 = "download1 finished!" ascii wide
        $msg3 = "download2 finished!" ascii wide
        $msg4 = "start get all pass!" ascii wide
        $msg5 = "start get all pass 1!" ascii wide
        $msg6 = "init Refresh...'" ascii wide
        $msg7 = "busy stop..." ascii wide
        $msg8 = "success!" ascii wide
        $msg9 = "failed!" ascii wide
        $msg10 = "~MYTEMP" ascii wide
        $msg11 = "ExecYes" ascii wide
        $msg12 = "flagpro=" ascii wide

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       6 of them
}

rule BlackTech_Gh0stTimes_str {
     meta:
        description = "Gh0stTimes in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "01581f0b1818db4f2cdd9542fd8d663896dc043efb6a80a92aadfac59ddb7684"

     strings:
        $msg1 = "new big loop connect %s %d ,sleep %d" ascii wide
        $msg2 = "small loop connect %s %d ,sleep %d" ascii wide
        $msg3 = "SockCon1=%d SockCon2=%d" ascii wide
        $msg4 = "connect  %s %d ok" ascii wide
        $msg5 = "connect failure %s %d" ascii wide
        $msg6 = "CFileManager" ascii wide
        $msg7 = "CKernelManager" ascii wide
        $msg8 = "CManager" ascii wide
        $msg9 = "CPortmapManager" ascii wide
        $msg10 = "CShellManager" ascii wide
        $msg11 = "CUltraPortmapManager" ascii wide
        $b1 ={ C6 45 ?? DB C6 45 ?? 50 C6 45 ?? 62 }
            // mov     byte ptr [ebp+var_14], 0DBh ; 'ﾛ'
            // mov     byte ptr [ebp+var_14+1], 50h ; 'P'
            // mov     byte ptr [ebp+var_14+3], 62h ; 'b'
        $b2 = { C6 45 ?? 7B C6 45 ?? 3A C6 45 ?? 79 C6 45 ?? 64 }
            // mov     byte ptr [ebp+var_10], 7Bh ; '{'
            // mov     byte ptr [ebp+var_10+1], 3Ah ; ':'
            // mov     byte ptr [ebp+var_10+2], 79h ; 'y'
            // mov     byte ptr [ebp+var_10+3], 64h ; 'd'
        $b3 = { C6 45 ?? 33 C6 45 ?? F4 C6 45 ?? 27 }
            // mov     byte ptr [ebp+var_C], 33h ; '3'
            // mov     byte ptr [ebp+var_C+1], 0F4h
            // mov     byte ptr [ebp+var_C+2], 27h ; '''
        $b4 = { C6 45 ?? 57 C6 45 ?? EA C6 45 ?? 9F C6 45 ?? 30 }
            // mov     byte ptr [ebp+var_8], 57h ; 'W'
            // mov     byte ptr [ebp+var_8+1], 0EAh
            // mov     byte ptr [ebp+var_8+2], 9Fh
            // mov     byte ptr [ebp+var_8+3], 30h ; '0'

        $pdb = {73 76 63 68 6F 73 74 2D E5 85 A8 E5 8A 9F E8 83 BD 2D E5 8A A0 E5 AF 86 31 32 30 35 5C 52 65 6C 65 61 73 65 5C 73 76 63 68 6F 73 74 2E 70 64 62}
        //$pdb = "svchost-全功能-加密1205\Release\svchost.pdb"

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (all of ($b*) or $pdb or 5 of ($msg*))
}

rule BlackTech_Gh0stTimes_panel {
     meta:
        description = "Gh0stTimes Panel"
        author = "JPCERT/CC Incident Response Group"
        hash = "18a696b09d0b7e41ad8ab6a05b84a3022f427382290ce58f079dec7b07e86165"

     strings:
        $msg1 = "[server]Listen on %s:%d successful" ascii wide
        $msg2 = "[client] connect to target %s ok" ascii wide
        $msg3 = "WriteFile failure, Close anti-virus software and try again." ascii wide
        $msg4 = "[server<-->client]begin portmap..." ascii wide
        $msg5 = "This folder already contains the file named %s" ascii wide
        $table1 = "CPortMapDlg" ascii wide
        $table2 = "CSettingDlg" ascii wide
        $table3 = "CShellDlg" ascii wide
        $table4 = "CFileManagerDlg" ascii wide
        $table5 = "CFileTransferModeDlg" ascii wide

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       5 of them
}

rule BlackTech_Bifrose_elf {
     meta:
        description = "ELF Bifrose in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "0478fe3022b095927aa630ae9a00447eb024eb862dbfce3eaa3ca6339afec9c1"

     strings:
        $msg1 = { 30 7C 00 31 7C 00 }
        $msg2 = { 35 2E 30 2E 30 2E 30 7C 00 }
        $msg3 = "%c1%s%c3D%c4%u-%.2u-%.2u %.2u:%.2u" ascii
        $msg4 = "%c2%s%c3%u%c4%u-%.2u-%.2u %.2u:%.2u" ascii
        $msg5 = "RecvData 4 bytes header error!" ascii
        $msg6 = "Deal with error! ret==0 goto error!" ascii
        $msg7 = "send data over..." ascii
        $msg8 = "cfgCount=%d" ascii
        $msg9 = "%x : %s %d" ascii
        $msg10 = "recvData timeout :%d" ascii

     condition:
       uint32(0) == 0x464C457F and
       5 of them
}

rule BlackTech_BTSDoor_str {
     meta:
        description = "BTSDoor in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "85fa7670bb2f4ef3ca688d09edfa6060673926edb3d2d21dff86c664823dd609"
        hash = "ee6ed35568c43fbb5fd510bc863742216bba54146c6ab5f17d9bfd6eacd0f796"

     strings:
        $data1 = "Not implemented!" ascii wide
        $data2 = "Win%d.%d.%d" ascii wide
        $data3 = "CMD Error!" ascii wide
        $data4 = { 76 45 8B 9E 6F 00 00 00 45 76 8B 9E 6F 00 00 00 }
        $pdb1 = "C:\\Users\\Tsai\\Desktop\\20180522windows_tro\\BTSWindows\\Serverx86.pdb" ascii
        $pdb2 = "\\BTSWindows\\Serverx86.pdb" ascii
        $pdb3 = "\\BTSWindows\\Serverx64.pdb" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (1 of ($pdb*) or 4 of ($data*))
}

rule BlackTech_Hipid_str {
     meta:
        description = "Multi-architecture (ARM or x64) backdoor in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "3d18bb8b9a5af20ab10441c8cd40feff0aabdd3f4c669ad40111e3aa5e8c54b8"
        hash = "9603b62268c2bbb06da5c99572c3dc2ec988c49c86db2abc391acf53c1cccceb"

     strings:
        $msg1 = "[+] my_dns_query failed." ascii fullword
        $msg2 = "[+] my_dns_query success." ascii fullword
        $msg3 = "[+] connect to %s:%d failed." ascii fullword
        $msg4 = "[+] connect to %s:%d success." ascii fullword
        $msg5 = "cmd: %s" ascii fullword
        $msg6 = "path: %s" ascii fullword
        $msg7 = "has address" ascii fullword
        $msg8 = "host %s" ascii fullword
        $msg9 = {84 D2 (74 ?? |0F ?? ?? ?? 00 00) 80 FA 72 (74 ?? |0F ?? ?? ?? 00 00) 80 FA 77 (74 ?? |0F ?? ?? ?? 00 00) 80 FA 65 (74 ?? |0F ?? ?? ?? 00 00)}
        $func1 = "exec_cmd_send_xor" ascii fullword
        $func2 = "exec_cmd" ascii fullword
        $func3 = "rc4_init" ascii fullword
        $func4 = "my_dns_query" ascii fullword
        $func5 = "rc4_key" ascii fullword
        $func6 = "daemon_init" ascii fullword
        $key1 = "pASSword699" ascii fullword
        $key2 = "345asdflkasduf" ascii fullword

     condition:
       uint32(0) == 0x464C457F and
       (4 of ($msg*) or 4 of ($func*) or 1 of ($key*))
}

rule BlackTech_SelfMakeLoader_str {
     meta:
        description = "SelfMake(SpiderPig) Loader in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "2657ca121a3df198635fcc53efb573eb069ff2535dcf3ba899f68430caa2ffce"

     strings:
        $s1 = { 73 65 6C 66 6D 61 6B 65 3? 41 70 70 }
        $s2 = "fixmeconfig"
        $s3 = "[+] config path:%s"
        $cmp_magic_num = { 81 7C ?? ?? (D0 D9 FE E1 | EE D8 FF E0) }

     condition:
       uint16(0) == 0x5A4D and (all of ($s*) or $cmp_magic_num)
}

rule BlackTech_HeavyROTLoader {
     meta:
        description = "HeavyROT Loader in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "F32318060B58EA8CD458358B4BAE1F82E073D1567B9A29E98EB887860CEC563C"

     strings:
        $t1 = { 68 D8 A6 08 00 E8 }
        $t2 = { 43 81 FB 00 97 49 01 }
        $calc_key = { 63 51 E1 B7 8B ?? 8B ?? 81 ?? 00 10 00 00 C1 ?? 10 0B }
        $parse_data = { 8D 6F EE 8B 10 66 8B 70 10 8B 58 04 89 54 24 28 8B 50 08 3B F5 }

     condition:
       all of ($t*) or $calc_key or $parse_data
}

rule BlackTech_SpiderRAT_str {
     meta:
        description = "Spider(SpiderPig) RAT in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "C2B23689CA1C57F7B7B0C2FD95BFEF326D6A22C15089D35D31119B104978038B"

     strings:
        $msg1 = "InternetSetOption m_ProxyUserName Error."
        $msg2 = "InternetSetOption m_ProxyPassWord Error."
        $msg3 = "pWork->HC->HttpSendMessage failed!"
        $msg4 = "Recv_put error!"
        $msg5 = "Send_put error!"
        $msg6 = "Send Success - %d:%d"
        $msg7 = "Recv Success - %d:%d"

     condition:
       uint16(0) == 0x5A4D and 5 of ($msg*) 
}

rule BlackTech_AresPYDoor_str {
     meta:
        description = "AresPYDoor in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "52550953e6bc748dc4d774fbea66382cc2979580173a7388c01589e8cb882659"

     strings:
        $ares1 = "ares.desktop"
        $ares2 = "~/.ares"
        $ares3 = "grep -v .ares .bashrc >"
        $log1 = "[-]Error! server_hello: status_code=%d"
        $log2 = "[i]runcmd: %s"
        $log3 = "[i]send_output: posting data=%s"
        $log4 = "[i]server_hello: %s"
        $log5 = "[i]starting server_hello"

     condition:
       5 of them
}

rule darkhotel_dotNetDownloader_strings {
      meta:
        description = "detect dotNetDownloader"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "PE file search"
        reference = "internal research"
        hash1 = "d95ebbbe664b6ff75cf314b267501a5fa22e896524e6812092ae294e56b4ed44"
        hash2 = "9da9fe6af141a009f28ee37b4edba715e9d77a058b1469b4076b4ea2761e37c4"

      strings:
        $pdb = "C:\\xingxing\\snowball\\Intl_Cmm_Inteface_Buld_vesion2.6\\IMGJPS.pdb" fullword nocase
        $a1 = "4d1d3972223f623f36650c00633f247433244d5c" ascii fullword
        $b1 = "snd1vPng" ascii fullword
        $b2 = "sdMsg" ascii fullword
        $b3 = "rqPstdTa" ascii fullword
        $b4 = "D0w1ad" ascii fullword
        $b5 = "U1dAL1" ascii fullword

      condition:
        (uint16(0) == 0x5A4D) and
        (filesize<200KB)  and
        (($pdb) or ($a1) or (3 of  ($b*)))
}


rule darkhotel_lnk_strings {
      meta:
        description = "detect suspicious lnk file"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "lnk file search"
        reference = "internal research"
        hash1 = "cd431575e46b80237e84cc38d3b0bc6dcd676735c889539b5efa06cec22f0560"
        hash2 = "f0d9acec522aafce3ba1c90c8af0146399a6aa74427d1cbd010a4485aacd418d"
        hash3 = "decafff59011282484d47712eec5c11cac7e17b0a5026e54d69c05e3e593ee48"

      strings:
        $hostname1 = "win-j1m3n7bfrbl" ascii fullword
        $hostname2 = "win-fe8b6nec4ks" ascii fullword
        $a1 = "cmd.exe" wide ascii
        $a2 = "mshta.exe" wide ascii
        $b1 = "TVqQAAMAAAAEAAAA" ascii

      condition:
        (uint16(0) == 0x004C) and
        ((filesize<1MB) and (filesize>200KB))  and
        ((1 of ($hostname*)) or ((1 of ($a*)) and ($b1)))
}


rule darkhotel_srdfqm_strings {
      meta:
          description = "darkhotel srdfqm.exe"
          author = "JPCERT/CC Incident Response Group"
          hash1 = "b7f9997b2dd97086343aa21769a60fb1d6fbf2d5cc6386ee11f6c52e6a1a780c"
          hash2 = "26a01df4f26ed286dbb064ef5e06ac7738f5330f6d60078c895d49e705f99394"

    	strings:
          $a1="BadStatusLine (%s)" ascii fullword
          $a2="UnknownProtocol (%s)" ascii fullword
          $a3="Request already issued" ascii fullword
          $a4="\\Microsoft\\Network\\" ascii fullword

    	condition:
          (uint16(0) == 0x5A4D) and
          (filesize<800KB)  and
        	(all of them)
}

rule DragonOK_CHWRITER_strings {
    meta:
      description = "CHWRITER malware"
      author = "JPCERT/CC Incident Response Group"
      hash = "fb1ee331be22267bc74db1c42ebb8eb8029c87f6d7a74993127db5d7ffdceaf4"

  	strings:
      $command="%s a a b c %d \"%s\"" wide

	  condition:
    	$command
}

rule DragonOK_sysget_strings {
    meta:
      description = "sysget malware"
      author = "JPCERT/CC Incident Response Group"
      hash = "a9a63b182674252efe32534d04f0361755e9f2f5d82b086b7999a313bd671348"

  	strings:
      $netbridge = "\\netbridge" wide
      $post = "POST" wide
      $cmd = "cmd /c " wide
      $register = "index.php?type=register&pageinfo" wide

    condition:
    	($netbridge and $post and $cmd) or $register
}

rule AppleJeus_UnionCrypto_code {
     meta:
        description = "UnionCrypto malware in AppleJeus"
        author = "JPCERT/CC Incident Response Group"
        hash = "295c20d0f0a03fd8230098fade0af910b2c56e9e5700d4a3344d10c106a6ae2a"

     strings:
        $http1 = "auth_timestamp:" ascii
        $http2 = "auth_signature:" ascii
        $http3 = "&act=check" ascii
        $http4 = "Windows %d(%d)-%s" ascii
        $key = "vG2eZ1KOeGd2n5fr" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (all of ($http*) or $key)
}

rule AppleJeus_UnionCrypto_loader {
     meta:
        description = "UnionCrypto loader in AppleJeus"
        author = "JPCERT/CC Incident Response Group"
        hash = "949dfcafd43d7b3d59fe3098e46661c883b1136c0836f8f9219552f13607405b"

     strings:
        $xorcode = { 33 D2 4D ?? ?? 01 8B C7 FF C7 F7 F6 42 0F B? ?? ?? 41 3? 4? FF 3B FB }
        $callcode = { 48 8? ?? E8 ?? ?? 00 00 FF D3 4C }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       all of them
}

rule CryptHunter_downloaderjs {
     meta:
        description = "JS downloader executed from an lnk file used in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        hash = "bb7349d4fd7efa838a92fc4a97ec2a25b82dde36236bdc09b531c20370d7f848"

     strings:
        $a = "pi.ProcessID!==0 && pi.ProcessID!==4){"
        $b = "prs=prs+pi.CommandLine.toLowerCase();}"

     condition:
       any of them
}

rule CryptHunter_lnk_bitly {
      meta:
        description = "detect suspicious lnk file"
        author = "JPCERT/CC Incident Response Group"
        reference = "internal research"
        hash1 = "01b5cd525d18e28177924d8a7805c2010de6842b8ef430f29ed32b3e5d7d99a0"

      strings:
        $a1 = "cmd.exe" wide ascii
        $a2 = "mshta" wide ascii
        $url1 = "https://bit.ly" wide ascii

      condition:
        (uint16(0) == 0x004c) and
        (filesize<100KB)  and
        ((1 of ($a*)) and ($url1))
}

rule CryptHunter_httpbotjs_str {
    meta:
        description = "HTTP bot js in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b316b81bc0b0deb81da5e218b85ca83d7260cc40dae97766bc94a6931707dc1b"

     strings:
        $base64 = "W0NtZGxldEJpbmRpbmcoKV1QYXJhbShbUGFyYW1ldGVyKFBvc2l0aW9uPTApXVtTdHJpbmddJFVSTCxbUGFyYW1ldGVyKFBvc2l0aW9uPTEpXVtTdHJpbmddJFVJRCkNCmZ1bmN0aW9uIEh0dHBSZXEyew" ascii
        $var1 = { 40 28 27 22 2b 70 32 61 2b 22 27 2c 20 27 22 2b 75 69 64 2b 22 27 29 3b 7d }

     condition:
        all of them
}



rule CryptHunter_python_downloader {
    meta:
        description = "1st stage python downloader in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "Hunting"
        hash1 = "e0891a1bfa5980171599dc5fe31d15be0a6c79cc08ab8dc9f09ceec7a029cbdf"

    strings:
        $str01 = "auto_interrupt_handle" ascii wide fullword
        $str02 = "aW1wb3J0IHN0cmluZw0KaW1wb3J0IHJhbmRvbQ0" ascii wide fullword

        $rot13_01 = "clguba" ascii wide fullword
        $rot13_02 = "log_handle_method" ascii wide fullword
        $rot13_03 = "rot13" ascii wide fullword
        $rot13_04 = "zfvrkrp" ascii wide fullword
        $rot13_05 = "Jvaqbjf" ascii wide fullword
        $rot13_06 = ".zfv" ascii wide fullword
        $rot13_07 = "qrirybcpber" ascii wide fullword
        $rot13_08 = "uggc://ncc." ascii wide fullword
        $rot13_09 = "cat_file_header_ops" ascii wide fullword

    condition:
        (filesize > 10KB)
        and (filesize < 5MB)
        and ( 1 of ($str*) or ( 3 of ($rot13*) ))
}

rule CryptHunter_python_simple_rat {
    meta:
        description = "2nd stage python simple rat in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "Hunting"
        hash1 = "39bbc16028fd46bf4ddad49c21439504d3f6f42cccbd30945a2d2fdb4ce393a4"
        hash2 = "5fe1790667ee5085e73b054566d548eb4473c20cf962368dd53ba776e9642272"

    strings:
        $domain01 = "www.git-hub.me" ascii wide fullword
        $domain02 = "nivyga.com" ascii wide fullword
        $domain03 = "tracking.nivyga.com" ascii wide fullword
        $domain04 = "yukunmaoyi.com" ascii wide fullword
        $domain05 = "gameofwarsite.com" ascii wide fullword
        $domain06 = "togetherwatch.com" ascii wide fullword
        $domain07 = "9d90-081d2f-vultr-los-angeles-boxul.teridions.net" ascii wide fullword
        $domain08 = "8dae-77766a-vultr-los-angeles-egnyte-sj.d1.teridioncloud.net" ascii wide fullword
        $domain09 = "www.jacarandas.top" ascii wide fullword
        $domain10 = "cleargadgetwinners.top" ascii wide fullword
        $domain11 = "ns1.smoothieking.info" ascii wide fullword
        $domain12 = "ns2.smoothieking.info" ascii wide fullword

        $str01 = "Jvaqbjf" ascii wide fullword
        $str02 = "Yvahk" ascii wide fullword
        $str03 = "Qnejva" ascii wide fullword
        $str04 = "GITHUB_REQ" ascii wide fullword
        $str05 = "GITHUB_RES" ascii wide fullword
        $str06 = "BasicInfo" ascii wide fullword
        $str07 = "CmdExec" ascii wide fullword
        $str08 = "DownExec" ascii wide fullword
        $str09 = "KillSelf" ascii wide fullword
        $str10 = "pp -b /gzc/.VPR-havk/tvg" ascii wide fullword
        $str11 = "/gzc/.VPR-havk/tvg" ascii wide fullword
        $str12 = "NccyrNppbhag.gtm" ascii wide fullword
        $str13 = "/GrzcHfre/NccyrNppbhagNffvfgnag.ncc" ascii wide fullword
        $str14 = "Pheerag Gvzr" ascii wide fullword
        $str15 = "Hfreanzr" ascii wide fullword
        $str16 = "Ubfganzr" ascii wide fullword
        $str17 = "BF Irefvba" ascii wide fullword
        $str18 = "VQ_YVXR=qrovna" ascii wide fullword
        $str19 = "VQ=qrovna" ascii wide fullword
        $str20 = "/rgp/bf-eryrnfr" ascii wide fullword
        $str21 = " -yafy -ycguernq -yerfbyi -fgq=tah99" ascii wide fullword

    condition:
        (filesize > 1KB)
        and (filesize < 5MB)
        and ( 1 of ($domain*) or ( 3 of ($str*) ))
}

rule CryptHunter_js_downloader {
    meta:
        description = "1st stage js downloader in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "Hunting"
        hash1 = "67a0f25a20954a353021bbdfdd531f7cc99c305c25fb03079f7abbc60e8a8081"

    strings:
        $code01 = "UID + AgentType + SessionType + OS;" ascii wide fullword
        $code02 = "received_data.toString().startsWith" ascii wide fullword
        $str01 = "GITHUB_RES" ascii wide fullword
        $str02 = "GITHUB_REQ" ascii wide fullword

    condition:
        (filesize > 1KB)
        and (filesize < 5MB)
        and ( 1 of ($code*) or ( 2 of ($str*) ))
}

rule CryptHunter_JokerSpy_macos {
     meta:
        description = "Mach-O malware using APT29"
        author = "JPCERT/CC Incident Response Group"
        hash = "6d3eff4e029db9d7b8dc076cfed5e2315fd54cb1ff9c6533954569f9e2397d4c"
        hash = "951039bf66cdf436c240ef206ef7356b1f6c8fffc6cbe55286ec2792bf7fe16c"
        hash = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"

     strings:
        $db = "/Library/Application Support/com.apple.TCC/TCC.db" ascii
        $path = "/Users/joker/Downloads/Spy/XProtectCheck/XProtectCheck/" ascii
        $msg1 = "The screen is currently LOCKED!" ascii
        $msg2 = "Accessibility: YES" ascii
        $msg3 = "ScreenRecording: YES" ascii
        $msg4 = "FullDiskAccess: YES" ascii
        $msg5 = "kMDItemDisplayName = *TCC.db" ascii

     condition:
       (uint32(0) == 0xfeedface or
        uint32(0) == 0xcefaedfe or
        uint32(0) == 0xfeedfacf or
        uint32(0) == 0xcffaedfe or
        uint32(0) == 0xcafebabe or
        uint32(0) == 0xbebafeca or
        uint32(0) == 0xcafebabf or
        uint32(0) == 0xbfbafeca) and
       5 of them
}

rule Lazarus_BILDINGCAN_RC4 {
    meta:
        description = "BILDINGCAN_RC4 in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "8db272ea1100996a8a0ed0da304610964dc8ca576aa114391d1be9d4c5dab02e"

    strings:
        $customrc4 = { 75 C0 41 8B D2 41 BB 00 0C 00 00 0F 1F 80 00 00 00 00 }
            // jnz     short loc_180002E60
            // mov     edx, r10d
            // mov     r11d, 0C00h
            //nop     dword ptr [rax+00000000h]
         $id = "T1B7D95256A2001E" ascii
         $nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
         $post = "id=%s%s&%s=%s&%s=%s&%s=" ascii
         $command = "%s%sc \"%s > %s 2>&1" ascii

     condition:
         uint16(0) == 0x5a4d and 3 of them
}

rule Lazarus_BILDINGCAN_AES {
    meta:
        description = "BILDINGCAN_AES in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "925922ef243fa2adbd138942a9ecb4616ab69580a1864429a1405c13702fe773 "

    strings:
        $AES = { 48 83 C3 04 30 43 FC 0F B6 44 1F FC 30 43 FD 0F B6 44 1F FD 30 43 FE 0F B6 44 1F FE 30 43 FF 48 FF C9 }
        $pass = "RC2zWLyG50fPIPkQ" wide
        $nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
        $confsize = { 48 8D ?? ?? ?? ?? 00 BA F0 06 00 00 E8 }
        $buffsize = { 00 00 C7 ?? ?? ??  B8 8E 03 00 }
        $rand = { 69 D2 ?? ?? 00 00 2B ?? 81 C? D2 04 00 00 }

     condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule Lazarus_BILDINGCAN_module {
    meta:
        description = "BILDINGCAN_AES module in Lazarus"
        author = "JPCERT/CC Incident Response Group"

    strings:
      $cmdcheck1 = { 3D ED AB 00 00 0F ?? ?? ?? 00 00 3D EF AB 00 00 0F ?? ?? ?? 00 00 3D 17 AC 00 00 0F ?? ?? ?? 00 00 }
      $cmdcheck2 = { 3D 17 AC 00 00 0F ?? ?? ?? 00 00 3D 67 EA 00 00 0F ?? ?? ?? 00 00 }
      $recvsize = { 00 00 41 81 F8 D8 AA 02 00 }
      $nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
      $rand = { 69 D2 ?? ?? 00 00 2B ?? 81 C? D2 04 00 00 }

    condition:
      uint16(0) == 0x5a4d and 3 of them
}

rule Lazarus_Torisma_strvest {
    meta:
        description = "Torisma in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "7762ba7ae989d47446da21cd04fd6fb92484dd07d078c7385ded459dedc726f9"

    strings:
         $post1 = "ACTION=NEXTPAGE" ascii
         $post2 = "ACTION=PREVPAGE" ascii
         $post3 = "ACTION=VIEW" ascii
         $post4 = "Your request has been accepted. ClientID" ascii
         $password = "ff7172d9c888b7a88a7d77372112d772" ascii
         $vestt = { 4F 70 46 DA E1 8D F6 41 }
         $vestsbox = { 07 56 D2 37 3A F7 0A 52 }
         $vestrns = { 41 4B 1B DD 0D 65 72 EE }

     condition:
         uint16(0) == 0x5a4d and (all of ($post*) or $password or all of ($vest*))
}

rule Lazarus_LCPDot_strings {
    meta:
        description = "LCPDot in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "0c69fd9be0cc9fadacff2c0bacf59dab6d935b02b5b8d2c9cb049e9545bb55ce"

    strings:
         $ua = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" wide
         $class = "HotPlugin_class" wide
         $post = "Cookie=Enable&CookieV=%d&Cookie_Time=64" ascii

     condition:
         uint16(0) == 0x5a4d and all of them
}

rule Lazarus_Torisma_config {
    meta:
        description = "Torisma config header"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b78efeac54fa410e9e3e57e4f3d5ecc1b47fd4f7bf0d7266b3cb64cefa48f0ec"

     strings:
        $header = { 98 11 1A 45 90 78 BA F9 4E D6 8F EE }

     condition:
        all of them
}

rule Lazarus_loader_thumbsdb {
    meta:
        description = "Loader Thumbs.db malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "44e4e14f8c8d299ccf5194719ab34a21ad6cc7847e49c0a7de05bf2371046f02"

     strings:
        $switchcase = { E8 ?? ?? ?? ?? 83 F8 64 74 ?? 3D C8 00 00 00 74 ?? 3D 2C 01 00 00 75 ?? E8 ?? ?? ?? ?? B9 D0 07 00 00 E8 }

     condition:
        all of them
}

rule Lazarus_Comebacker_strings {
    meta:
        description = "Comebacker malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "1ff4421a99793acda5dd7412cb9a62301b14ed0a455edbb776f56471bef08f8f"

     strings:
        $postdata1 = "%s=%s&%s=%s&%s=%s&%s=%d&%s=%d&%s=%s" ascii
        $postdata2 = "Content-Type: application/x-www-form-urlencoded" wide
        $postdata3 = "Connection: Keep-Alive" wide
        $key  = "5618198335124815612315615648487" ascii
        $str1 = "Hash error!" ascii wide
        $str2 = "Dll Data Error|" ascii wide
        $str3 = "GetProcAddress Error|" ascii wide
        $str4 = "Sleeping|" ascii wide
        $str5 = "%s|%d|%d|" ascii wide

     condition:
        all of ($postdata*) or $key or all of ($str*)
}

rule Lazarus_VSingle_strings {
     meta:
        description = "VSingle malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b114b1a6aecfe6746b674f1fdd38a45d9a6bb1b4eb0b0ca2fdb270343f7c7332"
        hash2 = "63fa8ce7bf7c8324ed16c297092e1b1c5c0a0f8ab7f583ab16aa86a7992193e6"

     strings:
        $encstr1 = "Valefor was uninstalled successfully." ascii wide
        $encstr2 = "Executable Download Parameter Error" ascii wide
        $encstr3 = "Plugin Execute Result" ascii wide
        $pdb = "G:\\Valefor\\Valefor_Single\\Release\\VSingle.pdb" ascii
        $str1 = "sonatelr" ascii
        $str2 = ".\\mascotnot" ascii
        $str3 = "%s_main" ascii
        $str4 = "MigMut" ascii
        $str5 = "lkjwelwer" ascii
        $str6 = "CreateNamedPipeA finished with Error-%d" ascii
        $str7 = ".\\pcinpae" ascii
        $str8 = { C6 45 80 4C C6 45 81 00 C6 45 82 00 C6 45 83 00 C6 45 84 01 C6 45 85 14 C6 45 86 02 C6 45 87 00 }
        $xorkey1 = "o2pq0qy4ymcrbe4s" ascii wide
        $xorkey2 = "qwrhcd4pywuyv2mw" ascii wide
        $xorkey3 = "3olu2yi3ynwlnvlu" ascii wide
        $xorkey4 = "uk0wia0uy3fl3uxd" ascii wide

     condition:
        all of ($encstr*) or $pdb or 1 of ($xorkey*) or 3 of ($str*)
}

rule Lazarus_ValeforBeta_strings {
    meta:
        description = "ValeforBeta malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "5f3353063153a29c8c3075ffb1424b861444a091d9007e6f3b448ceae5a3f02e"

     strings:
        $str0 = "cmd interval: %d->%d" ascii wide
        $str1 = "script interval: %d->%d" ascii wide
        $str2 = "Command not exist. Try again." ascii wide
        $str3 = "successfully uploaded from %s to %s" ascii wide
        $str4 = "success download from %s to %s" ascii wide
        $str5 = "failed with error code: %d" ascii wide

     condition:
        3 of ($str*)
}

//import "pe"

//rule Lzarus_2toy_sig {
//   meta:
//      description = "Lazarus using signature 2 TOY GUYS LLC"
//      date = "2021-02-03"
//      author = "JPCERT/CC Incident Response Group"
//      hash1 = "613f1cc0411485f14f53c164372b6d83c81462eb497daf6a837931c1d341e2da"
//      hash2 = "658e63624b73fc91c497c2f879776aa05ef000cb3f38a340b311bd4a5e1ebe5d"

//   condition:
//      uint16(0) == 0x5a4d and
//      for any i in (0 .. pe.number_of_signatures) : (
//         pe.signatures[i].issuer contains "2 TOY GUYS LLC" and
//         pe.signatures[i].serial == "81:86:31:11:0B:5D:14:33:1D:AC:7E:6A:D9:98:B9:02"
//      )
//}

rule Lazarus_packer_code {
    meta:
        description = "Lazarus using packer"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b114b1a6aecfe6746b674f1fdd38a45d9a6bb1b4eb0b0ca2fdb270343f7c7332"
        hash2 = "5f3353063153a29c8c3075ffb1424b861444a091d9007e6f3b448ceae5a3f02e"

     strings:
        $code = { 55 8B EC A1 ?? ?? ?? 00 83 C0 01 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 ( 01 | 02 | 03 | 04 | 05 ) 76 16 8B 0D ?? ?? ?? 00 83 E9 01 89 0D ?? ?? ?? 00 B8 ?? ?? ?? ?? EB  }
     condition:
        all of them
}

rule Lazarus_Kaos_golang {
    meta:
        description = "Kaos malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "6db57bbc2d07343dd6ceba0f53c73756af78f09fe1cb5ce8e8008e5e7242eae1"
        hash2 = "2d6a590b86e7e1e9fa055ec5648cd92e2d5e5b3210045d4c1658fe92ecf1944c"

     strings:
        $gofunc1 = "processMarketPrice" ascii wide
        $gofunc2 = "handleMarketPrice" ascii wide
        $gofunc3 = "EierKochen" ascii wide
        $gofunc4 = "kandidatKaufhaus" ascii wide
        $gofunc5 = "getInitEggPrice" ascii wide
        $gofunc6 = "HttpPostWithCookie" ascii wide

     condition:
        4 of ($gofunc*)
}

rule Lazarus_VSingle_elf {
    meta:
        description = "ELF_VSingle malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "f789e1895ce24da8d7b7acef8d0302ae9f90dab0c55c22b03e452aeba55e1d21"

     strings:
        $code1 = { C6 85 ?? ?? FF FF 26 C6 85 ?? ?? FF FF 75 C6 85 ?? ?? FF FF 69 C6 85 ?? ?? FF FF 73 } // &uis
        $code2 = { C6 85 ?? ?? FF FF 75 C6 85 ?? ?? FF FF 66 C6 85 ?? ?? FF FF 77 } // ufw
        $code3 = { C6 85 ?? ?? FF FF 25 C6 85 ?? ?? FF FF 73 C6 85 ?? ?? FF FF 7C C6 85 ?? ?? FF FF 25 C6 85 ?? ?? FF FF 78 } // %s|%x
        $code4 = { C6 85 ?? ?? FF FF 4D C6 85 ?? ?? FF FF 6F C6 85 ?? ?? FF FF 7A C6 85 ?? ?? FF FF 69 C6 85 ?? ?? FF FF 6C C6 85 ?? ?? FF FF 6C C6 85 ?? ?? FF FF 61 C6 85 ?? ?? FF FF 2F } // Mozilla
        $code5 = { C6 84 ?? ?? ?? 00 00 25 C6 84 ?? ?? ?? 00 00 73 C6 84 ?? ?? ?? 00 00 25 C6 84 ?? ?? ?? 00 00 31 C6 84 ?? ?? ?? 00 00 75 C6 84 ?? ?? ?? 00 00 25 C6 84 ?? ?? ?? 00 00 31 C6 84 ?? ?? ?? 00 00 75 } // %s%1u%1u
     condition:
        3 of ($code*)
}

rule Lazarus_packer_upxmems {
    meta:
        description = "ELF malware packer based UPX in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "f789e1895ce24da8d7b7acef8d0302ae9f90dab0c55c22b03e452aeba55e1d21"

     strings:
        $code1 = { 47 2C E8 3C 01 77 [10-14] 86 C4 C1 C0 10 86 C4 }
                                       // inc edi
                                       // sub al, 0E8h
                                       // cmp al, 1
                                       // xchg al, ah
                                       // rol eax, 10h
                                       // xchg al, ah
        $code2 = { 81 FD 00 FB FF FF 83 D1 02 8D } // cmp ebp, FFFFFB00h    adc ecx, 2
        $sig = "MEMS" ascii
     condition:
        all of ($code*) and #sig >= 3 and uint32(0x98) == 0x534d454d
}

rule Lazarus_httpbot_jsessid {
    meta:
        description = "Unknown HTTP bot in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "451ad26a41a8b8ae82ccfc850d67b12289693b227a7114121888b444d72d4727"

     strings:
        $jsessid = "jsessid=%08x%08x%08x" ascii
        $http = "%04x%04x%04x%04x" ascii
        $init = { 51 68 ?? ?? ?? 00 51 BA 04 01 00 00 B9 ?? ?? ?? 00 E8 }
        $command = { 8B ?? ?? 05 69 62 2B 9F 83 F8 1D 0F ?? ?? ?? 00 00 FF}

     condition:
        $command or ($jsessid and $http and #init >= 3)
}

rule Lazarus_tool_smbscan {
    meta:
        description = "SMB scan tool in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "d16163526242508d6961f061aaffe3ae5321bd64d8ceb6b2788f1570757595fc"
        hash2 = "11b29200f0696041dd607d0664f1ebf5dba2e2538666db663b3077d77f883195"

     strings:
        $toolstr1 = "Scan.exe StartIP EndIP ThreadCount logfilePath [Username Password Deep]" ascii
        $toolstr2 = "%s%-30s%I64d\t%04d-%02d-%02d %02d:%02d" ascii
        $toolstr3 = "%s%-30s(DIR)\t%04d-%02d-%02d %02d:%02d" ascii
        $toolstr4 = "%s U/P not Correct! - %d" ascii
        $toolstr5 = "%s %-20S%-30s%S" ascii
        $toolstr6 = "%s - %s:(Username - %s / Password - %s" ascii

     condition:
        4 of ($toolstr*)
}

rule Lazarus_simplecurl_strings {
    meta:
        description = "Tool of simple curl in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "05ffcbda6d2e38da325ebb91928ee65d1305bcc5a6a78e99ccbcc05801bba962"
     strings:
        $str1 = "Usage: [application name].exe url filename" ascii
        $str2 = "completely succeed!" ascii
        $str3 = "InternetOpenSession failed.." ascii
        $str4 = "HttpSendRequestA failed.." ascii
        $str5 = "HttpQueryInfoA failed.." ascii
        $str6 = "response code: %s" ascii
        $str7 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d :" ascii
     condition:
        4 of ($str*)
}

rule Lazarus_Dtrack_code {
     meta:
        description = "Dtrack malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "2bcb693698c84b7613a8bde65729a51fcb175b04f5ff672811941f75a0095ed4"
        hash = "467893f5e343563ed7c46a553953de751405828061811c7a13dbc0ced81648bb"

     strings:
        $rc4key1 = "xwqmxykgy0s4"
        $rc4key2 = "hufkcohxyjrm"
        $rc4key3 = "fm5hkbfxyhd4"
        $rc4key4 = "ihy3ggfgyohx"
        $rc4key5 = "fwpbqyhcyf2k"
        $rc4key6 = "rcmgmg3ny3pa"
        $rc4key7 = "a30gjwdcypey"
        $zippass1 = "dkwero38oerA^t@#"
        $zippass2 = "z0r0f1@123"
        $str1 = "Using Proxy"
        $str2 = "Preconfig"
        $str3 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d :"
        $str4 = "%02X:%02X:%02X:%02X:%02X:%02X"
        $str5 = "%s\\%c.tmp"
        $code = { 81 ?? EB 03 00 00 89 ?? ?? ?? FF FF 83 ?? ?? ?? FF FF 14 0F 87 EA 00 00 00 }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (1 of ($rc4key*) or 1 of ($zippass*) or (3 of  ($str*) and $code))
}

rule Lazarus_keylogger_str {
     meta:
        description = "Keylogger in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "e0567863b10e9b1ac805292d30626ea24b28ee12f3682a93d29120db3b77a40a"

     strings:
        $mutex = "c2hvcGxpZnRlcg"
        $path = "%APPDATA%\\\\Microsoft\\\\Camio\\\\"
        $str = "[%02d/%02d/%d %02d:%02d:%02d]"
        $table1 = "CppSQLite3Exception"
        $table2 = "CppSQLite3Query"
        $table3 = "CppSQLite3DB"
        $table4 = "CDataLog"
        $table5 = "CKeyLogger"

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       4 of them
}

rule Lazarus_DreamJob_doc2021 {
     meta:
        description = "Malicious doc used in Lazarus operation Dream Job"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "ffec6e6d4e314f64f5d31c62024252abde7f77acdd63991cb16923ff17828885"
        hash2 = "8e1746829851d28c555c143ce62283bc011bbd2acfa60909566339118c9c5c97"
        hash3 = "294acafed42c6a4f546486636b4859c074e53d74be049df99932804be048f42c"

     strings:
        $peheadb64 = "dCBiZSBydW4gaW4gRE9TIG1vZGU"
        $command1 = "cmd /c copy /b %systemroot%\\system32\\"
        $command2 = "Select * from Win32_Process where name"
        $command3 = "cmd /c explorer.exe /root"
        $command4 = "-decode"
        $command5 = "c:\\Drivers"
        $command6 = "explorer.exe"
        $command7 = "cmd /c md"
        $command8 = "cmd /c del"

     condition:
       uint16(0) == 0xCFD0 and
       $peheadb64 and 4 of ($command*)
}

rule Lazarus_boardiddownloader_code {
     meta:
        description = "boardid downloader in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "fe80e890689b0911d2cd1c29196c1dad92183c40949fe6f8c39deec8e745de7f"

     strings:
        $enchttp = { C7 ?? ?? 06 1A 1A 1E C7 ?? ?? 1D 54 41 41 }
        $xorcode = { 80 74 ?? ?? 6E 80 74 ?? ?? 6E (48 83|83) ?? 02 (48|83) }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       all of them
}

rule Lazarus_obfuscate_string {
    meta:
        description = "Strings contained in obfuscated files used by Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "e5466b99c1af9fe3fefdd4da1e798786a821c6d853a320d16cc10c06bc6f3fc5"

    strings:
        $str1 = { 2D 41 72 67 75 6D 65 6E 74 4C 69 73 74 20 27 5C 22 00 }
        $str2 = "%^&|," wide
        $str3 = "SeDebugPrivilege" wide

    condition:
        uint16(0) == 0x5a4d and
        filesize > 1MB and
        all of them
}

rule Lazarus_VSingle_github {
     meta:
        description = "VSingle using GitHub in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "199ba618efc6af9280c5abd86c09cdf2d475c09c8c7ffc393a35c3d70277aed1"
        hash = "2eb16dbc1097a590f07787ab285a013f5fe235287cb4fb948d4f9cce9efa5dbc"

     strings:
        $str1 = "Arcan3" ascii wide fullword
        $str2 = "Wr0te" ascii wide fullword
        $str3 = "luxuryboy" ascii wide fullword
        $str4 = "pnpgather" ascii wide fullword
        $str5 = "happyv1m" ascii wide fullword
        $str6 = "laz3rpik" ascii wide fullword
        $str7 = "d0ta" ascii wide fullword
        $str8 = "Dronek" ascii wide fullword
        $str9 = "Panda3" ascii wide fullword
        $str10 = "cpsponso" ascii wide fullword
        $str11 = "ggo0dlluck" ascii wide fullword
        $str12 = "gar3ia" ascii wide fullword
        $str13 = "wo0d" ascii wide fullword
        $str14 = "tr3e" ascii wide fullword
        $str15 = "l0ve" ascii wide fullword
        $str16 = "v0siej" ascii wide fullword
        $str17 = "e0vvsje" ascii wide fullword
        $str18 = "polaris" ascii wide fullword
        $str19 = "grav1ty" ascii wide fullword
        $str20 = "w1inter" ascii wide fullword

     condition:
       (uint32(0) == 0x464C457F and
       8 of ($str*)) or
       (uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       8 of ($str*))
}

rule Lazarus_BTREE_str {
     meta:
        description = "BTREE malware using Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "4fb31b9f5432fd09f1fa51a35e8de98fca6081d542827b855db4563be2e50e58"

     strings:
        $command1 = "curl -A cur1-agent -L %s -s -d da" ascii wide
        $command2 = "cmd /c timeout /t 10 & rundll32 \"%s\" #1" ascii wide
        $command3 = "rundll32.exe %s #1 %S" ascii wide
        $command4 = "%s\\marcoor.dll" ascii wide
        $rc4key = "FaDm8CtBH7W660wlbtpyWg4jyLFbgR3IvRw6EdF8IG667d0TEimzTiZ6aBteigP3" ascii wide

     condition:
       2 of ($command*) or $rc4key
}

//import "pe"
//import "hash"

//rule Lazarus_PDFIcon {
//    meta:
//        description = "PDF icon used in PE file by Lazarus"
//        author = "JPCERT/CC Incident Response Group"
//        hash = "e5466b99c1af9fe3fefdd4da1e798786a821c6d853a320d16cc10c06bc6f3fc5"

//    condition:
//        for any i in (0..pe.number_of_resources - 1) : (
//            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "b3e0e069d00fb2a746b7ed1eb3d6470772a684349800fc84bae9f40c8a43d87a"
//        )
//}

rule Lazarus_msi_str {
    meta:
        description = "msi file using Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "f0b6d6981e06c7be2e45650e5f6d39570c1ee640ccb157ddfe42ee23ad4d1cdb"
	
    strings:
        $magic = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00/
        $s1 = "New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 300)" ascii wide
        $s2 = "New-ScheduledTaskAction -Execute \"c:\\windows\\system32\\pcalua.exe" ascii wide
        $s3 = "function sendbi(pd)" ascii wide
        $s4 = "\\n\\n\"+g_mac()+\"\\n\\n\"+g_proc()" ascii wide

     condition:
       $magic at 0 and 2 of ($s*)
}

rule Lazarus_downloader_code {
     meta:
        description = "Lazarus downloader"
        author = "JPCERT/CC Incident Response Group"
        hash = "faba4114ada285987d4f7c771f096e0a2bc4899c9244d182db032acd256c67aa"

     strings:
        $jmp = { 53 31 c0 50 50 50 50 50 C7 ?? ?? 00 00 00 00 EB 00 }
        $count = { 00 00 EB 00 B8 FF 59 62 02 3B 05 ?? ?? ?? 00 }
        $api = "InitOnceExecuteOnce" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       filesize < 200KB and
       all of them
}

rule tick_xxmm_parts {
      meta:
        description = "xxmm malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "9374040a9e2f47f7037edaac19f21ff1ef6a999ff98c306504f89a37196074a2"

      strings:
        $pdb1 = "C:\\Users\\123\\Desktop\\xxmm3\\"
        $pdb2 = "C:\\Users\\123\\documents\\visual studio 2010\\Projects\\"
        $pdb3 = "C:\\Users\\123\\Documents\\Visual Studio 2010\\Projects\\"
        $sa = "IsLogAllAccess"
        $sb = "allaccess.log"

      condition:
        ($pdb1 or $pdb2 or $pdb3 or all of ($s*)) and uint16(0) == 0x5A4D and
        uint32(uint32(0x3c)) == 0x00004550
}

rule tick_xxmm_strings {
      meta:
        description = "detect xxmm in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"

      strings:
        $v1 = "setupParameter:"
        $v2 = "loaderParameter:"
        $v3 = "parameter:"

      condition:
        all of them
}

rule tick_Datper {
      meta:
        description = "detect Datper in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "https://blogs.jpcert.or.jp/en/2017/08/detecting-datper-malware-from-proxy-logs.html"
        hash = "4d4ad53fd47c2cc7338fab0de5bbba7cf45ee3d1d947a1942a93045317ed7b49"

      strings:
        $a1 = { E8 03 00 00 }
        $b1 = "|||"
        $c1 = "Content-Type: application/x-www-form-urlencoded"
        $delphi = "SOFTWARE\\Borland\\Delphi\\" ascii wide
        $push7530h64 = { C7 C1 30 75 00 00 }
        $push7530h = { 68 30 75 00 00 }

      condition:
        $a1 and $b1 and $c1 and $delphi and ($push7530h64 or $push7530h)
}

rule tick_daserf_mmid {
      meta:
        description = "Daserf malware (Delphi)"
        author = "JPCERT/CC Incident Response Group"
        hash = "94a9a9e14acaac99f7a980d36e57a451fcbce3bb4bf24e41f53d751c062e60e5"

      strings:
        $ua = /Mozilla\/\d.0 \(compatible; MSIE \d{1,2}.0; Windows NT 6.\d; SV1\)/
        $delphi = "Delphi"
        $mmid = "MMID"
        $ccaacmds = "ccaacmds"
        $php = ".php"

      condition:
        $ua and $delphi and #php > 3 and $mmid and $ccaacmds
}

rule tick_daserf_1_5_mini {
    meta:
      description = "Daserf malware"
      author = "JPCERT/CC Incident Response Group"
      hash = "bba61cdb14574c7700d2622167cb06432cd3f97899fa52a0530b83780a6545b2"

  	strings:
    	$user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1)"
      $version = "n:1.5"
      $mini = "Mini"

    condition:
    	all of them
}

rule tick_daserf_1_5_not_mini {
    meta:
      description = "Daserf malware"
      author = "JPCERT/CC Incident Response Group"
      hash = "446e71e2b12758b4ceda27ba2233e464932cf9dc96daa758c4b221c8a433570f"

  	strings:
    	$user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1)"
      $s1 = "Progman"
      $s3 = ".asp"
      $s4 = "DRIVE_" wide

    condition:
    	all of them
}

rule tick_Gofarer_ua {
    meta:
      description = "Gofarer malware"
      author = "JPCERT/CC Incident Response Group"
      hash = "9a7e18ab6e774a76e3bd74709e9435449915329a1234364b4ef1b0d5d69158db"

	  strings:
        $ua = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+6.1;+Trident/4.0;+SLCC2;+.NET+CLR+2.0.50727;+.NET4.0E)"

    condition:
        all of them
}

rule tick_xxmm_panel {
    meta:
      description = "xxmm php panel"
      author = "JPCERT/CC Incident Response Group"

	  strings:
        $sa = "REMOTE_ADDR"
        $sb = "HTTP_USER_AGENT"
        $sc = "$clienttype="
        $sd = "$ccmd="
        $se = "ccc_"
        $sf = "sss_"
        $sg = "|||"

    condition:
    	all of them
}

rule tick_SKYSEA_downloader {
      meta:
        description = "Malware downloaded using a vulnerability in SKYSEA"
        author = "JPCERT/CC Incident Response Group"
        hash = "3955d0340ff6e625821de294acef4bdc0cc7b49606a984517cd985d0aac130a3"

  	  strings:
      	$sa = "c:\\Projects\\vs2013\\phc-tools\\Release\\loader.pdb"
        $sb = "%s\\config\\.regeditKey.rc"

      condition:
      	all of them
}

rule tick_Datper_RSAtype {
      meta:
        description = "Datper malware (RSA type)"
        author = "JPCERT/CC Incident Response Group"

      strings:
         $a1 = { E8 03 00 00 }
         $b1 = "|||"
         $c1 = "Content-Type: application/x-www-form-urlencoded"
         $d1 = { A8 03 10 00 FF FF FF FF }
         $push7530h64 = { C7 C1 30 75 00 00 }
         $push7530h = { 68 30 75 00 00 }

      condition:
        $a1 and $b1 and $c1 and $d1 and ($push7530h64 or $push7530h)
}

rule tick_app_js {
      meta:
        description = "JavaScript malware downloaded using a vulnerability in SKYSEA"
        author = "JPCERT/CC Incident Response Group"
        hash = "f36db81d384e3c821b496c8faf35a61446635f38a57d04bde0b3dfd19b674587"

  	  strings:
      	$sa = "File download error!"
        $sb = "/tools/uninstaller.sh"
        $sc = "./npm stop"

      condition:
      	all of them
}

//import "cuckoo"

//rule tick_datper_mutex {
//      meta:
//        description = "Datper malware used mutex strings"
//        author = "JPCERT/CC Incident Response Group"
//        hash1 = "c2e87e5c0ed40806949628ab7d66caaf4be06cab997b78a46f096e53a6f49ffc"
//        hash2 = "4149da63e78c47fd7f2d49d210f9230b94bf7935699a47e26e5d99836b9fdd11"

//      condition:
//        cuckoo.sync.mutex(/d4fy3ykdk2ddssr/) or
//        cuckoo.sync.mutex(/gyusbaihysezhrj/) or
//        cuckoo.sync.mutex(/edc1icnmfgj9UJ\(1G63K/)
//}

rule tick_DALBOTDRPR_strings {
      meta:
        description = "DALBOT dropper malware"
        author = "JPCERT/CC Incident Response Group"

      strings:
        $pdb = "C:\\Users\\jack\\Documents\\Visual Studio 2010\\down_new\\Release\\down_new.pdb"
        $comment = "CreatePipe(cmd) failed!!!"
        $mac = "%.2x%.2x%.2x%.2x%.2x%.2x"
        $aacmd = "AAAAA"

      condition:
        $pdb or ($comment and $mac and $aacmd)
}

rule tick_DALBOT_strings {
      meta:
        description = "DALBOT malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "4092c39282921a8884f5ce3d85fb1f2045323dba2a98332499fdd691fe4b8488"

  	  strings:
        $pdb = "C:\\Users\\jack\\Documents\\Visual Studio 2010\\down_new\\Release\\down_new.pdb"
        $message = "CreatePipe(cmd) failed!!!"
        $url = "&uc=go"

      condition:
        $pdb or ($message and $url)
}

rule tick_ABK_pdb {
      meta:
        description = "ABK downloader malware"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "fb0d86dd4ed621b67dced1665b5db576247a10d43b40752c1236be783ac11049"
        hash2 = "3c16a747badd3be70e92d10879eb41d4312158c447e8d462e2b30c3b02992f2a"

      strings:
//		    $pdb1 = "C:\\Users\\Frank\\Desktop\\"
//        $pdb2 = "C:\\Users\\Frank\\Documents\\"
        $pdb3 = "C:\\Users\\Frank\\Desktop\\ABK\\Release\\Hidder.pdb"
        $pdb4 = "C:\\Users\\Frank\\Documents\\Visual Studio 2010\\Projects\\avenger\\Release\\avenger.pdb"
        $pdb5 = "C:\\Users\\Frank\\Desktop\\ABK\\Release\\ABK.pdb"

      condition:
//        ($pdb1 or $pdb2 or $pdb3 or $pdb4 or $pdb5) and uint16(0) == 0x5A4D
        ($pdb3 or $pdb4 or $pdb5) and uint16(0) == 0x5A4D
}

rule tick_ABK_downloader {
      meta:
        description = "ABK downloader malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "5ae244a012951ab2089ad7dc70e564f90586c78ff08b93bb2861bb69edcdd5c5"

      strings:
        $a1 = "PccNT.exe" wide
        $bytecode = {	50 63 63 00 4e 54 2e 00 65 78 65 00 }

      condition:
        (uint16(0) == 0x5A4D) and
        (filesize>10MB) and
        ((any of ($a1)) or $bytecode)
}

rule tick_ABK_downloader_susp_ua {
      meta:
        description = "ABK downloader malware"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "ade2a4c4fc0bd291d2ecb2f6310c75243107301f445a947409b38777ff014972"
        hash2 = "32dbfc069a6871b2f6cc54484c86b21e2f13956e3666d08077afa97d410185d2"
        hash3 = "d1307937bd2397d92bb200b29eeaace562b10474ff19f0013335e37a80265be6"

      strings:
        $UA= "Mozilla/4.0(compatible;MSIE8.0;WindowsNT6.0;Trident/4.0)"

      condition:
        (uint16(0) == 0x5A4D) and
        (filesize<50MB) and
        $UA
}

//rule tick_ABK_downloader_susp_mutex {
//      meta:
//        description = "ABK downloader malware"
//        author = "JPCERT/CC Incident Response Group"
//        hash1 = "ade2a4c4fc0bd291d2ecb2f6310c75243107301f445a947409b38777ff014972"
//        hash2 = "32dbfc069a6871b2f6cc54484c86b21e2f13956e3666d08077afa97d410185d2"
//        hash3 = "d1307937bd2397d92bb200b29eeaace562b10474ff19f0013335e37a80265be6"

//      condition:
//        (uint16(0) == 0x5A4D) and
//        (filesize<50MB) and
//        (cuckoo.sync.mutex(/PPGword/) or cuckoo.sync.mutex(/CQFB/))
//}

rule malware_Lokibot_strings {
          meta:
            description = "detect Lokibot in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"
            hash1 = "6f12da360ee637a8eb075fb314e002e3833b52b155ad550811ee698b49f37e8c"

          strings:
            $des3 = { 68 03 66 00 00 }
            $param = "MAC=%02X%02X%02XINSTALL=%08X%08X"
            $string = { 2d 00 75 00 00 00 46 75 63 6b 61 76 2e 72 75 00 00}

          condition:
            all of them
}

rule tool_3proxy_strings {
    meta:
        description = "3Proxy tiny proxy server"
        author = "JPCERT/CC Incident Response Group"
        reference = "http://3proxy.ru/"
     strings:
        $str1 = "http://3proxy.ru/" ascii
        $str2 = "size of network buffer (default 4096 for TCP, 16384 for UDP)" ascii
        $str3 = "value to add to default client thread stack size" ascii
        $str4 = "Connect back not received, check connback client" ascii
        $str5 = "Failed to allocate connect back socket" ascii
        $str6 = "Warning: too many connected clients (%d/%d)" ascii
     condition:
        3 of ($str*)
}

rule malware_Remcos_strings {
          meta:
            description = "detect Remcos in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            hash1 = "7d5efb7e8b8947e5fe1fa12843a2faa0ebdfd7137582e5925a0b9c6a9350b0a5"

          strings:
            $remcos = "Remcos" ascii fullword
            $url1 = "Breaking-Security.Net" ascii fullword
            $url2 = "BreakingSecurity.Net" ascii fullword
            $resource = "SETTINGS" ascii wide fullword

          condition:
            1 of ($url*) and $remcos and $resource
}

rule malware_droplink_str {
     meta:
        description = "malware using dropbox api(TRANSBOX, PLUGBOX)"
        author = "JPCERT/CC Incident Response Group"
        hash = "bdc15b09b78093a1a5503a1a7bfb487f7ef4ca2cb8b4d1d1bdf9a54cdc87fae4"
        hash = "6e5e2ed25155428b8da15ac78c8d87d2c108737402ecba90d70f305056aeabaa"

     strings:
        $data1 = "%u/%u_%08X_%u_%u.jpg" ascii wide
        $data2 = "%u/%u.jpg" ascii wide
        $data3 = "%u/%s" ascii wide
        $data4 = "%u/%u.3_bk.jpg"
        $data5 = "%u/%u.2_bk.jpg" ascii wide
        $data6 = "%u/%u_%08X_%d.jpg" ascii wide
        $data7 = "%s\",\"mode\":\"overwrite" ascii wide
        $data8 = "Dropbox-API-Art-Type:" ascii wide
        $data9 = "/2/files/upload" ascii wide
        $data10 = "Dropbox-API-Arg: {\"path\":\"/" ascii wide
        $data11 = "/oauth2/token" ascii wide
        $data12 = "LoadPlgFromRemote.dll" ascii wide
        $data13 = "FILETRANDLL.dll" ascii wide
        $data14 = "NVIDLA" ascii wide
        $data15 = "start.ini" ascii wide
        $data16 = "RunMain" ascii wide
        $data17 = "cfg.png" ascii wide
        $data18 = "DWrite.dll" ascii wide
        $pdb1 = "\\\\daddev\\office10\\2609.0\\setup\\x86\\ship\\program files\\common files\\microsoft shared\\office10\\1033\\DWINTLO.PDB" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       filesize<1MB and
       (1 of ($pdb*) or 5 of ($data*))
}

rule malware_RestyLink_lnk {
     meta:
        description = "RestyLink lnk file"
        author = "JPCERT/CC Incident Response Group"
        hash = "90a223625738e398d2cf0be8d37144392cc2e7d707b096a7bfc0a52b408d98b1"
        hash = "9aa2187dbdeef231651769ec8dc5f792c2a9a7233fbbbcf383b05ff3d6179fcf"
        hash = "3feb9275050827543292a97cbf18c50c552a1771c4423c4df4f711a39696ed93"

     strings:
        $cmd1 = "C:\\Windows\\System32\\cmd.exe" wide
        $cmd2 = "Windows\\system32\\ScriptRunner.exe" wide
        $command1 = "/c set a=start winword.exe /aut&&set" wide
        $command2 = "&&set n=omation /vu /q&&cmd /c %a%%n% %m%" wide
        $command3 = "-appvscript explorer.exe https://" wide
        $command4 = "-appvscript curl.exe -s https://" wide

     condition:
       uint16(0) == 0x004c and
       filesize<100KB and
       1 of ($cmd*) and
       1 of ($command*)
}


rule restylink_Secur32_dll_downloader {
    meta:
        description = "Hunting no stripped Binaries by AutoYara4ELFsig JPCERT/CC"
        author = "AutoYara4ELFsig"
        rule_usage = "Hunting"
        hash = "107426B7B30D613E694F9153B415037C4E8194B7E7C96F0760EB59DE8F349809"
    
    strings:
        /* Function Address: 0x1800011b0 : mal_main
        41 B8 00 20 00 00                   mov     r8d, 2000h            
        48 8B D3                            mov     rdx, rbx              
        49 8B CE                            mov     rcx, r14              
        FF D6                               call    rsi                   
        B9 64 00 00 00                      mov     ecx, 64h ; 'd'        
        FF D7                               call    rdi                   
        48 81 C3 00 20 00 00                add     rbx, 2000h            
        */
        $func0 = { 41 B8 00 20 00 00 48 8B D3 49 8B CE FF D6 B9 64 00 00 00 FF D7 48 81 C3 00 20 00 00 }

        /* Function Address: 0x1800011b0 : mal_main
        44 8B C7                mov     r8d, edi
        BB A3 00 00 00          mov     ebx, 0A3h
        0F 1F 80 00 00 00 00    nop     dword ptr [rax+00000000h]
        FF C0                   inc     eax
        25 FF 00 00 80          and     eax, 800000FFh
        7D 09                   jge     short loc_180001592
        FF C8                   dec     eax
        0D 00 FF FF FF          or      eax, 0FFFFFF00h
        FF C0                   inc     eax
        48 63 C8                movsxd  rcx, eax         
        */
        $func1 = { 44 8B C7 BB A3 00 00 00 0F 1F 80 00 00 00 00 FF C0 25 FF 00 00 80 7D 09 FF C8 0D 00 FF FF FF FF C0 48 63 C8 }

        /*
          RC4key  j#ghsj@%dhg#87u*#RYCIHfvd )7
        */
        $func2 = { 6A 23 67 68 73 6A 40 25  64 68 67 23 38 37 75 2A 23 52 59 43 49 48 66 76  64 20 29 37 }

        /*
          c2
        */
        $func3 = { 61 62 63 2E 6D 62 75 73 61 62 63 2E 63 6F 6D 00}

    condition:
        (uint16(0) == 0x5A4D)
        and (filesize < 1MB)
        and ( 1 of ($func*) )
}

rule malware_StealthWorker {
    meta:
      description = "detect StealthWorker"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "b6fc97981b4be0536b650a364421d1435609223e1c5a058edeced954ca25f6d1"

    strings:
      $a1 = "StealthWorker/Worker"
      $a2 = "/bots/knock?worker=%s&os=%s&version=%s"
      $a3 = "/project/saveGood"

    condition:
      all of them
}
