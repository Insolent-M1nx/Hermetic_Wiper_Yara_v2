rule Hermetic_Wiper {
   meta:
      description = "Hermetic_Wiper targeting Ukrain."
      author = "Joe Wood"
      reference = "Copia.exe and QxSk2n7kna.exe"
      date = "2022-02-24"
      hashA = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
      hashB = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
      hashC = "3c557727953a8f6b4788984464fb77741b821991acbf5e746aebdd02615b1767"
   strings:
    
      $s1 = "tdrv.pdb" fullword wide
      $s2 = "Hermetica Digital Ltd0" fullword ascii
      $s3 = "\\\\.\\EPMNTDRV\\%u" fullword wide
      $s4 = "runtime " fullword ascii
      $s5 = "=+>:>G>Z>h>u>|>" fullword ascii
      $s6 = "jectarea" fullword ascii
      $s7 = "KeWai_tForSO" fullword ascii
      $s8 = "chronous" fullword ascii
      $s9 = "pkioq/pro?ducts/" fullword wide
      $s10 = "essdrive" fullword ascii
      $s11 = "DRV_X64" fullword wide
      $s12 = "accessdr" fullword ascii
      $s13 = "PerfLogs" fullword wide
      $s14 = "ccessdri" fullword ascii
      $s15 = "author3 d" fullword ascii
      $s16 = "ndiskacc" fullword ascii
      $s17 = "windiska" fullword ascii
      $s18 = "Corp{or0" fullword wide
      $s19 = "3*373W3f3k3v3" fullword wide
      $s20 = "eference" fullword ascii   
      $s21 = "ojectare" fullword ascii
      $s22 = "9Redmon_d1" fullword wide
      $s23 = "%ws%.2ws" fullword wide
      $s24 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" fullword wide

   condition:
      ( uint16(0) == 0x5a4d or uint16(0) == 0x5a53 and filesize < 410KB and ( 8 of them )
      ) or ( all of them )
}
