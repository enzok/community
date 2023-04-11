rule NetSupport {
    meta:
        author = "ditekSHen"
        description = "Detects NetSupport client"
        cape_type = "NetSupport Payload"
    strings:
        $s1 = ":\\nsmsrc\\nsm\\" fullword ascii
        $s2 = "name=\"NetSupport Client Configurator\"" fullword ascii
        $s3 = "<description>NetSupport Manager Remote Control.</description>" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule NetSupportLoader {
    meta:    
        author = "enzok"
        description = "Detects NetSupport Loader"
        cape_type = "NetSupport Payload"
    strings:    
        $as1 = "whost" wide ascii
        $as2 = "rename-item" wide ascii
        $as3 = "ExpirienceHost" wide ascii
        $as4 = "-ComputerName" wide ascii
        $client = "client32.exe" wide ascii
    condition:
        $client and 3 of ($as*)
}
