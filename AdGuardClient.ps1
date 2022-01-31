<#
.SYNOPSIS
AdGuardHomeClient.ps1 - Client for Adguard home.

.DESCRIPTION 
Description PlaceHolder

.PARAMETER URL
[Mandatory] Specifies the URL for your AdGuardHome instance.
.PARAMETER Credentials
[Mandatory] Specifies the credentials Object of type [pscredentials] to be used to authenticate against the AdGuardHome instance.


.EXAMPLE

Example Title PlaceHolder
.\Client.ps1 -URL [String] -Credentials [pscredential]

.NOTES
Created by: Giulio Dalicco

Find me on:

* LinkedIn:	https://www.linkedin.com/in/giuliodalicco/
* Github:	https://github.com/GD-HCK

Official Documentations
* Website:	
    1. https://adguard.com/en/adguard-home/overview.html
    2. https://github.com/AdguardTeam/AdGuardHome#getting-started
    3. https://github.com/AdguardTeam/AdGuardHome/tree/master/openapi
    4. http://editor.swagger.io/
    5. https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml

Change Log
V1.00, 07/12/2021 - Initial version
#>


[CmdletBinding()]
param (
        
    [Parameter(Mandatory, HelpMessage = "Define your AdGuard Home website URL. Example https://adguard.example.com")]    
    [ValidateNotNullOrEmpty()]
    [String]
    $URL,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [pscredential]
    $Credentials
)

begin {

    #### Import Yml API Definitions ####
    ##Import-Module ConvertFrom-Yaml
    $Yaml = (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/openapi/openapi.yaml" -Method GET).RawContent
    $Yaml = $Yaml.Remove(0, $Yaml.IndexOf("'openapi':"))
    $Yaml | Set-Content -Path "$PSScriptRoot\AdGuard.Yaml" # Backup Locally
    $Definitions = $Yaml | ConvertFrom-Yaml
        
    #Use This For Testing
    <#
    You would need to replace the password parameter with the below
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Password = 'Your Password Here'
    #>
    #$Password = ConvertTo-Securestring -String $Password -AsPlainText -Force #for testing only
    
    $Username = $Credentials.UserName
    $Password = $Credentials.Password

    # Web request components
    $BASE_URL = "$URL/control"
    $TagsURL = ([System.Uri]::new("$BASE_URL/clients")).AbsoluteUri

    #Convert credentials to a base64 string - Compatibility with powershall 5.1 and Below
    $PlainTextPwd = [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($Password))
    $BASE_64_Creds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$Username`:$PlainTextPwd"))
    $WebReqHeaders = @{Authorization = "Basic $BASE_64_Creds" }
    
    ## Powershell Core
    $credentials = [System.Management.Automation.PSCredential]::new($Username, $password)
        

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $supportedTags = @(((Invoke-WebRequest -Uri $TagsURL -UseBasicParsing -Headers $WebReqHeaders -Method Get).Content | ConvertFrom-Json).supported_tags)
    }
    else {
        $supportedTags = @(((Invoke-WebRequest -Uri $TagsURL -Authentication Basic -Credential $credentials -Method Get).Content | ConvertFrom-Json).supported_tags) 

    }
    
    $BlockedServices = @("9gag", "amazon", "cloudflare", "dailymotion", "discord", "disneyplus", "ebay", 
        "epic_games", "facebook", "hulu", "imgur", "instagram", "mail_ru",
        "netflix", "ok", "origin", "pinterest", "qq", "reddit", "skype", "snapchat",
        "spotify", "steam", "telegram", "tiktok", "tinder", "twitch", "twitter", "viber", "vimeo", "vk",
        "wechat", "weibo", "whatsapp", "youtube")
    
    # Tags List #
    $clients = [ordered]@{
        header  = "Clients list operations";
        options = [ordered]@{
            0 = [PSCustomObject]@{description = "0. Get Clients"; location = "/clients"; Method = "GET" };
            1 = [PSCustomObject]@{description = "1. Add a new client"; location = "/clients/add" ; Method = "POST"; Body = [ordered]@{
                    name                        = [ordered]@{Description = "Client name"; Type = "String" };
                    ids                         = [ordered]@{Description = "Comma-Separated IDs, `nClients can be identified by the IP address, CIDR, MAC address or a special client ID (can be used for DoT/DoH/DoQ)."; Type = "Array" };
                    use_global_settings         = [ordered]@{Description = "Use Global Settings? True/False"; Type = "Bool" };
                    filtering_enabled           = [ordered]@{Description = "Enable Filtering? True/False"; Type = "Bool" };
                    parental_enabled            = [ordered]@{Description = "Enable Parental Control? True/False"; Type = "Bool" };
                    safebrowsing_enabled        = [ordered]@{Description = "Enable Sage Browsing? True/False"; Type = "Bool" };
                    safesearch_enabled          = [ordered]@{Description = "Enable SafeSearch? True/False"; Type = "Bool" };
                    use_global_blocked_services = [ordered]@{Description = "Use Global Blocked Services? True/False"; Type = "Bool" };
                    blocked_services            = [ordered]@{Description = "Comma-Separated Blocked Services, if any.`n$BlockedServices"; Type = "Array" };
                    upstreams                   = [ordered]@{Description = "Comma-Separated Upstreams, if any. Example: 1.1.1.1, https://dns.cloudflare.com/dns-query"; Type = "Array" };
                    tags                        = [ordered]@{Description = "Comma-Separated Tags, `n$supportedTags"; Type = "Array" };
                }
            };
            2 = [PSCustomObject]@{description = "2. Remove a client"; location = "/clients/delete" ; Method = "POST"; Body = [ordered]@{
                    name = [ordered]@{Description = "Client name"; Type = "String" };
                } 
            };
            3 = [PSCustomObject]@{description = "3. Update client information"; location = "/clients/update" ; Method = "POST"; Body = [ordered]@{
                    name = [ordered]@{Description = "Client name"; Type = "String" };
                    data = [ordered]@{
                        name                        = [ordered]@{Description = "Client new name"; Type = "String" };
                        ids                         = [ordered]@{Description = "Comma-Separated IDs, `nClients can be identified by the IP address, CIDR, MAC address or a special client ID (can be used for DoT/DoH/DoQ)."; Type = "Array" };
                        use_global_settings         = [ordered]@{Description = "Use Global Settings? True/False"; Type = "Bool" };
                        filtering_enabled           = [ordered]@{Description = "Enable Filtering? True/False"; Type = "Bool" };
                        parental_enabled            = [ordered]@{Description = "Enable Parental Control? True/False"; Type = "Bool" };
                        safebrowsing_enabled        = [ordered]@{Description = "Enable Sage Browsing? True/False"; Type = "Bool" };
                        safesearch_enabled          = [ordered]@{Description = "Enable SafeSearch? True/False"; Type = "Bool" };
                        use_global_blocked_services = [ordered]@{Description = "Use Global Blocked Services? True/False"; Type = "Bool" };
                        blocked_services            = [ordered]@{Description = "Comma-Separated Blocked Services, if any.`n$BlockedServices"; Type = "Array" };
                        upstreams                   = [ordered]@{Description = "Comma-Separated Upstreams, if any. Example: 1.1.1.1, https://dns.cloudflare.com/dns-query"; Type = "Array" };
                        tags                        = [ordered]@{Description = "Comma-Separated Tags, `n$supportedTags"; Type = "Array" };
                    }
                }
            };
            4 = [PSCustomObject]@{description = "4. Get clients by IP or IDs"; location = "/clients/find" ; Method = "GET"; Parameters = @{
                    IP = [ordered]@{Description = "What is the hostname or IP?"; Element = "?Ip0="; Type = "String" }; 
                } 
            };
            5 = [PSCustomObject]@{description = "5. Get Blocked/Unblocked clients"; location = "/access/list" ; Method = "GET" };
            6 = [PSCustomObject]@{description = "6. Block/Unblock client"  ; location = "/access/set" ; Method = "POST"; Body = [ordered]@{
                    allowed_clients    = [ordered]@{Description = "A list of CIDR or IP addresses. If configured, AdGuard Home will accept requests from these IP addresses only.`nComma-Separated Allowed Clients, if any"; Type = "Array" };
                    disallowed_clients = [ordered]@{Description = "A list of CIDR or IP addresses. If configured, AdGuard Home will drop requests from these IP addresses.`nComma-Separated Disallowed Clients, if any"; Type = "Array" };
                    blocked_hosts      = [ordered]@{Description = "Don't confuse this with filters. AdGuard Home will drop DNS queries with these domains in queries' questions. Here you can specify the exact domain names, wildcards and URL filter rules, e.g. `"example.org`", `"*.example.org`" or `"||example.org^`".`nComma-Separated Blocked Domains, if any"; Type = "Array" };
                }
            }
        }
    }
    $dhcp = [ordered]@{
        header  = "Built-in DHCP server controls";
        options = [ordered]@{
            7  = [PSCustomObject]@{description = "7. Gets DHCP settings"; location = "/dhcp/status" ; Method = "GET" };
            8  = [PSCustomObject]@{description = "8. Gets available interfaces"; location = "/dhcp/interfaces" ; Method = "GET" };
            9  = [PSCustomObject]@{description = "9. Update DHCP configuration"; location = "/dhcp/set_config" ; Method = "POST"; Body = [ordered]@{
                    enabled        = [ordered]@{Description = "Enable/Disable DHCP. True to Enable, False to Disable"; Type = "Bool" };
                    interface_name = [ordered]@{Description = "Specify the DHCP interface. If Unsure, use option `"$(($dhcp.options.Values | Where-Object{$_.location -eq '/dhcp/interfaces'}).description)`", to get the interface information"; Type = "String" };
                    v4             = [ordered]@{
                        gateway_ip     = [ordered]@{Description = "DHCP Gateway IP Address, Example: 192.168.1.254"; Type = "String" };
                        subnet_mask    = [ordered]@{Description = "DHCP IPs' Subnet Mask, Example: 255.255.255.0"; Type = "String" };
                        range_start    = [ordered]@{Description = "Start DHCP Range, Example: 192.168.1.1"; Type = "String" };
                        range_end      = [ordered]@{Description = "End DHCP Range, Example: 192.168.1.50"; Type = "String" };
                        lease_duration = [ordered]@{Description = "Lease Duration in Hours. Example: 24"; Type = "Integer" };
                    };
                    v6             = [ordered]@{
                        range_start    = [ordered]@{Description = "Start DHCP IPv6 Range, Example: 6000::"; Type = "String" };
                        range_end      = [ordered]@{Description = "End DHCP IPv6 Range, Example: 6000::ffff:ffff:ffff:ffff"; Type = "String" };
                        lease_duration = [ordered]@{Description = "Lease Duration in Hours. Example: 24"; Type = "Integer" };
                    };
                    
                }
            };
            10 = [PSCustomObject]@{description = "10. Scan for active DHCPs"; location = "/dhcp/find_active_dhcp"; Method = "POST" };
            11 = [PSCustomObject]@{description = "11. Add static lease"; location = "/dhcp/add_static_lease" ; Method = "POST"; Body = [ordered]@{
                    mac      = [ordered]@{Description = "Static Lease MAC Address"; Type = "String" };
                    ip       = [ordered]@{Description = "Static Lease IP Address"; Type = "String" };
                    hostname = [ordered]@{Description = "Static Lease Hostname"; Type = "Array" };
                } 
            };
            12 = [PSCustomObject]@{description = "12. Remove static lease"; location = "/dhcp/remove_static_lease" ; Method = "POST"; Body = [ordered]@{
                    mac      = [ordered]@{Description = "Static Lease MAC Address"; Type = "String" };
                    ip       = [ordered]@{Description = "Static Lease IP Address"; Type = "String" };
                    hostname = [ordered]@{Description = "Static Lease Hostname"; Type = "Array" };
                }  
            };
            13 = [PSCustomObject]@{description = "13. Reset DHCP configuration"  ; location = "/dhcp/reset" ; Method = "POST"; Body = @() };
            14 = [PSCustomObject]@{description = "14. Reset DHCP leases"  ; location = "/dhcp/reset_leases" ; Method = "POST"; Body = @() };
        };
    }

    $filtering = [ordered]@{
        header  = "Rule-based filtering";
        options = [ordered]@{
            15 = [PSCustomObject]@{description = "15. Get filtering parameters"; location = "/filtering/status" ; Method = "GET" };
            16 = [PSCustomObject]@{description = "16. Check if hostname is filtered"; location = "/filtering/check_host" ; Method = "GET"; Parameters = @{
                    name = [ordered]@{Description = "Hostname?"; Element = "?name="; Type = "String" }; 
                } 
            };
            17 = [PSCustomObject]@{description = "17. Set filtering parameters"; location = "/filtering/config" ; Method = "POST"; Body = [ordered]@{
                    enabled  = [ordered]@{Description = "Enable/Disable filterng. True to Enable, False to Disable"; Type = "Bool" };
                    interval = [ordered]@{Description = "How long do you want to enable/disable filtering for? 0 means indefinitely"; Type = "String" };
                }
            };
            18 = [PSCustomObject]@{description = "18. Add filtering list from URL or absolute file path"; location = "/filtering/add_url"; Method = "POST"; Body = [ordered]@{
                    name      = [ordered]@{Description = "List name"; Type = "String" };
                    url       = [ordered]@{Description = "List Path or URL, Examle https://filters.adtidy.org/windows/filters/15.txt"; Type = "String" };
                    whitelist = [ordered]@{Description = "Add to filtering blocklist or whitelist. True for whitelist, False for Blacklist"; Type = "Bool" };
                }  
            };
            19 = [PSCustomObject]@{description = "19. Remove Whitelist/Blacklist"; location = "/filtering/remove_url" ; Method = "POST"; Body = [ordered]@{
                    url = [ordered]@{Description = "List Path or URL, Examle https://filters.adtidy.org/windows/filters/15.txt"; Type = "String" };
                } 
            };
            20 = [PSCustomObject]@{description = "20. Set List parameters"; location = "/filtering/set_url" ; Method = "POST"; Body = [ordered]@{
                    data      = [ordered]@{
                        enabled = [ordered]@{Description = "Enable/Disable filterng. True to Enable, False to Disable"; Type = "Bool" };
                        name    = [ordered]@{Description = "List name"; Type = "String" };
                        url     = [ordered]@{Description = "List Path or URL, Examle https://filters.adtidy.org/windows/filters/15.txt"; Type = "String" };
                    };
                    url       = [ordered]@{Description = "List Path or URL, Examle https://filters.adtidy.org/windows/filters/15.txt"; Type = "String" };
                    whitelist = [ordered]@{Description = "Add to filtering blocklist or whitelist. True for whitelist, False for Blacklist"; Type = "Bool" };
                }  
            };
            21 = [PSCustomObject]@{description = "21. Reload filtering rules from URLs"; location = "/filtering/refresh" ; Method = "POST"; Body = @{
                    whitelist = [ordered]@{Description = "Specify the list you want to refresh: True for whitelist, False for Blacklist"; Type = "Bool" };
                } 
            };
            22 = [PSCustomObject]@{description = "22. Set user-defined filter rules"  ; location = "/filtering/set_rules" ; Method = "POST"; Body = [ordered]@{
                    filter = [ordered]@{Description                                                           = "Define your filter. Examples:`n
                    1. ||example.org^ : block access to the example.org domain and all its subdomains`n
                    2. @@||example.org^ : unblock access to the example.org domain and all its subdomains`n
                    3. 127.0.0.1 example.org : AdGuard Home will now return 127.0.0.1 address for the example.org domain (but not its subdomains).`n
                    4. ! Here goes a comment : just a comment`n
                    5. # Also a comment : just a comment`n
                    6. /REGEX/ : block access to the domains matching the specified regular expression"; Type = "String" 
                    };
                } 
            };
        };
    }

    $global = [ordered]@{
        header  = "AdGuard Home general settings";
        options = [ordered]@{
            23 = [PSCustomObject]@{description = "23. Get DNS server current status and general settings"; location = "/status" ; Method = "GET" };
            24 = [PSCustomObject]@{description = "24. Get general DNS parameters"; location = "/dns_info" ; Method = "GET" };
            25 = [PSCustomObject]@{description = "25. Perform administrator log-out"; location = "/logout" ; Method = "GET" };
            26 = [PSCustomObject]@{description = "26. Get Profile information"; location = "/profile" ; Method = "GET" };
            27 = [PSCustomObject]@{description = "27. Get DNS over HTTPS .mobileconfig"; location = "/apple/doh.mobileconfig" ; Method = "GET"; Parameters = @{
                    name      = [ordered]@{Description = "Host for which the config is generated. If no host is provided, tls.server_name from the configuration file is used.`nIf tls.server_name is not set, the API returns an error with a 500 status.`nExample: domain.org"; Element = "?host="; Type = "String" }; 
                    client_id = [ordered]@{Description = "Client ID"; Element = "&client_id="; Type = "String" }; 
                }  
            };
            28 = [PSCustomObject]@{description = "28. Get DNS over TLS .mobileconfig."; location = "/apple/dot.mobileconfig" ; Method = "GET"; Parameters = @{
                    name      = [ordered]@{Description = "Host for which the config is generated. If no host is provided, tls.server_name from the configuration file is used.`nIf tls.server_name is not set, the API returns an error with a 500 status.`nExample: domain.org"; Element = "?host="; Type = "String" }; 
                    client_id = [ordered]@{Description = "Client ID"; Element = "&client_id="; Type = "String" }; 
                }  
            };
            
            29 = [PSCustomObject]@{description = "29. Set general DNS parameters"; location = "/dns_config" ; Method = "POST"; Body = [ordered]@{
                    bootstrap_dns             = [ordered]@{Description = "Bootstrap DNS servers are used to resolve IP addresses of the DoH/DoT resolvers you specify as upstreams.`nExample: 1.1.1.1"; Type = "Array" };
                    upstream_dns              = [ordered]@{Description = "Comma-Separated Upstream Dns Servers.`nExample: https://dns.cloudflare.com/dns-query,https://doh.opendns.com/dns-query"; Type = "Array" };
                    upstream_dns_file         = [ordered]@{Description = "CSV file containing Upstream Dns Servers, if any"; Type = "String" };
                    protection_enabled        = [ordered]@{Description = "Enable protection, True or False"; Type = "Bool" };
                    dhcp_available            = [ordered]@{Description = "Enable DHCP, True or False"; Type = "Bool" };
                    ratelimit                 = [ordered]@{Description = "The number of requests per second allowed per client. Setting it to 0 means no limit.`nExample: 0"; Type = "Integer" };
                    blocking_mode             = [ordered]@{
                        Description = "Blocking mode. Choose from:`n
                                        1. Default: Default: Respond with zero IP address (0.0.0.0 for A; :: for AAAA) when blocked by Adblock-style rule; respond with the IP address specified in the rule when blocked by /etc/hosts-style rule,`n
                                        2.refused: REFUSED: Respond with REFUSED code,`n
                                        3.nxdomain: NXDOMAIN: Respond with NXDOMAIN code,`n4.null_ip: Null IP: Respond with zero IP address (0.0.0.0 for A; :: for AAAA),`n
                                        5.custom_ip: Custom IP: Respond with a manually set IP address,`n
                                        Example: Default"; 
                        Type        = "String" 
                    };
                    blocking_ipv4             = [ordered]@{Description = "CSV file containing Upstream Dns Servers, if any"; Type = "Bool" };
                    blocking_ipv6             = [ordered]@{Description = "CSV file containing Upstream Dns Servers, if any"; Type = "Bool" };
                    edns_cs_enabled           = [ordered]@{Description = "Enable EDNS CLient Subnet.`nIf Enabled, AdGuard Home will be sending clients' subnets to the DNS servers. True or False"; Type = "Bool" };
                    disable_ipv6              = [ordered]@{Description = "If this feature is enabled, all DNS queries for IPv6 addresses (type AAAA) will be dropped. True or False"; Type = "Bool" };
                    dnssec_enabled            = [ordered]@{Description = "Enable DNSSEC. Set DNSSEC flag in the outcoming DNS queries and check the result (DNSSEC-enabled resolver is required). True or False"; Type = "Bool" };
                    cache_size                = [ordered]@{Description = "DNS cache size (in bytes). Example: 4194304"; Type = "Integer" };
                    cache_ttl_min             = [ordered]@{Description = "Override minimum TTL"; Type = "Integer" };
                    cache_ttl_max             = [ordered]@{Description = "Override maximum TTL"; Type = "Integer" };
                    cache_optimistic          = [ordered]@{Description = "Cache optimistic. True or False"; Type = "Bool" };
                    upstream_mode             = [ordered]@{Description = "Upstream query mode. Choose from:`n1. Blank, Load Balance requestes between upstreams,`n2. parallel, Query upstreams simultaneously,`n3. fastest_addr, query all upstreams and return the fastest response"; Type = "Bool" };
                    use_private_ptr_resolvers = [ordered]@{Description = "If enabled, AdGuard Home will attempt to reversely resolve clients' IP addresses into their hostnames by sending PTR queries to corresponding resolvers (private DNS servers for local clients, upstream server for clients with public IP addresses). True or False"; Type = "Bool" };
                    resolve_clients           = [ordered]@{Description = "Resolve clients, True or False"; Type = "Bool" };
                    local_ptr_upstreams       = [ordered]@{Description = "Comma-Separated ptr Upstream Dns Servers, if any. Example tls://1.1.1.1,tls://1.0.0.1"; Type = "Array" };
                
                }  
            };
            30 = [PSCustomObject]@{description = "30. Test upstream configuration"; location = "/test_upstream_dns" ; Method = "POST"; Body = [ordered]@{
                    bootstrap_dns    = [ordered]@{Description = "Comma-Separated Bootstrap DNS servers used to resolve IP addresses of the DoH/DoT resolvers.`nExample: 1.1.1.1"; Type = "Array" };
                    upstream_dns     = [ordered]@{Description = "Comma-Separated Upstream DNS Servers.`nExample: https://dns.cloudflare.com/dns-query,https://doh.opendns.com/dns-query"; Type = "Array" };
                    private_upstream = [ordered]@{Description = "Comma-Separated private DNS Servers, if any"; Type = "Array" };
                }  
            };
        };
    }



    $tags = @($clients, $dhcp, $filtering, $global)
    $OptionsCount = $tags.options.keys.count - 1
    $StartingTag = 0
    
    function Get-Menu {
        [CmdletBinding()]
        param (
            [string]
            $ErrorMessage
        )
        
        # menu box width #
        $BannerSize = 100
        $sectionsSize = 59


        $Headings = @('AdGuard Home Client', "URL: $URL")

        # Client Banner # 
        $BannerContour = "+" + ''.PadRight($BannerSize, '=') + "+"
        Write-Host $BannerContour -ForegroundColor Magenta

        foreach ($heading in $Headings) {
            $Paddig = ($BannerSize - $heading.Length - 1) / 4
            $BannerOpening = '|' + ''.PadRight($Paddig, '#') + ''.PadRight($Paddig)
            $Paddig = ($BannerSize - $heading.Length) / 4
            $BannerClosing = ''.PadRight($Paddig) + ''.PadRight($Paddig, '#') + '|'
            Write-Host $BannerOpening -ForegroundColor Magenta -NoNewline; Write-Host $heading -ForegroundColor Yellow -NoNewline; Write-Host $BannerClosing -ForegroundColor Magenta
            Write-Host $BannerContour -ForegroundColor Magenta
        }

        $MenuCount = 0
        for ($y = $StartingTag; $y -lt $tags.Count; $y++) {
            $openingSection = "|######  ".PadRight(($sectionsSize - $tags[$y].header.Length) / 2)
            $closingSection = "  ######|".PadLeft(($sectionsSize - $tags[$y].header.Length) / 2)
            Write-Host $openingSection -ForegroundColor Magenta -NoNewline; Write-Host $tags[$y].header -ForegroundColor Yellow -NoNewline; Write-Host $closingSection -ForegroundColor Magenta
            $headerline = "|".PadRight($sectionsSize, '_') + "|"
            Write-Host $headerline -ForegroundColor Magenta
            
            $options = $tags[$y].options
            for ($i = 0; $i -lt $options.Count; $i++) {
                $openingTag = "|--> "
                [string] $text = $($options[$i].description)
                $text = $text + ''.PadRight($sectionsSize - ($openingTag.Length + $text.Length))
                $closingTag = "|"
                Write-Host $openingTag -ForegroundColor Magenta -NoNewline; Write-Host $text -ForegroundColor Yellow -NoNewline; Write-Host $closingTag -ForegroundColor Magenta
            }
            $headerline = "+".PadRight($sectionsSize, '=') + "+"
            Write-Host $headerline -ForegroundColor Magenta
            $MenuCount++
            if ($MenuCount -eq 2) {
                break
            }
        }
        if ($ErrorMessage) {
            Write-Host $ErrorMessage -ForegroundColor Red
        }
        $option = Read-Host "Choose an option, press CTRL + C to exit or press Enter to move on to the next options"
        if ($option.length -gt 0) {
            return $option
        }
        else {
            $StartingTag = $StartingTag + 2
            if ($StartingTag -ge $tags.Count) {
                $StartingTag = 0
            }
            Clear-Host
            Get-Menu
        }
    }

    function Invoke-GetAdguardData {
        [CmdletBinding()]
        param (
            [string]
            $URL,
            [hashtable]
            $Data
        )
        
        if ($Data) {
            foreach ($key in $Data.Keys) { 
                $value = Read-Host -Prompt $Data[$Key].Description
                [string]$URL += $Data[$Key].Element + $value
            }
        }
        Write-Host "Querying URL: "$URL
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            $Content = ((Invoke-WebRequest -Uri $URL -UseBasicParsing -Headers $WebReqHeaders -Method Get).Content | ConvertFrom-Json)
        }
        else {
            $Content = ((Invoke-WebRequest -Uri $URL -Authentication Basic -Credential $script:credentials -Method Get).Content | ConvertFrom-Json)
        }
        
        <#
        $result = @()
        if ($Content) {
            
            $properties = ($Content | Get-Member -MemberType Properties).Name
            
                      
            if ($properties.Count -gt 0) {
                foreach ($property in $properties) {
                    $value = Select-Object -InputObject $Content -ExpandProperty $property
                    $result += @{$property = $value }
                }
            }
            else {
                $value = Select-Object -InputObject $Content -ExpandProperty $properties[0]
                $result += @{$properties[0] = $value }
            }
        }
        else {
            $result = "No results returned"
        }#>
        
        return $Content
    }

    function Invoke-PostAdguardData {
        [CmdletBinding()]
        param (
            [string]
            $URL,
            [hashtable]
            $Data
        )  
        
        $Body = @{}
        $SubBody = @{}
        
        Write-Host ""; Write-Host "Data:"; $Data; Write-Host ""
        
        if ($Data.body) {
            foreach ($key in $Data.body.Keys) {
                if ($Data.body.$key.keys -notcontains "Description") {
                    foreach ($subkey in $Data.Body.$key.keys) {
                        $value = Read-Host -Prompt $Data.Body.$key[$subkey].Description
                        if ($value.Length -gt 0) {
                            if ($Data.Body.$key[$subkey].Type -eq "Bool") {
                                if ($value -ieq "true") { $value = $true }else { $value = $false }
                            }
                            elseif ($Data.Body.$key[$subkey].Type -eq "Array") {
                                $value = @($value -split ",")
                            }
                            elseif ($Data.Body.$key[$subkey].Type -eq "Integer") {
                                if ([regex]::match($value, "\d").Success) { [int]$value = $value }
                            }
                            $SubBody += @{$subkey = $value }
                        }
                    }
                    $Body += @{data = $SubBody } 
                }
                else {
                    $value = Read-Host -Prompt $Data.Body[$Key].Description
                    if ($value.Length -gt 0) {
                        if ($Data.Body[$Key].Type -eq "Bool") {
                            if ($value -ieq "true") { $value = $true }else { $value = $false }
                        }
                        elseif ($Data.Body[$Key].Type -eq "Array") {
                            $value = @($value -split ",")
                        }
                        elseif ($Data.Body[$key].Type -eq "Integer") {
                            if ([regex]::match($value, "\d").Success) { [int]$value = $value }
                        }
                        $Body += @{$key = $value }
                    }
                }
            }
        }
        
        if ($Body) {
            $Body = $Body | ConvertTo-Json
            Write-Host ""
            Write-Host "Posting Body to $URL`: `n$Body"
            Write-Host ""
            if ($PSVersionTable.PSVersion.Major -lt 5) {
                $Content = ((Invoke-WebRequest -Uri $URL -UseBasicParsing -Headers $WebReqHeaders -Method Post -Body $Body).Content | ConvertFrom-Json)
            }
            else {
                $Content = ((Invoke-WebRequest -Uri $URL -Authentication Basic -Credential $script:credentials -Method Post -Body $Body).Content | ConvertFrom-Json)
            }
        }
        else {
            $Content = $Null
        }
        
        return $Content
        
    }

    function Invoke-CmdBuilder {
        [CmdletBinding()]
        param (
            [int]
            $Command
        )

        $obj = $null

        foreach ($tag in $tags) {
            $options = $tag.options
            if ($options.Contains($command)) {
                $location = ($options.$command).location;
                $URI = [System.Uri]::new("$BASE_URL$location")
                $obj = @{
                    URI         = $URI.AbsoluteUri;
                    Parameters  = ($options.$command).Parameters
                    Method      = ($options.$command).Method;
                    description = ($options.$command).description;
                    body        = ($options.$command).body;
                }
                break
            }
        }

        return $obj
    }

}

##########################################################################################################################################################
#####################################                               Starting Client                              #########################################
##########################################################################################################################################################
process {

    function Get-Client {
        [CmdletBinding()]
        param (
            [string]
            $ErrorMessage
        )
        $Option = $null
        $command = $null
        if ($ErrorMessage) {
            $Option = Get-Menu -ErrorMessage $ErrorMessage
        }
        else {
            $Option = Get-Menu
        }
        if (-not ([regex]::match($Option, "\d")).Success) {
            Clear-Host
            $ErrorMessage = "Option selected is not within the list. Try again"
            Get-Client -ErrorMessage $ErrorMessage
        }
        else {
            [int]$Option = $Option
            if ($Option -gt $OptionsCount) {
                Clear-Host
                $ErrorMessage = "Option selected is not within the list. Try again"
                Get-Client -ErrorMessage $ErrorMessage
            }
            $command = Invoke-CmdBuilder -Command $Option
            Clear-Host
            Write-Host "Option selected: "$command.description
            if ($command.Method -eq "GET") {
                try {
                    $result = $null

                    if ($command.Parameters) {
                        $result = Invoke-GetAdguardData -URL $command.URI -Data $command.Parameters
                    }
                    else {
                        $result = Invoke-GetAdguardData -URL $command.URI
                    }

                    if ($result) {
            
                        $properties = ($result | Get-Member -MemberType Properties).Name
                        
                                  
                        if ($properties.Count -gt 0) {
                            foreach ($property in $properties) {
                                Select-Object -InputObject $result -ExpandProperty $property
                            }
                        }
                        else {
                            Select-Object -InputObject $Content -ExpandProperty $properties[0]
                        }
                    }
                    else {
                        $result = "No results returned"
                    }

                    <#
                    foreach ($key in $result.keys) {
                        "$Key :"
                        $result.$key
                        #Select-Object -InputObject $result -ExpandProperty $Key
                    }
                    #>
                }
                catch {
                    $ErrorMessage = "ERROR WHEN RUNNING COMMAND: `n$($_.exception.message)"
                    Get-Client -ErrorMessage $ErrorMessage
                }
            }
            else {
                try {
                    $result = Invoke-PostAdguardData -Data  $command -URL $command.URI
                    If ($null -eq $result) {
                        Write-Warning "No values supplied, nothing to send here"
                    }
                }
                catch {
                    $ErrorMessage = Write-Host "ERROR WHEN RUNNING COMMAND: `n$($_.exception.message).`nCheck your data is valid and try again." -ForegroundColor Red
                    Get-Client -ErrorMessage $ErrorMessage
                }
                
            }
            Get-Client
        }
    }
    Clear-Host
    Get-Client
}

<#
$title = @"
        ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
        █░▄▄▀██░▄▄▀██░▄▄░██░██░█░▄▄▀██░▄▄▀██░▄▄▀████░▄▄▀██░████▄░▄██░▄▄▄██░▀██░█▄▄░▄▄
        █░▀▀░██░██░██░█▀▀██░██░█░▀▀░██░▀▀▄██░██░████░█████░█████░███░▄▄▄██░█░█░███░██
        █░██░██░▀▀░██░▀▀▄██▄▀▀▄█░██░██░██░██░▀▀░████░▀▀▄██░▀▀░█▀░▀██░▀▀▀██░██▄░███░██
        ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
"@
        $title2 = @"
╔═══╗╔═══╗╔═══╗╔╗ ╔╗╔═══╗╔═══╗╔═══╗    ╔═══╗╔╗   ╔══╗╔═══╗╔═╗ ╔╗╔════╗
║╔═╗║╚╗╔╗║║╔═╗║║║ ║║║╔═╗║║╔═╗║╚╗╔╗║    ║╔═╗║║║   ╚╣╠╝║╔══╝║║╚╗║║║╔╗╔╗║
║║ ║║ ║║║║║║ ╚╝║║ ║║║║ ║║║╚═╝║ ║║║║    ║║ ╚╝║║    ║║ ║╚══╗║╔╗╚╝║╚╝║║╚╝
║╚═╝║ ║║║║║║╔═╗║║ ║║║╚═╝║║╔╗╔╝ ║║║║    ║║ ╔╗║║ ╔╗ ║║ ║╔══╝║║╚╗║║  ║║  
║╔═╗║╔╝╚╝║║╚╩═║║╚═╝║║╔═╗║║║║╚╗╔╝╚╝║    ║╚═╝║║╚═╝║╔╣╠╗║╚══╗║║ ║║║ ╔╝╚╗ 
╚╝ ╚╝╚═══╝╚═══╝╚═══╝╚╝ ╚╝╚╝╚═╝╚═══╝    ╚═══╝╚═══╝╚══╝╚═══╝╚╝ ╚═╝ ╚══╝ 
"@
@"
         _____           ________         ___________
        /     \         |   ___  \       |   ________|
       /   _   \        |  |   \  \      |  |
      /   / \   \       |  |    |  |     |  |   _______        
     /   /___\   \      |  |    |  |     |  |  |____   |
    /    _____    \     |  |___/   |     |  |       |  |
   /    /     \    \    |         /      |  |_______|  |
  /____/       \____\   |________/       |____________/
                    
"@

@"      
        #####              ############       ###############     #####       #####            #####           #############      ############
       #######             #############      ###############     #####       #####           #######          #############      #############
      #########            ###        ###     ###                 #####       #####          #########         ###       ###      ###        ###
     ###     ###           ###        ###     ###                 #####       #####         ###     ###        ###       ###      ###        ###
    ####     ####          ###        ###     ###    ########     #####       #####        ####     ####       #############      ###        ###
   ###############         ###        ###     ###    ########     #####       #####       ###############      #############      ###        ###
  #################        ###        ###     ###         ###     #####       #####      #################     ####     ####      ###        ###
 ####           ####       ##############     ###############      ###############      ####           ####    ####      ####     ##############
####             ####      ############       ###############       #############      ####             ####   ####       ####    ############

"@
#>
    


