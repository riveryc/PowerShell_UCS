Import-Module Cisco.UCSCentral, Cisco.UCSManager

function Exportfrom-UcsVlanToJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsvlan1.json",
        [string]$DatacenterName = "PE1"
    )
    Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true >> $null
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $fi1upbru01 = Connect-Ucs -Name fi1upbru01.eulnd01.gmgmt.cloud -Credential $Cred
    $fi1inbru02 = Connect-Ucs -Name fi1inbru02.eulnd01.gmgmt.cloud -Credential $Cred

    $ResultJson = @{}
    $ResultJson.vLans = Get-UcsVlan | Sort-Object Ucs
    $ResultJson.DatacenterName = $DatacenterName
    $ResultJson | ConvertTo-Json -Depth 50 | Out-File -FilePath $UcsJsonConfigFile
    Disconnect-Ucs -Ucs $fi1upbru01
    Disconnect-Ucs -Ucs $fi1inbru02
}
#Exportfrom-UcsVlanToJson

function Importto-UcsCentralVlanFromUcsVlan
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsvlan.json"
    )
    $Configuration = Get-Content -Path $UcsJsonConfigFile -Raw | ConvertFrom-Json
    $DataCenterName = $Configuration.DatacenterName
    $vLans = $Configuration.vLans | Where-Object {$_.IfRole -eq "network"}
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $UCSCentralHandle = Connect-UcsCentral -Name ucs-central.gmgmt.cloud -Credential $Cred
    $UcsCentralDomainGroup = Get-UcsCentralOrgDomainGroup -Name $DataCenterName -UcsCentral $UCSCentralHandle
    $UcsCentralFabricEp = Get-UcsCentralFabricEp -OrgDomainGroup $UcsCentralDomainGroup -LimitScope
    $UcsCentralLanCloud = Get-UcsCentralLanCloud -FabricEp $UcsCentralFabricEp
    foreach ($vlan in $vlans)
    {
        Write-Host "Checking for vLan `"$($vlan.Name)`" ..." -ForegroundColor Green
        $UCSCentralvlan = Get-UcsCentralVlan -UcsCentral $UCSCentralHandle -Name "$($vlan.Name)`_$($vlan.Id)"
        if ($UCSCentralvlan -eq $null)
        {
            Write-Host "vLan `"$($vlan.Name)`" is not present, creating now..." -ForegroundColor Yellow
            $UCSCentralvlan = Add-UcsCentralVlan -Id $vlan.Id -Name "$($vlan.Name)`_$($vlan.Id)" -Sharing "none" -LanCloud $UcsCentralLanCloud
        }
    }
    $UCSCentralHandle = Disconnect-UcsCentral -UcsCentral $UCSCentralHandle -Verbose
}
#Importto-UcsCentralVlanFromUcsVlan

function Exportfrom-UcsOrgToJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsorg1.json"
    )
    Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true >> $null
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $fi1upbru01 = Connect-Ucs -Name fi1upbru01.eulnd01.gmgmt.cloud -Credential $Cred
    $fi1inbru02 = Connect-Ucs -Name fi1inbru02.eulnd01.gmgmt.cloud -Credential $Cred

    $ResultJson = Get-UcsOrg | Sort-Object Ucs
    $ResultJson | ConvertTo-Json -Depth 50 | Out-File -FilePath $UcsJsonConfigFile
    Disconnect-Ucs -Ucs $fi1upbru01
    Disconnect-Ucs -Ucs $fi1inbru02
}
#Exportfrom-UcsOrgToJson

function Importto-UcsCentralOrgFromUcsOrg
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsorg1.json"
    )
    $Configuration = Get-Content -Path $UcsJsonConfigFile -Raw | ConvertFrom-Json
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $UCSCentralHandle = Connect-UcsCentral -Name ucs-central.gmgmt.cloud -Credential $Cred
    foreach ($org in $Configuration)
    {
        Write-Host "Checking for Org `"$($org.Name)`" ..." -ForegroundColor Green
        $UCSCentralOrg = Get-UcsCentralOrg -Dn $org.Dn -UcsCentral $UCSCentralHandle
        if ($org.Dn -ne "org-root")
        {
            $dn = $org.Dn
            $ParentDn = $dn.Substring(0,$dn.LastIndexOf("/"))
            $ParentOrg = Get-UcsCentralOrg -Dn $ParentDn -UcsCentral $UCSCentralHandle
            $UCSCentralOrg = Add-UcsCentralOrg -Org $ParentOrg -Name $org.Name -Descr $org.Descr -UcsCentral $UCSCentralHandle -Verbose -ErrorAction SilentlyContinue
        }
    }
    $UCSCentralHandle = Disconnect-UcsCentral -UcsCentral $UCSCentralHandle -Verbose
}
#Importto-UcsCentralVlanFromUcsVlan

function Exportfrom-UcsCentralDomainToJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucscentraldomain.json"
    )
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $UCSCentralHandle = Connect-UcsCentral -Name ucs-central.gmgmt.cloud -Credential $Cred

    $ResultJson = Get-UcsCentralOrgDomainGroup -UcsCentral $UCSCentralHandle | Sort-Object Dn
    $ResultJson | ConvertTo-Json -Depth 50 | Out-File $UcsJsonConfigFile
    $UCSCentralHandle = Disconnect-UcsCentral -UcsCentral $UCSCentralHandle -Verbose
}
#Exportfrom-UcsCentralDomainToJson

function Importto-UcsCentralDomainFromJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucscentraldomain.json"
    )
    $Configuration = Get-Content -Path $UcsJsonConfigFile -Raw | ConvertFrom-Json
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $UCSCentralHandle = Connect-UcsCentral -Name ucs-central.gmgmt.cloud -Credential $Cred
    foreach ($domain in $Configuration)
    {
        Write-Host "Checking for Domain `"$($domain.Name)`" ..." -ForegroundColor Green
        $UCSCentralDomain = Get-UcsCentralOrgDomainGroup -Dn $domain.Dn -UcsCentral $UCSCentralHandle
        if ($UCSCentralDomain -eq $null)
        {
            Write-Host "Domain `"$($domain.Name)`" is not present, creating now..." -ForegroundColor Yellow
            $dn = $domain.Dn
            $ParentDn = $dn.Substring(0,$dn.LastIndexOf("/"))
            $ParentDomain = Get-UcsCentralOrgDomainGroup -Dn $ParentDn -UcsCentral $UCSCentralHandle
            $UCSCentralDomain = Add-UcsCentralOrgDomainGroup -OrgDomainGroup $ParentDomain -Name $domain.Name -Descr $domain.Descr -UcsCentral $UCSCentralHandle -Verbose -ErrorAction SilentlyContinue
        }
    }
    $UCSCentralHandle = Disconnect-UcsCentral -UcsCentral $UCSCentralHandle -Verbose
}
#Importto-UcsCentralDomainFromJson

function Exportfrom-UcsMACPoolToJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsMacPool.json"
    )
    Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true >> $null
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $fi1upbru01 = Connect-Ucs -Name fi1upbru01.eulnd01.gmgmt.cloud -Credential $Cred
    $fi1inbru02 = Connect-Ucs -Name fi1inbru02.eulnd01.gmgmt.cloud -Credential $Cred

    $ResultJson = @()
    $MacPools = Get-UcsMacPool
    foreach ($MacPool in $MacPools)
    {
        $MacMemberBlock = Get-UcsMacMemberBlock -MacPool $MacPool
        $MacPool | Add-Member -NotePropertyName MacMemberBlock -NotePropertyValue $MacMemberBlock
        $ResultJson += $MacPool
    }
    $ResultJson | ConvertTo-Json -Depth 999 | Out-File -FilePath $UcsJsonConfigFile
    Disconnect-Ucs -Ucs $fi1upbru01
    Disconnect-Ucs -Ucs $fi1inbru02
}
#Exportfrom-UcsMACPoolToJson

function Importto-UcsCentralMACPoolFromJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsMacPool.json"
    )
    $Configuration = Get-Content -Path $UcsJsonConfigFile -Raw | ConvertFrom-Json
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $UCSCentralHandle = Connect-UcsCentral -Name ucs-central.gmgmt.cloud -Credential $Cred
    foreach ($MacPool in $Configuration)
    {
        Write-Host "Checking for MacPool `"$($MacPool.Name)`" ..." -ForegroundColor Green
        $UCSCentralMacPool = Get-UCSCentralMacPool -Dn $MacPool.Dn -UcsCentral $UCSCentralHandle
        if ($UCSCentralMacPool -eq $null)
        {
            Write-Host "MacPool `"$($MacPool.Name)`" is not present, creating now..." -ForegroundColor Yellow
            $dn = $MacPool.Dn
            $ParentDn = $dn.Substring(0,$dn.LastIndexOf("/"))
            $ParentOrg = Get-UcsCentralOrg -Dn $ParentDn -UcsCentral $UCSCentralHandle
            $UCSCentralMacPool = Add-UcsCentralMacPool -Org $ParentOrg -Name $MacPool.Name -Descr $MacPool.Descr -UcsCentral $UCSCentralHandle -Verbose -ErrorAction SilentlyContinue
        }
        if ($MacPool.MacMemberBlock -ne $null)
        {
            Write-Host "Checking for MacMemberBlock `"$($MacPool.MacMemberBlock.Rn)`" ..." -ForegroundColor Green
            $MacMemberBlock = Get-UcsCentralMacMemberBlock -Dn $MacPool.MacMemberBlock.Dn -UcsCentral $UCSCentralHandle
            if ($MacMemberBlock -eq $null)
            {
                Write-Host "MacMemberBlock `"$($MacPool.MacMemberBlock.Rn)`" is not present, creating now..." -ForegroundColor Yellow
                $MacMemberBlock = Add-UcsCentralMacMemberBlock -MacPool $UCSCentralMacPool -From $MacPool.MacMemberBlock.From -To $MacPool.MacMemberBlock.To -UcsCentral $UCSCentralHandle -Verbose
            }
        }
    }
    $UCSCentralHandle = Disconnect-UcsCentral -UcsCentral $UCSCentralHandle -Verbose
}
#Importto-UcsCentralMACPoolFromJson

function Exportfrom-UcsQosPolicyToJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsQosPolicy.json"
    )
    Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true >> $null
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $fi1upbru01 = Connect-Ucs -Name fi1upbru01.eulnd01.gmgmt.cloud -Credential $Cred
    $fi1inbru02 = Connect-Ucs -Name fi1inbru02.eulnd01.gmgmt.cloud -Credential $Cred

    $ResultJson = @()
    $QosPolicies = Get-UcsQosPolicy
    foreach ($QosPolicy in $QosPolicies)
    {
        $VnicEgressPolicy = Get-UcsVnicEgressPolicy -QosPolicy $QosPolicy
        $QosPolicy | Add-Member -NotePropertyName VnicEgressPolicy -NotePropertyValue $VnicEgressPolicy
        $ResultJson += $QosPolicy
    }
    $ResultJson | ConvertTo-Json -Depth 999 | Out-File -FilePath $UcsJsonConfigFile
    Disconnect-Ucs -Ucs $fi1upbru01
    Disconnect-Ucs -Ucs $fi1inbru02
}
#Exportfrom-UcsQosPolicyToJson

function Importto-UcsCentralQosPolicyFromJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsQosPolicy.json"
    )
    $Configuration = Get-Content -Path $UcsJsonConfigFile -Raw | ConvertFrom-Json
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $UCSCentralHandle = Connect-UcsCentral -Name ucs-central.gmgmt.cloud -Credential $Cred
    foreach ($QosPolicy in $Configuration)
    {
        Write-Host "Checking for QosPolicy `"$($QosPolicy.Name)`" ..." -ForegroundColor Green
        $UCSCentralQosPolicy = Get-UCSCentralQosPolicy -Dn $QosPolicy.Dn -UcsCentral $UCSCentralHandle
        if ($UCSCentralQosPolicy -eq $null)
        {
            Write-Host "QosPolicy `"$($QosPolicy.Name)`" is not present, creating now..." -ForegroundColor Yellow
            $dn = $QosPolicy.Dn
            $ParentDn = $dn.Substring(0,$dn.LastIndexOf("/"))
            $ParentOrg = Get-UcsCentralOrg -Dn $ParentDn -UcsCentral $UCSCentralHandle
            $UCSCentralQosPolicy = Add-UCSCentralQosPolicy -Org $ParentOrg -Name $QosPolicy.Name -Descr $QosPolicy.Descr -UcsCentral $UCSCentralHandle -Verbose -ErrorAction SilentlyContinue
        }
        if ($QosPolicy.VnicEgressPolicy -ne $null)
        {
            Write-Host "Checking for VnicEgressPolicy `"$($QosPolicy.VnicEgressPolicy.Dn)`" ..." -ForegroundColor Green
            $VnicEgressPolicy = Get-UcsCentralVnicEgressPolicy -Dn $QosPolicy.VnicEgressPolicy.Dn -UcsCentral $UCSCentralHandle
            if ($VnicEgressPolicy -eq $null)
            {
                Write-Host "VnicEgressPolicy `"$($QosPolicy.VnicEgressPolicy.Dn)`" is not present, creating now..." -ForegroundColor Yellow
                $VnicEgressPolicy = Add-UcsCentralVnicEgressPolicy -QosPolicy $UCSCentralQosPolicy -ModifyPresent -Burst $QosPolicy.VnicEgressPolicy.Burst -HostControl $QosPolicy.VnicEgressPolicy.HostControl -Name $QosPolicy.VnicEgressPolicy.Name -Prio $QosPolicy.VnicEgressPolicy.Prio -Rate $QosPolicy.VnicEgressPolicy.Rate -UcsCentral $UCSCentralHandle -Verbose
            }
        }
    }
    $UCSCentralHandle = Disconnect-UcsCentral -UcsCentral $UCSCentralHandle -Verbose
}
#Importto-UcsCentralQosPolicyFromJson

function Exportfrom-UcsNetworkControlPolicyToJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsNetworkControlPolicy.json"
    )
    Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true >> $null
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $fi1upbru01 = Connect-Ucs -Name fi1upbru01.eulnd01.gmgmt.cloud -Credential $Cred
    $fi1inbru02 = Connect-Ucs -Name fi1inbru02.eulnd01.gmgmt.cloud -Credential $Cred

    $ResultJson = @()
    $NetworkControlPolicies = Get-UcsNetworkControlPolicy
    foreach ($NetworkControlPolicy in $NetworkControlPolicies)
    {
        $ResultJson += $NetworkControlPolicy
    }
    $ResultJson | ConvertTo-Json -Depth 999 | Out-File -FilePath $UcsJsonConfigFile
    Disconnect-Ucs -Ucs $fi1upbru01
    Disconnect-Ucs -Ucs $fi1inbru02
}
#Exportfrom-UcsNetworkControlPolicyToJson

function Importto-UcsCentralNetworkControlPolicyFromJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsNetworkControlPolicy.json"
    )
    $Configuration = Get-Content -Path $UcsJsonConfigFile -Raw | ConvertFrom-Json
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $UCSCentralHandle = Connect-UcsCentral -Name ucs-central.gmgmt.cloud -Credential $Cred
    foreach ($NetworkControlPolicy in $Configuration)
    {
        Write-Host "Checking for NetworkControlPolicy `"$($NetworkControlPolicy.Name)`" ..." -ForegroundColor Green
        $UCSCentralNetworkControlPolicy = Get-UcsCentralNetworkControlPolicy -Dn $NetworkControlPolicy.Dn -UcsCentral $UCSCentralHandle
        if ($UCSCentralNetworkControlPolicy -eq $null)
        {
            Write-Host "NetworkControlPolicy `"$($NetworkControlPolicy.Name)`" is not present, creating now..." -ForegroundColor Yellow
            $dn = $NetworkControlPolicy.Dn
            $ParentDn = $dn.Substring(0,$dn.LastIndexOf("/"))
            if ($ParentDn -ilike "org-*")
            {
                $ParentOrg = Get-UcsCentralOrg -Dn $ParentDn -UcsCentral $UCSCentralHandle
                $UCSCentralNetworkControlPolicy = Add-UcsCentralNetworkControlPolicy -Org $ParentOrg -Name $NetworkControlPolicy.Name -Descr $NetworkControlPolicy.Descr -Cdp $NetworkControlPolicy.Cdp -LldpReceive $NetworkControlPolicy.LldpReceive -LldpTransmit $NetworkControlPolicy.LldpTransmit -MacRegisterMode $NetworkControlPolicy.MacRegisterMode -UplinkFailAction $NetworkControlPolicy.UplinkFailAction -ModifyPresent -UcsCentral $UCSCentralHandle -Verbose -ErrorAction SilentlyContinue
            }
        }
    }
    $UCSCentralHandle = Disconnect-UcsCentral -UcsCentral $UCSCentralHandle -Verbose
}
#Importto-UcsCentralNetworkControlPolicyFromJson

function Exportfrom-UcsVnicTemplateToJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsvNicTempate.json"
    )
    Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true >> $null
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $fi1upbru01 = Connect-Ucs -Name fi1upbru01.eulnd01.gmgmt.cloud -Credential $Cred
    $fi1inbru02 = Connect-Ucs -Name fi1inbru02.eulnd01.gmgmt.cloud -Credential $Cred

    $ResultJson = @()
    $VnicTemplates = Get-UcsVnicTemplate
    foreach ($VnicTemplate in $VnicTemplates)
    {
        $VnicInterface = Get-UcsVnicInterface -VnicTemplate $VnicTemplate
        $VnicTemplate | Add-Member -NotePropertyName VnicInterface -NotePropertyValue $VnicInterface
        $ResultJson += $VnicTemplate
    }
    $ResultJson | ConvertTo-Json -Depth 999 | Out-File -FilePath $UcsJsonConfigFile
    Disconnect-Ucs -Ucs $fi1upbru01
    Disconnect-Ucs -Ucs $fi1inbru02
}
#Exportfrom-UcsVnicTemplateToJson

function Importto-UcsCentralVnicTemplateFromJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsvNicTempate.json"
    )
    $Configuration = Get-Content -Path $UcsJsonConfigFile -Raw | ConvertFrom-Json
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $UCSCentralHandle = Connect-UcsCentral -Name ucs-central.gmgmt.cloud -Credential $Cred
    foreach ($VnicTemplate in $Configuration)
    {
        Write-Host "Checking for VnicTemplate `"$($VnicTemplate.Name)`" ..." -ForegroundColor Green
        $UCSCentralVnicTemplate = Get-UcsCentralVnicTemplate -Dn $VnicTemplate.Dn -UcsCentral $UCSCentralHandle
        if ($UCSCentralVnicTemplate -eq $null)
        {
            Write-Host "VnicTemplate `"$($VnicTemplate.Name)`" is not present, creating now..." -ForegroundColor Yellow
            $dn = $VnicTemplate.Dn
            $ParentDn = $dn.Substring(0,$dn.LastIndexOf("/"))
            $ParentOrg = Get-UcsCentralOrg -Dn $ParentDn -UcsCentral $UCSCentralHandle
            if ($VnicTemplate.CdnSource -eq $null)
            {
                $UCSCentralVnicTemplate = Add-UcsCentralVnicTemplate -UcsCentral $UCSCentralHandle -Verbose -ErrorAction SilentlyContinue -CdnSource vnic-name -Org $ParentOrg -Name $VnicTemplate.Name -Descr $VnicTemplate.Descr -IdentPoolName $VnicTemplate.IdentPoolName -Mtu $VnicTemplate.Mtu -NwCtrlPolicyName $VnicTemplate.NwCtrlPolicyName -PinToGroupName $VnicTemplate.PinToGroupName -QosPolicyName $VnicTemplate.QosPolicyName -StatsPolicyName $VnicTemplate.StatsPolicyName -SwitchId $VnicTemplate.SwitchId -TemplType $VnicTemplate.TemplType -ModifyPresent
            }
            else
            {
                $UCSCentralVnicTemplate = Add-UcsCentralVnicTemplate -UcsCentral $UCSCentralHandle -Verbose -ErrorAction SilentlyContinue -CdnSource user-defined -AdminCdnName $VnicTemplate.AdminCdnName -Org $ParentOrg -Name $VnicTemplate.Name -Descr $VnicTemplate.Descr -IdentPoolName $VnicTemplate.IdentPoolName -Mtu $VnicTemplate.Mtu -NwCtrlPolicyName $VnicTemplate.NwCtrlPolicyName -PinToGroupName $VnicTemplate.PinToGroupName -QosPolicyName $VnicTemplate.QosPolicyName -StatsPolicyName $VnicTemplate.StatsPolicyName -SwitchId $VnicTemplate.SwitchId -TemplType $VnicTemplate.TemplType -ModifyPresent
            }
        }
        if ($VnicTemplate.VnicInterface -ne $null)
        {
            foreach ($vNicInterface_item in $VnicTemplate.VnicInterface)
            {
                Write-Host "Checking for VnicInterface `"$($vNicInterface_item.Name)`" ..." -ForegroundColor Green
                $VnicInterface = Get-UcsCentralVnicInterface -UcsCentral $UCSCentralHandle -Dn $vNicInterface_item.Dn
                if ($VnicInterface -eq $null)
                {
                    Write-Host "VnicInterface `"$($vNicInterface_item.Name)`" is not present, creating now..." -ForegroundColor Yellow
                    $VnicInterface = Add-UcsCentralVnicInterface -UcsCentral $UCSCentralHandle -Verbose -VnicTemplate $UCSCentralVnicTemplate -Name $vNicInterface_item.Name -DefaultNet $vNicInterface_item.DefaultNet -ModifyPresent
                }
            }
        }
    }
    $UCSCentralHandle = Disconnect-UcsCentral -UcsCentral $UCSCentralHandle -Verbose
}
#Importto-UcsCentralVnicTemplateFromJson

function Exportfrom-UcsBiosPolicyToJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsBiosPolicy.json"
    )
    Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true >> $null
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $fi1upbru01 = Connect-Ucs -Name fi1upbru01.eulnd01.gmgmt.cloud -Credential $Cred
    $fi1inbru02 = Connect-Ucs -Name fi1inbru02.eulnd01.gmgmt.cloud -Credential $Cred
    $ResultJson = @()

    $BiosPolicies = Get-UcsBiosPolicy
    foreach ($BiosPolicy in $BiosPolicies)
    {
        $BiosChildConfigurations = Get-UcsChild -ManagedObject (Get-UcsManagedObject -Dn $BiosPolicy.Dn -Ucs $BiosPolicy.Ucs) -Ucs $BiosPolicy.Ucs
        $BiosPolicyConfiguration = New-Object PSObject
        foreach ($BiosChildConfiguration in $BiosChildConfigurations)
        {
            $BiosPolicyConfiguration | Add-Member -NotePropertyName $BiosChildConfiguration.Rn -NotePropertyValue $BiosChildConfiguration
        }
        $BiosPolicy | Add-Member -NotePropertyName BiosPolicyConfiguration -NotePropertyValue $BiosPolicyConfiguration
        $ResultJson += $BiosPolicy
    }

    $ResultJson | ConvertTo-Json -Depth 999 | Out-File -FilePath $UcsJsonConfigFile
    Disconnect-Ucs -Ucs $fi1upbru01
    Disconnect-Ucs -Ucs $fi1inbru02
}
#Exportfrom-UcsBiosPolicyToJson

function Importto-UcsCentralBiosPolicyFromJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsBiosPolicy.json"
    )
    $Configuration = Get-Content -Path $UcsJsonConfigFile -Raw | ConvertFrom-Json
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $UCSCentralHandle = Connect-UcsCentral -Name ucs-central.gmgmt.cloud -Credential $Cred

    foreach ($BiosPolicy in $Configuration)
    {
        Write-Host "Checking for BiosPolicy `"$($BiosPolicy.Name)`" ..." -ForegroundColor Green
        $UCSCentralBiosPolicy = Get-UcsCentralBiosPolicy -Dn $BiosPolicy.Dn -UcsCentral $UCSCentralHandle
        if ($UCSCentralBiosPolicy -eq $null)
        {
            Write-Host "BiosPolicy `"$($BiosPolicy.Name)`" is not present, creating now..." -ForegroundColor Yellow
            $dn = $BiosPolicy.Dn
            $ParentDn = $dn.Substring(0,$dn.LastIndexOf("/"))
            $ParentOrg = Get-UcsCentralOrg -Dn $ParentDn -UcsCentral $UCSCentralHandle
            $UCSCentralBiosPolicy = Add-UcsCentralBiosPolicy -Org $ParentOrg -Name $BiosPolicy.Name -Descr $BiosPolicy.Descr -RebootOnUpdate $BiosPolicy.RebootOnUpdate -ModifyPresent -UcsCentral $UCSCentralHandle -Verbose
        }
        $BiosPolicyConfiguration = $BiosPolicy.BiosPolicyConfiguration
        $arrayfilter = "PropAcl","Sacl","SupportedByDefault","Ucs","UcsCentral","Dn","Rn","Status","XtraProperty"
        foreach ($BiosPolicyConfig in $BiosPolicyConfiguration.psobject.Properties)
        {
            $UcsCentralmo = Get-UcsCentralManagedObject -Dn $BiosPolicyConfig.Value.Dn
            $UcsCentralmoCompare = $UcsCentralmo.PsObject.Properties | Where-Object {$arrayfilter -inotcontains $_.Name}
            $UcsmoCompare = $BiosPolicyConfig.Value.PsObject.Properties | Where-Object {$arrayfilter -inotcontains $_.Name}
            $hashparam = @{}
            foreach	($UcsCentralco in $UcsCentralmoCompare)
            {
	            $Ucsco = $UcsmoCompare | ? {$_.Name -eq $UcsCentralco.Name}
                if ($Ucsco -ne $null) 
                {
                    if ($UcsCentralco.Value -ne $Ucsco.Value)
                    {
                        Write-Host "UCS $($Ucsco.Name) has value: `"$($Ucsco.Value)`" but UCSCentral $($UcsCentralco.Name) has value: `"$($UcsCentralco.Value)`", changing now..." -ForegroundColor Yellow
                        $hashparam.Add($Ucsco.Name,$Ucsco.Value)
                    }
                }
            }

            if ($hashparam.count -ge 1)
            {
                $UcsCentralmo = Set-UcsCentralManagedObject -ManagedObject $UcsCentralmo -PropertyMap $hashparam -Confirm: $false -Force
            }
        }
    }

    $UCSCentralHandle = Disconnect-UcsCentral -UcsCentral $UCSCentralHandle -Verbose
}
#Importto-UcsCentralBiosPolicyFromJson

function Exportfrom-UcsBootPolicyToJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsBootPolicy.json"
    )
    Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true >> $null
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $fi1upbru01 = Connect-Ucs -Name fi1upbru01.eulnd01.gmgmt.cloud -Credential $Cred
    $fi1inbru02 = Connect-Ucs -Name fi1inbru02.eulnd01.gmgmt.cloud -Credential $Cred
    $ResultJson = @()

    $BootPolicies = Get-UcsBootPolicy
    foreach ($BootPolicy in $BootPolicies)
    {
        $BootChildConfigurations = Get-UcsChild -ManagedObject (Get-UcsManagedObject -Dn $BootPolicy.Dn -Ucs $BootPolicy.Ucs) -Ucs $BootPolicy.Ucs
        $BootPolicyConfiguration = New-Object PSObject
        foreach ($BootChildConfiguration in $BootChildConfigurations)
        {
            $BootChildConfiguration | Add-Member -NotePropertyName ClassId -NotePropertyValue $BootChildConfiguration.GetType().Name
            $BootPolicyConfiguration | Add-Member -NotePropertyName $BootChildConfiguration.Rn -NotePropertyValue $BootChildConfiguration
        }
        $BootPolicy | Add-Member -NotePropertyName BootPolicyConfiguration -NotePropertyValue $BootPolicyConfiguration
        $ResultJson += $BootPolicy
    }

    $ResultJson | ConvertTo-Json -Depth 999 | Out-File -FilePath $UcsJsonConfigFile
    Disconnect-Ucs -Ucs $fi1upbru01
    Disconnect-Ucs -Ucs $fi1inbru02
}
#Exportfrom-UcsBootPolicyToJson

function Importto-UcsCentralBootPolicyFromJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsBootPolicy.json"
    )
    $Configuration = Get-Content -Path $UcsJsonConfigFile -Raw | ConvertFrom-Json
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $UCSCentralHandle = Connect-UcsCentral -Name ucs-central.gmgmt.cloud -Credential $Cred
    
    foreach ($BootPolicy in $Configuration)
    {
        Write-Host "Checking for BootPolicy `"$($BootPolicy.Name)`" ..." -ForegroundColor Green
        $UCSCentralBootPolicy = Get-UcsCentralBootPolicy -Dn $BootPolicy.Dn -UcsCentral $UCSCentralHandle
        if ($UCSCentralBootPolicy -eq $null)
        {
            Write-Host "BootPolicy `"$($BootPolicy.Name)`" is not present, creating now..." -ForegroundColor Yellow
            $dn = $BootPolicy.Dn
            $ParentDn = $dn.Substring(0,$dn.LastIndexOf("/"))
            $ParentOrg = Get-UcsCentralOrg -Dn $ParentDn -UcsCentral $UCSCentralHandle
            $UCSCentralBootPolicy = Add-UcsCentralBootPolicy -Org $ParentOrg -Name $BootPolicy.Name -Descr $BootPolicy.Descr -BootMode $BootPolicy.BootMode -Purpose $BootPolicy.Purpose -RebootOnUpdate $BootPolicy.RebootOnUpdate -EnforceVnicName $BootPolicy.EnforceVnicName -ModifyPresent -UcsCentral $UCSCentralHandle -Verbose
        }
        $BootPolicyConfiguration = $BootPolicy.BootPolicyConfiguration
        $arrayfilter = "Type","PropAcl","Sacl","Ucs","UcsCentral","Status","XtraProperty","ClassId","Dn","Rn"
        foreach ($BootPolicyConfig in $BootPolicyConfiguration.psobject.Properties)
        {
            $sc = $sc = "Cisco.UcsCentral.$($BootPolicyConfig.Value.ClassId)" -as [type]
            if ($sc::AccessMeta.Access -eq "ReadOnly")
            {
                $arrayfilter += "Access"
            }
            $UcsmoCompare = $BootPolicyConfig.Value.PsObject.Properties | Where-Object {($arrayfilter -inotcontains $_.Name) -and ($_.IsSettable -eq "True")}
            $UcsCentralmo = Get-UcsCentralManagedObject -Dn $BootPolicyConfig.Value.Dn
            if ($UcsCentralmo -eq $null)
            {
                $hashparam = @{}
                foreach ($Ucsco in $UcsmoCompare)
                {
                    $hashparam.Add($Ucsco.Name,$Ucsco.Value)
                }
                $UcsCentralmo = Add-UcsCentralManagedObject -Parent $UCSCentralBootPolicy -ClassId $BootPolicyConfig.Value.ClassId -PropertyMap $hashparam
            }
            else
            {
                $UcsCentralmoCompare = $UcsCentralmo.PsObject.Properties | Where-Object {$arrayfilter -inotcontains $_.Name}
                $hashparam = @{}
                foreach ($UcsCentralco in $UcsCentralmoCompare)
                {
                    $Ucsco = $UcsmoCompare | ? {$_.Name -eq $UcsCentralco.Name}
                    if ($Ucsco -ne $null) 
                    {
                        if ($UcsCentralco.Value -ne $Ucsco.Value)
                        {
                            Write-Host "UCS $($Ucsco.Name) has value: `"$($Ucsco.Value)`" but UCSCentral $($UcsCentralco.Name) has value: `"$($UcsCentralco.Value)`", changing now..." -ForegroundColor Yellow
                            $hashparam.Add($Ucsco.Name,$Ucsco.Value)
                        }
                    }
                }

                if ($hashparam.count -ge 1)
                {
                    $UcsCentralmo = Set-UcsCentralManagedObject -ManagedObject $UcsCentralmo -PropertyMap $hashparam -Confirm: $false -Force
                }
            }
        }
    }
    
    $UCSCentralHandle = Disconnect-UcsCentral -UcsCentral $UCSCentralHandle -Verbose
}
#Importto-UcsCentralBootPolicyFromJson

function Exportfrom-UcsIpPoolToJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsIpPool.json"
    )
    Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true >> $null
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $fi1upbru01 = Connect-Ucs -Name fi1upbru01.eulnd01.gmgmt.cloud -Credential $Cred
    $fi1inbru02 = Connect-Ucs -Name fi1inbru02.eulnd01.gmgmt.cloud -Credential $Cred

    $ResultJson = @()
    $IpPools = Get-UcsIpPool
    foreach ($IpPool in $IpPools)
    {
        $IpPoolBlock = Get-UcsIpPoolBlock -IpPool $IpPool
        $IpPool | Add-Member -NotePropertyName IpPoolBlock -NotePropertyValue $IpPoolBlock
        $ResultJson += $IpPool
    }
    $ResultJson | ConvertTo-Json -Depth 999 | Out-File -FilePath $UcsJsonConfigFile
    Disconnect-Ucs -Ucs $fi1upbru01
    Disconnect-Ucs -Ucs $fi1inbru02
}
#Exportfrom-UcsIpPoolToJson

function Importto-UcsCentralIpPoolFromJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsIpPool.json"
    )
    $Configuration = Get-Content -Path $UcsJsonConfigFile -Raw | ConvertFrom-Json
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $UCSCentralHandle = Connect-UcsCentral -Name ucs-central.gmgmt.cloud -Credential $Cred
    foreach ($IpPool in $Configuration)
    {
        Write-Host "Checking for IpPool `"$($IpPool.Name)`" ..." -ForegroundColor Green
        $UCSCentralIpPool = Get-UCSCentralIpPool -Dn $IpPool.Dn -UcsCentral $UCSCentralHandle
        if ($UCSCentralIpPool -eq $null)
        {
            Write-Host "IpPool `"$($IpPool.Name)`" is not present, creating now..." -ForegroundColor Yellow
            $dn = $IpPool.Dn
            $ParentDn = $dn.Substring(0,$dn.LastIndexOf("/"))
            $ParentOrg = Get-UcsCentralOrg -Dn $ParentDn -UcsCentral $UCSCentralHandle
            $UCSCentralIpPool = Add-UCSCentralIpPool -Org $ParentOrg -Name $IpPool.Name -Descr $IpPool.Descr -UcsCentral $UCSCentralHandle -Verbose -ErrorAction SilentlyContinue
        }
        if ($IpPool.IpPoolBlock -ne $null)
        {
            Write-Host "Checking for IpPoolBlock `"$($IpPool.IpPoolBlock.Rn)`" ..." -ForegroundColor Green
            $IpPoolBlock = Get-UcsCentralIpPoolBlock -Dn $IpPool.IpPoolBlock.Dn -UcsCentral $UCSCentralHandle
            if ($IpPoolBlock -eq $null)
            {
                Write-Host "IpPoolBlock `"$($IpPool.IpPoolBlock.Rn)`" is not present, creating now..." -ForegroundColor Yellow
                $IpPoolBlock = Add-UcsCentralIpPoolBlock -IpPool $UCSCentralIpPool -From $IpPool.IpPoolBlock.From -To $IpPool.IpPoolBlock.To -DefGw $IpPool.IpPoolBlock.DefGw -PrimDns $IpPool.IpPoolBlock.PrimDns -SecDns $IpPool.IpPoolBlock.SecDns -Subnet $IpPool.IpPoolBlock.Subnet -UcsCentral $UCSCentralHandle -Verbose
            }
        }
    }
    $UCSCentralHandle = Disconnect-UcsCentral -UcsCentral $UCSCentralHandle -Verbose
}
#Importto-UcsCentralIpPoolFromJson

function Exportfrom-UcsHostFirmwarePackToJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsHostFirmwarePack.json"
    )
    Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true >> $null
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $fi1upbru01 = Connect-Ucs -Name fi1upbru01.eulnd01.gmgmt.cloud -Credential $Cred
    $fi1inbru02 = Connect-Ucs -Name fi1inbru02.eulnd01.gmgmt.cloud -Credential $Cred

    $ResultJson = @()
    $FirmwareComputeHostPacks = Get-UcsFirmwareComputeHostPack
    foreach ($FirmwareComputeHostPack in $FirmwareComputeHostPacks)
    {
        $FirmwareExcludeServerComponent = Get-UcsFirmwareExcludeServerComponent -FirmwareComputeHostPack $FirmwareComputeHostPack
        $FirmwareComputeHostPack | Add-Member -NotePropertyName FirmwareExcludeServerComponent -NotePropertyValue $FirmwareExcludeServerComponent
        $ResultJson += $FirmwareComputeHostPack
    }
    $ResultJson | ConvertTo-Json -Depth 999 | Out-File -FilePath $UcsJsonConfigFile
    Disconnect-Ucs -Ucs $fi1upbru01
    Disconnect-Ucs -Ucs $fi1inbru02
}
Exportfrom-UcsHostFirmwarePackToJson

function Exportfrom-UcsToJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsBiosPolicy.json"
    )
    Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true >> $null
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $fi1upbru01 = Connect-Ucs -Name fi1upbru01.eulnd01.gmgmt.cloud -Credential $Cred
    $fi1inbru02 = Connect-Ucs -Name fi1inbru02.eulnd01.gmgmt.cloud -Credential $Cred
    $ResultJson = @()

    #Export Method

    $ResultJson | ConvertTo-Json -Depth 999 | Out-File -FilePath $UcsJsonConfigFile
    Disconnect-Ucs -Ucs $fi1upbru01
    Disconnect-Ucs -Ucs $fi1inbru02
}
#Exportfrom-UcsToJson

function Importto-UcsCentralFromJson
{
    param(
        [string]$UcsJsonConfigFile = "H:\Documents\UCS\json\ucsNetworkControlPolicy.json"
    )
    $Configuration = Get-Content -Path $UcsJsonConfigFile -Raw | ConvertFrom-Json
    $Username = "ucs-GMGMT.CLOUD\ryang"
    $Password = Read-Host "Please enter password for $Username" -AsSecureString
    $Cred = New-Object PSCredential -ArgumentList $Username,$Password
    $UCSCentralHandle = Connect-UcsCentral -Name ucs-central.gmgmt.cloud -Credential $Cred
    
    #Import Method
    
    $UCSCentralHandle = Disconnect-UcsCentral -UcsCentral $UCSCentralHandle -Verbose
}
#Importto-UcsToJson