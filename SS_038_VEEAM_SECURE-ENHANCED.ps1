# =======================================================
# NAME: SS_038_VEEAM_SECURE-ENHANCED.ps1
# AUTHOR: GUILLEMARD, Erwan, PERSONNAL PROPRIETY
# DATE: 2024/04/12
#
# KEYWORDS: VEEAM
# 2024/04/12 - 1.0.0 : Script creation
# 2024/05/22 - 1.0.1 : Logtrace
# 2024/09/04 - 1.0.2 : Add new recommandations applied on 12.2.x
#                      LSASS as a protected process
#                      NetBIOS disabled
# COMMENTS: 
#
#Requires -Version 3.0
#https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
# =======================================================

cd "C:\Users\ErwanGUILLEMARD\OneDrive\Personnel\Projet\Scripts\SS_038_VEEAM-ENHANCED"
$_const_debug = $true

if($_const_debug){
    $DebugPreference="Continue"
}else{
    $DebugPreference="SilentlyContinue"
}

$_const_currentDate=Get-Date -Format 'yyyyMMdd_HHmmss'
$_const_LogDirectory="$PSScriptRoot\logs\"
$_const_LogNameFileInventory="$($_const_currentDate)_InitialServer_Settings.txt"
$_const_LogNameFileSetRecommandation="$($_const_currentDate)_SetRecommandations.txt"
$_const_InventoryPath=$_const_LogDirectory+$_const_LogNameFileInventory
$_const_RecommandationsPath=$_const_LogDirectory+$_const_LogNameFileSetRecommandation

function checkPrerequiresScript {
    
}

#Restored all admin shared visbility
function EditRegistry {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)][String]$Path,
        [Parameter(Mandatory=$true)][String]$Name,
        [Parameter(Mandatory=$true)][String]$Type,
        [Parameter(Mandatory=$true)][String]$Value
    )
    #Check if Type are correct : String(REG_SZ), Binary(REG_BINARY), DWORD, QWORD, MultiString(REG_MULTI_SZ), ExpandString (REG_EXPAND_SZ)
    switch ($Type){
        String{
            Write-Debug "$($Type) match with String (REG_SZ)"
            "$(Date -Format o) -    -  REGEDIT : Type=$($Type) match with REG_SZ" >> $_const_RecommandationsPath
        }
        Binary{
            Write-Debug "$($Type) match with Binary (REG_BINARY)"
            "$(Date -Format o) -    -  REGEDIT : Type=$($Type) match with REG_BINARY" >> $_const_RecommandationsPath
        }
        DWORD{
            Write-Debug "$($Type) match with DWORD"
            "$(Date -Format o) -    -  REGEDIT : Type=$($Type) match with DWORD" >> $_const_RecommandationsPath
            #Convert Value String to int if value is different to String
            $Value=[int]$Value
        }
        QWORD{
            Write-Debug "$($Type) match with QWORD"
            "$(Date -Format o) -    -  REGEDIT : Type=$($Type) match with QWORD" >> $_const_RecommandationsPath
            #Convert Value String to int if value is different to String
            $Value=[int]$Value
        }
        MultiString{
            Write-Debug "$($Type) match with MultiString (REG_MUTLI_SZ)"
            "$(Date -Format o) -    -  REGEDIT : Type=$($Type) match with REG_MUTLI_SZ" >> $_const_RecommandationsPath
        }
        ExpandString{
            Write-Debug "$($Type) match with ExpandString (REG_EXPAND_SZ)"
            "$(Date -Format o) -    -  REGEDIT : Type=$($Type) match with REG_EXPAND_SZ" >> $_const_RecommandationsPath
        }
        Default{
          Write-Host "$($Type) not correct, Type must be REG_SZ, REG_BINARY, DWORD, QWORD, REG_MULTI_SZ, REG_EXPAND_SZ"
          "$(Date -Format o) -    -  REGEDIT : Type=$($Type)  no match with REG_SZ, REG_BINARY, DWORD, QWORD, REG_MULTI_SZ, REG_EXPAND_SZ" >> $_const_RecommandationsPath
          return $false  
        }    
    }
    #check if Property registry exist
    $regLocalPropertyExist=(Get-Item -Path $Path).property -contains $Name
    #Exist, check value
    if($regLocalPropertyExist){
        "$(Date -Format o) -    -  REGEDIT : Value=$($Name) exists : Path=$($Path)" >> $_const_RecommandationsPath
        $regPropertyValue=Get-ItemPropertyValue $Path $Name
        #Check if value is 1, else set it
        if($regPropertyValue -eq $Value){
            Write-Debug "Value is $($regPropertyValue)"
            "$(Date -Format o) -    -  REGEDIT : Value=$($Name) already defined to $($Value)" >> $_const_RecommandationsPath
        }
        else{
            Write-Debug "Value is $($regPropertyValue), need to be set to $($Value)"
            "$(Date -Format o) -    -  REGEDIT : Value=$($Name) defined to $($regPropertyValue) need to set to $($Value)" >> $_const_RecommandationsPath
            try{
                Set-ItemProperty -LiteralPath $Path `
                                 -Name $Name `
                                 -Type $Type `
                                 -Value $Value
                Write-Debug "Value defined for $($Name) as $($Type) Type to $($Value)"
                "$(Date -Format o) -    -  REGEDIT : Value=$($Name) set to $($Value) successfuly" >> $_const_RecommandationsPath
            }catch{
                Write-Debug "Error, can't define value for $($Name) as $($Type) Type to $($Value)"
                "$(Date -Format o) -    -  REGEDIT : Value=$($Name) can't be set to $($Value)" >> $_const_RecommandationsPath
            }
        }
    }
    #Not Exist, need to create registry DWORD
    else{
        Write-Debug "Registry doesn't exist : $($Path)\$($Name), need to create it $($Name) and set to $($Value) as $($Type) Type"
        "$(Date -Format o) -    -  REGEDIT : Registry doesn't exist : Path=$($Path) : Value=$($Name) : Need to create it $($Name) and set to $($Value) as $($Type)" >> $_const_RecommandationsPath
        try{
            Set-ItemProperty -LiteralPath $Path `
                                -Name $Name `
                                -Type $Type `
                                -Value $Value
            Write-Debug "Registry created $($Name) as $($Type) Type set to $($Value)"
            "$(Date -Format o) -    -  REGEDIT : Registry created successfuly : Value=$($Name) : Type=$($Type) : Value=$($Value)" >> $_const_RecommandationsPath
        }catch{
            Write-Debug "Error, can't define value for $($Name) as $($Type) Type set to $($Value) $_"
            "$(Date -Format o) -    -  REGEDIT : Registry can't be created and defined : Value=$($Name) : Type=$($Type) : Value=$($Value)" >> $_const_RecommandationsPath
        }  
    }
}

function Get-EditRegistry {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)][String]$Path,
        [Parameter(Mandatory=$true)][String]$Name
    )
    $regExist=Test-Path -Path $Path
    if($regExist){
        Write-Debug "$($Path) exists"
        "$(Date -Format o) -    - REGEDIT : Path=$($Path) exists" >> $_const_InventoryPath
        try{
            $regValue=Get-ItemPropertyValue -Path $Path -Name $Name
            $regType=$regValue.GetType() | Select Name
            switch($regType.Name){
                Int32{
                    Write-Debug "$($regType.Name) match with REG_DWORD"
                    "$(Date -Format o) -    - REGEDIT : Name=$($Name) : Type=REG_DWORD : Value=$($regValue)" >> $_const_InventoryPath
                }
                String{
                    Write-Debug "$($regType.Name) match with REG_SZ or REG_EXPAND_SZ"
                    "$(Date -Format o) -    - REGEDIT : Name=$($Name) : Type=REG_SZ or REG_EXPAND_SZ : Value=$($regValue)" >> $_const_InventoryPath
                }
                Int64{
                    Write-Debug "$($regType.Name) match with QWORD"
                    "$(Date -Format o) -    - REGEDIT : Name=$($Name) : Type=REG_QWORD : Value=$($regValue)" >> $_const_InventoryPath
                }
                Byte[]{
                    Write-Debug "$($regType.Name) match with REG_BINARY"
                    "$(Date -Format o) -    - REGEDIT : Name=$($Name) : Type=REG_BINARY : Value=$($regValue)" >> $_const_InventoryPath
                }
                String[]{
                    Write-Debug "$($regType.Name) match with MultiString (REG_MUTLI_SZ)"
                    "$(Date -Format o) -    - REGEDIT : Name=$($Name) : Type=REG_MUTLI_SZ : Value=$($regValue)" >> $_const_InventoryPath
                }
                Default{
                  Write-Host "$($regType.Name) not correct, Type must be REG_SZ, REG_BINARY, DWORD, QWORD, REG_MULTI_SZ, REG_EXPAND_SZ"
                  "$(Date -Format o) -     - REGEDIT : Name=$($Name) : Type=UNKNOW : Value=$($regValue)" >> $_const_InventoryPath  
                }    
            }    
        }catch{
            Write-Debug "$(Date -Format o) - REGEDIT : Name=$($Name) doesn't exist"
            "$(Date -Format o) -    - REGEDIT : Name=$($Name) doesn't exist" >> $_const_InventoryPath    
        }

    }
    else{
        Write-Debug "$($Path) doesn't exist"
        "$(Date -Format o) -     - REGEDIT : Path=$($Path) doesn't exist" >> $_const_InventoryPath
    }
}

#Function to managed Services
function ManageService {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)][String]$ServiceName,
        [Parameter(Mandatory=$true)][String]$StartupType
    )
    $services=Get-Service -Name $ServiceName
    #TurnOff the service
    if($services.Status -eq "Running"){
        try{
            Write-Debug "Service $($ServiceName) is Running, try to stop it"
            Set-Service -Name $ServiceName -Status Stopped
            Write-Debug "Service $($ServiceName) is now stopped"
        }catch{
            Write-Host "Service $($ServiceName) can't be stopped"
            Write-Host "$_"
        }
    }
    else{
        Write-Host "Service $($ServiceName) is set to $($services.Status)"
    }
    #Disabled the service to not start it at boot or manually
    if($services.StartType -ne "Disabled"){
        try{
            Write-Debug "Service $($ServiceName) will be set to Disabled StartupType"
            "$(Date -Format o) -    - Service $($ServiceName) : will be set to Disabled StartupType" >> $_const_RecommandationsPath
            Set-Service -Name $ServiceName -StartupType $StartupType
            Write-Debug "Service $($ServiceName) Startup type is now $($StartupType)"
            "$(Date -Format o) -    - Service $($ServiceName) : StartupType=$($StartupType) is now defined" >> $_const_RecommandationsPath
        }catch{
            Write-Debug "Service $($ServiceName) can't be $($StartupType)"
            Write-Debug "$_"
            "$(Date -Format o) -    - Service $($ServiceName) : StartupType can't be defined to $($StartupType)" >> $_const_RecommandationsPath    
        }    
    }
    else{
        Write-Debug "Service $($ServiceName) is set as Startype $($services.StartType)"
        "$(Date -Format o) -    - Service $($ServiceName) : StartupType=$($StartupType) is already defined" >> $_const_RecommandationsPath
    }
}

function Get-ManageService {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)][String]$ServiceName
    )
    try{
        $service=Get-Service -Name $ServiceName
        Write-Debug "$(Date -Format o) - Service $($ServiceName) : StartType=$($service.StartType) : ServiceStatus=$($service.Status)"
        "$(Date -Format o) -    - Service $($ServiceName) : StartType=$($service.StartType) : ServiceStatus=$($service.Status)" >> $_const_InventoryPath
    }catch{
        Write-Debug "Service $($ServiceName) unknow"
        Write-Debug "$_"
    }
}

#Function to managed Firewall Profile
function ManageFirewall {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)][boolean]$Enabled
    )
    $profilsFirewall=Get-NetFirewallProfile | Select-Object Name,Enabled
    foreach ($profil in $profilsFirewall){
        Write-Debug "Statment Firewall : $($profil.Name)"
        if($profil.Enabled){
            Write-Debug "Firewall $($profil.Name) is already enabled ($($profil.Enabled))"
            "$(Date -Format o) -    - Firewall : Profil=$($profil.Name) : Status=$($profil.Enabled) is already defined" >> $_const_RecommandationsPath
        }
        else{
            Write-Debug "Firewall $($profil.Name) is disabled ($($profil.Enabled))"
            "$(Date -Format o) -    - Firewall : Profil=$($profil.Name) : Status=$($profil.Enabled) is already defined" >> $_const_RecommandationsPath
            try{
                Set-NetFirewallProfile -Name $profil.Name -Enabled $profil.Enabled
                Write-Debug "Firewall $($profil.Name) is now enabled ($($profil.Enabled))"
                "$(Date -Format o) -    - Firewall : Profil=$($profil.Name) : Status=$($profil.Enabled) is now defined" >> $_const_RecommandationsPath
            }catch{
                Write-Debug "Firewall, $($profil.Name) can't be change"
                Write-Debug "$_" 
                "$(Date -Format o) -    - Firewall : Profil=$($profil.Name) : Status=$($profil.Enabled) can't be edited" >> $_const_RecommandationsPath
            }
        }
    }
}

function Get-ManageFirewall {
    $profilsFirewall=Get-NetFirewallProfile | Select-Object Name,Enabled
    foreach ($profil in $profilsFirewall){
        Write-Debug "Service $($ServiceName) : StartType=$($service.StartType) : ServiceStatus=$($service.Status)"
        "$(Date -Format o) -    - Firewall : Profil=$($profil.Name) : Status=$($profil.Enabled)" >> $_const_InventoryPath    
    }
}

#Function to realized initial configuration before to install VEEAM B&R
function Set-prerequiredSystemBeforeInstallVEEAM {
    if ($_const_debug){
        EditRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                     -Name "TEST_EGU" `
                     -Type "String" `
                     -Value "DEBUG" 
    }
    else{
        #Enable admin share visibility
        EditRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                     -Name "LocalAccountTokenFilterPolicy" `
                     -Type "DWORD" `
                     -Value "1"
        #Diskpart disable automount
        diskpart /s .\sources\diskpart_automout_disable.txt
    }       
}

#Function to managed SMBServer
function ManageSMBServer {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)][String]$Property,
        [Parameter(Mandatory=$true)][boolean]$Status
    )
    $value=Get-SmbServerConfiguration | Select-Object $Property
    Write-Debug "The property $($Property) is defined to $($value.EnableSMB1Protocol)"
    "$(Date -Format o) -    - SMBServer : Property=$($Property) : Value=$($value.EnableSMB1Protocol)" >> $_const_RecommandationsPath
    if($value.EnableSMB1Protocol -eq $Status){
        Write-Debug "Nothing to do the value is already defined"
        "$(Date -Format o) -    - SMBServer : Property=$($Property) : Status=$($Status) is already defined" >> $_const_RecommandationsPath
    }
    else{
        Write-Debug "The property $($Property) will be defined to $($Status)"
        "$(Date -Format o) -    - SMBServer : Property=$($Property) : Status=$($Status) must be defined" >> $_const_RecommandationsPath
        try{
            switch ($Property){
                EnableSMB1Protocol{
                    Set-SmbServerConfiguration -EnableSMB1Protocol $Status -Confirm:$false
                    Write-Debug "The property $($Property) is now set to $($Status)"
                    "$(Date -Format o) -    - SMBServer : Property=$($Property) : Status=$($Status) is set" >> $_const_RecommandationsPath
                }
                RequireSecuritySignature{
                    Set-SmbServerConfiguration -RequireSecuritySignature $Status -Confirm:$false
                    Write-Debug "The property $($Property) is now set to $($Status)"
                    "$(Date -Format o) -    - SMBServer : Property=$($Property) : Status=$($Status) is set" >> $_const_RecommandationsPath
                }
                EncryptData{
                    Set-SmbServerConfiguration -EncryptData $Status -Confirm:$false
                    Write-Debug "The property $($Property) is now set to $($Status)"
                    "$(Date -Format o) -    - SMBServer : Property=$($Property) : Status=$($Status) is set" >> $_const_RecommandationsPath
                }
                EnableSecuritySignature{
                    Set-SmbServerConfiguration -EnableSecuritySignature $Status -Confirm:$false
                    Write-Debug "The property $($Property) is now set to $($Status)"
                    "$(Date -Format o) -    - SMBServer : Property=$($Property) : Status=$($Status) is set" >> $_const_RecommandationsPath
                }
                Default{
                    Write-Debug "Property not supported in this script, please edit or contact erwanguillemard "
                    "$(Date -Format o) -    - SMBServer : Property=$($Property) is not supported by this script" >> $_const_RecommandationsPath
                }
            }
            
        }catch{
            Write-Debug "The property $($Property) can't be changed !"
            Write-Debug "$_"
            "$(Date -Format o) -    - SMBServer : Property=$($Property) : can't be changed or edited" >> $_const_RecommandationsPath
        }
    }   
}

function Get-ManageSMBServer {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)][String]$Property
    )
    try{
        $smbService=Get-SmbServerConfiguration | Select $Property
        Write-Debug "SMBServer : Property=$($Property) : Value=$($smbService.$Property)"
        "$(Date -Format o) -    - SMBServer : Property=$($Property) : Value=$($smbService.$Property)" >> $_const_InventoryPath  
    }catch{
        Write-Debug "SMBServer : Property=$($Property) doesn't exist"
        "$(Date -Format o) -    - SMBServer : Property=$($Property) doesn't exist" >> $_const_InventoryPath
    }
}

function Get-VEEAMSecurityComplianceRecommandation {
    "$(Date -Format o) - START - Get Current setting on $($env:COMPUTERNAME)" >> $_const_InventoryPath
    #Backup Infrastrcuture Security
    # 1 - Remote Desktop Services (TermService) should be disabled
    "$(Date -Format o) - 1 - Remote Desktop Services (TermService) should be disabled" >> $_const_InventoryPath
    ## Caution doesn't disable if VCC is used to managed the VB&R server
    Get-ManageService -ServiceName "TermService"
    # 2 - Remote Registry service (RemoteRegistry) should be disabled
    "$(Date -Format o) - 2 - Remote Registry service (RemoteRegistry) should be disabled" >> $_const_InventoryPath
    Get-ManageService -ServiceName "RemoteRegistry"
    # 3 - Windows Remote Management (WinRM) service should be disabled
    "$(Date -Format o) - 3 - Windows Remote Management (WinRM) service should be disabled" >> $_const_InventoryPath
    Get-ManageService -ServiceName "WinRM"
    # 4 - Windows Firewall should be enabled
    "$(Date -Format o) - 4 - Windows Firewall should be enabled" >> $_const_InventoryPath
    Get-ManageFirewall
    # 5 - WDigest credentials caching should be disabled
    "$(Date -Format o) - 5 - WDigest credentials caching should be disabled" >> $_const_InventoryPath
    Get-EditRegistry -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" `
                     -Name "UseLogonCredential"
    # 6 - Web Proxy Auto-Discovery service (WinHttpAutoProxySvc) should be disabled
    "$(Date -Format o) - 6 - Web Proxy Auto-Discovery service (WinHttpAutoProxySvc) should be disabled" >> $_const_InventoryPath
    Get-ManageService -ServiceName "WinHttpAutoProxySvc"
    Get-EditRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" `
                     -Name "DisableWpad"
    # 7 - Deprecated versions of SSL and TLS should be disabled
    "$(Date -Format o) - 7 - Deprecated versions of SSL and TLS should be disabled" >> $_const_InventoryPath
    #Disabled SSL/TLS
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" `
                     -Name "DisabledByDefault"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" `
                     -Name "DisabledByDefault"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" `
                     -Name "DisabledByDefault"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" `
                     -Name "DisabledByDefault"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" `
                     -Name "DisabledByDefault"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" `
                     -Name "DisabledByDefault"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" `
                     -Name "DisabledByDefault"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" `
                     -Name "DisabledByDefault"
    #Enabled SSL/TLS
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" `
                     -Name "Enabled"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" `
                     -Name "Enabled"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" `
                     -Name "Enabled"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" `
                     -Name "Enabled"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" `
                     -Name "Enabled"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" `
                     -Name "Enabled"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" `
                     -Name "Enabled"
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" `
                     -Name "Enabled"
    # 8 - Windows Script Host should be disabled
    "$(Date -Format o) - 8 - Windows Script Host should be disabled" >> $_const_InventoryPath
    Get-EditRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" `
                     -Name "Enabled"
    # 9 - SMBv1 protocol should be disabled
    "$(Date -Format o) - 9 - SMBv1 protocol should be disabled" >> $_const_InventoryPath
    Get-ManageSMBServer -Property EnableSMB1Protocol
    # 10 - Link-Local Multicast Name Resolution (LLMNR) should be disabled
    "$(Date -Format o) - 10 - Link-Local Multicast Name Resolution (LLMNR) should be disabled" >> $_const_InventoryPath
    Get-EditRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
                     -Name "EnableMultiCast"
    # 11 - SMBv3 signing and encryption should be enabled
    "$(Date -Format o) - 11 - SMBv3 signing and encryption should be enabled" >> $_const_InventoryPath
    Get-ManageSMBServer -Property RequireSecuritySignature
    Get-ManageSMBServer -Property EncryptData
    Get-ManageSMBServer -Property EnableSecuritySignature
    # 12 - Local Security Authority Server Service (LSASS) should be set to run as a protected process
    "$(Date -Format o) - 12 - Local Security Authority Server Service (LSASS) should be set to run as a protected process" >> $_const_InventoryPath
    Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                     -Name "RunAsPPL"
    # 13 - NetBIOS protocol should be disabled on all network interface
    "$(Date -Format o) - 13 - NetBIOS protocol should be disabled on all network interface" >> $_const_InventoryPath
    $regNetBiosItems=Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*" | Select PSChildName
    foreach ($NetBiosItem in $regNetBiosItems){
        Get-EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\$($NetBiosItem.PSChildName)" `
                         -Name "NetbiosOptions"
    }
    "$(Date -Format o) - END - Get Current setting on $($env:COMPUTERNAME)" >> $_const_InventoryPath
}

function Set-VEEAMSecurityComplianceRecommandation {
    "$(Date -Format o) - START - Set Veeam Compliance Recommandations on $($env:COMPUTERNAME)" >> $_const_RecommandationsPath
    #Backup Infrastrcuture Security
    # 1 - Remote Desktop Services (TermService) should be disabled
    "$(Date -Format o) - 1 - Remote Desktop Services (TermService) should be disabled" >> $_const_RecommandationsPath
    ## Caution doesn't disable if VCC is used to managed the VB&R server
    ManageService -ServiceName "TermService" `
                  -StartupType "Disabled"
    # 2 - Remote Registry service (RemoteRegistry) should be disabled
    "$(Date -Format o) - 2 - Remote Registry service (RemoteRegistry) should be disabled" >> $_const_RecommandationsPath
    ManageService -ServiceName "RemoteRegistry" `
                  -StartupType "Disabled"
    # 3 - Windows Remote Management (WinRM) service should be disabled
    "$(Date -Format o) - 3 - Windows Remote Management (WinRM) service should be disabled" >> $_const_RecommandationsPath
    ManageService -ServiceName "WinRM" `
                  -StartupType "Disabled"
    # 4 - Windows Firewall should be enabled
    "$(Date -Format o) - 4 - Windows Firewall should be enabled" >> $_const_RecommandationsPath
    ManageFirewall -Enabled $true
    # 5 - WDigest credentials caching should be disabled
    "$(Date -Format o) - 5 - WDigest credentials caching should be disabled" >> $_const_RecommandationsPath
    EditRegistry -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" `
                 -Name "UseLogonCredential" `
                 -Type "DWORD" `
                 -Value "0"
    # 6 - Web Proxy Auto-Discovery service (WinHttpAutoProxySvc) should be disabled
    "$(Date -Format o) - 6 - Web Proxy Auto-Discovery service (WinHttpAutoProxySvc) should be disabled" >> $_const_RecommandationsPath
    ManageService -ServiceName "WinHttpAutoProxySvc" -StartupType "Disabled"
    EditRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" `
                 -Name "DisableWpad" `
                 -Type "DWORD" `
                 -Value "1"
    # 7 - Deprecated versions of SSL and TLS should be disabled
    "$(Date -Format o) - 7 - Deprecated versions of SSL and TLS should be disabled" >> $_const_RecommandationsPath
    #Disabled SSL/TLS
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" `
                 -Name "DisabledByDefault" `
                 -Type "DWORD" `
                 -Value "1"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" `
                 -Name "DisabledByDefault" `
                 -Type "DWORD" `
                 -Value "1"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" `
                 -Name "DisabledByDefault" `
                 -Type "DWORD" `
                 -Value "1"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" `
                 -Name "DisabledByDefault" `
                 -Type "DWORD" `
                 -Value "1"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" `
                 -Name "DisabledByDefault" `
                 -Type "DWORD" `
                 -Value "1"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" `
                 -Name "DisabledByDefault" `
                 -Type "DWORD" `
                 -Value "1"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" `
                 -Name "DisabledByDefault" `
                 -Type "DWORD" `
                 -Value "1"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" `
                 -Name "DisabledByDefault" `
                 -Type "DWORD" `
                 -Value "1"
    #Enabled SSL/TLS
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" `
                 -Name "Enabled" `
                 -Type "DWORD" `
                 -Value "0"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" `
                 -Name "Enabled" `
                 -Type "DWORD" `
                 -Value "0"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" `
                 -Name "Enabled" `
                 -Type "DWORD" `
                 -Value "0"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" `
                 -Name "Enabled" `
                 -Type "DWORD" `
                 -Value "0"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" `
                 -Name "Enabled" `
                 -Type "DWORD" `
                 -Value "0"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" `
                 -Name "Enabled" `
                 -Type "DWORD" `
                 -Value "0"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" `
                 -Name "Enabled" `
                 -Type "DWORD" `
                 -Value "0"
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" `
                 -Name "Enabled" `
                 -Type "DWORD" `
                 -Value "0"
    # 8 - Windows Script Host should be disabled
    "$(Date -Format o) - 8 - Windows Script Host should be disabled" >> $_const_RecommandationsPath
    EditRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" `
                 -Name "Enabled" `
                 -Type "DWORD" `
                 -Value "0"
    # 9 - SMBv1 protocol should be disabled
    "$(Date -Format o) - 9 - SMBv1 protocol should be disabled" >> $_const_RecommandationsPath
    ManageSMBServer -Property EnableSMB1Protocol `
                    -Status $false
    # 10 - Link-Local Multicast Name Resolution (LLMNR) should be disabled
    "$(Date -Format o) - 10 - Link-Local Multicast Name Resolution (LLMNR) should be disabled" >> $_const_RecommandationsPath
    EditRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
                 -Name "EnableMultiCast" `
                 -Type "DWORD" `
                 -Value "0"
    # 11 - SMBv3 signing and encryption should be enabled
    "$(Date -Format o) - 11 - SMBv3 signing and encryption should be enabled" >> $_const_RecommandationsPath
    ManageSMBServer -Property RequireSecuritySignature `
                    -Status $true
    ManageSMBServer -Property EncryptData `
                    -Status $true
    ManageSMBServer -Property EnableSecuritySignature `
                    -Status $true
    # 12 - Local Security Authority Server Service (LSASS) should be set to run as a protected process
    "$(Date -Format o) - 12 - Local Security Authority Server Service (LSASS) should be set to run as a protected process" >> $_const_RecommandationsPath
    EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                 -Name "RunAsPPL" `
                 -Type "DWORD" `
                 -Value "2"
    # 13 - NetBIOS protocol should be disabled on all network interface
    "$(Date -Format o) - 13 - NetBIOS protocol should be disabled on all network interface" >> $_const_RecommandationsPath
    $regNetBiosItems=Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*" | Select PSChildName
    foreach ($NetBiosItem in $regNetBiosItems){
        EditRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\$($NetBiosItem.PSChildName)" `
                     -Name "NetbiosOptions" `
                     -Type "DWORD" `
                     -Value "2"
    }
    "$(Date -Format o) - END - Set Veeam Compliance Recommandations on $($env:COMPUTERNAME)" >> $_const_RecommandationsPath
}

$navMain = ""
while ($navMain -ne 0) {
    Write-Host "+--------------------------------------------------------------------------------+";
    Write-Host "|" -NoNewline;
	Write-Host "                           SS_038 - VEEAM ENHANCED                              " -NoNewline -ForegroundColor Yellow;
    Write-Host "|";
    Write-Host "+--------------------------------------------------------------------------------+";
    Write-Host "| [" -NoNewline;
    Write-Host "01" -NoNewline -ForegroundColor Cyan;
    Write-Host "] Prerequisites Before VEEAM Setup | [" -NoNewline;
    Write-Host "02" -NoNewline -ForegroundColor Cyan;
    Write-Host "] Set System Security Compliance    |";
    Write-Host "| [" -NoNewline;
    Write-Host "03" -NoNewline -ForegroundColor Cyan;
    Write-Host "] Get System Security Compliance   | [" -NoNewline;
    Write-Host "04" -NoNewline -ForegroundColor Cyan;
    Write-Host "]                                   |";
    Write-Host "| [" -NoNewline;
    Write-Host "0" -NoNewline -ForegroundColor Red;
    Write-Host "] Quit                              |                                        |";
    Write-Host "+--------------------------------------------------------------------------------+";
    $navMain = Read-Host "| Menu ";
    switch ($navMain) {
        "1" {
            Set-prerequiredSystemBeforeInstallVEEAM
            break
        }
        "2" {
            Get-VEEAMSecurityComplianceRecommandation
            Set-VEEAMSecurityComplianceRecommandation
            break
        }
        "3" {
            Get-VEEAMSecurityComplianceRecommandation
        }
        "0" { 
            Write-Host "+--------------------------------------------------------------------------------+";
            Write-Host "|" -NoNewline;
            Write-Host "                                  Bye Bye                                       " -NoNewline -ForegroundColor Red;
            Write-Host "|";
            Write-Host "+--------------------------------------------------------------------------------+";
            break
        }
        #Default
        default {
            Write-Host "+--------------------------------------------------------------------------------+";
            Write-Host "|" -NoNewline;
            Write-Host "             /!\ Bad Value, Do you need to change keyboard ? /!\                " -NoNewline -ForegroundColor Yellow;
            Write-Host "|";
            Write-Host "+--------------------------------------------------------------------------------+";
            break
        }
    }
}
