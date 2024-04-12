# =======================================================
# NAME: SS_038_VEEAM_SECURE-ENHANCED.ps1
# AUTHOR: GUILLEMARD, Erwan, PERSONNAL PROPRIETY
# DATE: 2024/04/12
#
# KEYWORDS: VEEAM
# 2024/04/12 - 1.0.0 : Script creation
# COMMENTS: 
#
#Requires -Version 3.0
# =======================================================

cd "C:\Users\ErwanGUILLEMARD\OneDrive\Personnel\Projet\Scripts\SS_038_VEEAM-ENHANCED"
$_const_debug = $true

if($_const_debug){
    $DebugPreference="Continue"
}else{
    $DebugPreference="SilentlyContinue"
}

$_const_currentDate=Get-Date -Format o
$_const_LogDirectory="$PSScriptRoot\logs\"

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
        }
        Binary{
            Write-Debug "$($Type) match with Binary (REG_BINARY)"
        }
        DWORD{
            Write-Debug "$($Type) match with DWORD"
            #Convert Value String to int if value is different to String
            $Value=[int]$Value
        }
        QWORD{
            Write-Debug "$($Type) match with QWORD"
            #Convert Value String to int if value is different to String
            $Value=[int]$Value
        }
        MultiString{
            Write-Debug "$($Type) match with MultiString (REG_MUTLI_SZ)"
        }
        ExpandString{
            Write-Debug "$($Type) match with ExpandString (REG_EXPAND_SZ)"
        }
        Default{
          Write-Host "$($Type) not correct, Type must be REG_SZ, REG_BINARY, DWORD, QWORD, REG_MULTI_SZ, REG_EXPAND_SZ"
          return $false  
        }    
    }
    #check if Property registry exist
    $regLocalPropertyExist=(Get-Item -Path $Path).property -contains $Name
    #Exist, check value
    if($regLocalPropertyExist){
        $regPropertyValue=Get-ItemPropertyValue $Path $Name
        #Check if value is 1, else set it
        if($regPropertyValue -eq $Value){
            Write-Host "Value is $($regPropertyValue)"
        }
        else{
            Write-Host "Value is $($regPropertyValue), need to be set to $($Value)"
            try{
                Set-ItemProperty -LiteralPath $Path `
                                 -Name $Name `
                                 -Type $Type `
                                 -Value $Value
                Write-Host "Value defined for $($Name) as $($Type) Type to $($Value)"
            }catch{
                Write-Host "Error, can't define value for $($Name) as $($Type) Type to $($Value)"
            }
        }
    }
    #Not Exist, need to create registry DWORD
    else{
        Write-Host "Registry doesn't exist : $($Path)\$($Name), need to create it $($Name) and set to $($Value) as $($Type) Type"
        try{
            Set-ItemProperty -LiteralPath $Path `
                                -Name $Name `
                                -Type $Type `
                                -Value $Value
            Write-Host "Registry created $($Name) as $($Type) Type set to $($Value)"
        }catch{
            Write-Host "Error, can't define value for $($Name) as $($Type) Type set to $($Value) $_"
        }  
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
            Set-Service -Name $ServiceName -StartupType $StartupType
            Write-Debug "Service $($ServiceName) Startup type is now $($StartupType)"
        }catch{
            Write-Host "Service $($ServiceName) can't be $($StartupType)"
            Write-Host "$_"    
        }    
    }
    else{
        Write-Host "Service $($ServiceName) is set as Startype $($services.StartType)"
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
        Write-Host "Statment Firewall : $($profil.Name)"
        if($profil.Enabled){
            Write-Host "Firewall $($profil.Name) is already enabled ($($profil.Enabled))"
        }
        else{
            Write-Host "Firewall $($profil.Name) is disabled ($($profil.Enabled))"
            try{
                Set-NetFirewallProfile -Name $profil.Name -Enabled $profil.Enabled
                Write-Host "Firewall $($profil.Name) is now enabled ($($profil.Enabled))"
            }catch{
                Write-Host "Firewall, $($profil.Name) can't be change"
                Write-Host "$_" 
            }
        }
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
    Write-Host "The property $($Property) is defined to $($value.EnableSMB1Protocol)"
    if($value.EnableSMB1Protocol -eq $Status){
        Write-Host "Nothing to do the value is already defined"
    }
    else{
        Write-Host "The property $($Property) will be defined to $($Status)"
        try{
            switch ($Property){
                EnableSMB1Protocol{
                    Set-SmbServerConfiguration -EnableSMB1Protocol $Status -Confirm:$false
                    Write-Host "The property $($Property) is now set to $($Status)"
                }
                RequireSecuritySignature{
                    Set-SmbServerConfiguration -RequireSecuritySignature $Status -Confirm:$false
                    Write-Host "The property $($Property) is now set to $($Status)"
                }
                EncryptData{
                    Set-SmbServerConfiguration -EncryptData $Status -Confirm:$false
                    Write-Host "The property $($Property) is now set to $($Status)"
                }
                EnableSecuritySignature{
                    Set-SmbServerConfiguration -EnableSecuritySignature $Status -Confirm:$false
                    Write-Host "The property $($Property) is now set to $($Status)"
                }
                Default{
                    Write-Host "Property not supported in this script, please edit or contact erwanguillemard "
                }
            }
            
        }catch{
            Write-Host "The property $($Property) can't be changed !"
            Write-Host "$_"
        }
    }   
}

function Set-VEEAMSecurityComplianceRecommandation {
    #Backup Infrastrcuture Security
    # 1 - Remote Desktop Services (TermService) should be disabled
    ## Caution doesn't disable if VCC is used to managed the VB&R server
    ManageService -ServiceName "TermService" -StartupType "Disabled"
    # 2 - Remote Registry service (RemoteRegistry) should be disabled
    ManageService -ServiceName "RemoteRegistry" -StartupType "Disabled"
    # 3 - Windows Remote Management (WinRM) service should be disabled
    ManageService -ServiceName "WinRM" -StartupType "Disabled"
    # 4 - Windows Firewall should be enabled
    ManageFirewall -Enabled $true
    # 5 - WDigest credentials caching should be disabled
    EditRegistry -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" `
                 -Name "UseLogonCredential" `
                 -Type "DWORD" `
                 -Value "0"
    # 6 - Web Proxy Auto-Discovery service (WinHttpAutoProxySvc) should be disabled
    ManageService -ServiceName "WinHttpAutoProxySvc" -StartupType "Disabled"
    EditRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" `
                 -Name "DisableWpad" `
                 -Type "DWORD" `
                 -Value "1"
    # 7 - Deprecated versions of SSL and TLS should be disabled
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
    EditRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" `
                 -Name "Enabled" `
                 -Type "DWORD" `
                 -Value "0"
    # 9 - SMBv1 protocol should be disabled
    ManageSMBServer -Property EnableSMB1Protocol -Status $false
    # 10 - Link-Local Multicast Name Resolution (LLMNR) should be disabled
    EditRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
                 -Name "EnableMultiCast" `
                 -Type "DWORD" `
                 -Value "0"
    # 11 - SMBv3 signing and encryption should be enabled
    ManageSMBServer -Property RequireSecuritySignature -Status $true
    ManageSMBServer -Property EncryptData -Status $true
    ManageSMBServer -Property EnableSecuritySignature -Status $true
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
    Write-Host "] System Security Compliance        |";
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
            Set-VEEAMSecurityComplianceRecommandation
            break
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
