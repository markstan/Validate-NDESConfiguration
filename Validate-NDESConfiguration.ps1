<#

.SYNOPSIS
Highlights configuration problems on an NDES server, as configured for use with Intune Standalone SCEP certificates.

.DESCRIPTION
Validate-NDESConfig looks at the configuration of your NDES server and ensures it aligns to the "Configure and manage SCEP 
certificates with Intune" article. 

.NOTE This script is used purely to validate the configuration. All remedial tasks will need to be carried out manually.
Where possible, a link and section description will be provided.

.EXAMPLE
.\Validate-NDESConfiguration -NDESServiceAccount Contoso\NDES_SVC.com -IssuingCAServerFQDN IssuingCA.contoso.com -SCEPUserCertTemplate SCEPGeneral

.EXAMPLE
.\Validate-NDESConfiguration -help

.LINK
https://learn.microsoft.com/en-us/troubleshoot/mem/intune/certificates/troubleshoot-scep-certificate-ndes-policy-module

.NOTES
v1.0 - 1/29/2024 - Initial release. Copy/paste from ODC (https://aka.ms/IntuneODC) to allow for standalone use.
v1.1 - 5/4/2024 - Updated to support system account as service account

#>
[CmdletBinding(DefaultParameterSetName="Unattended")]

Param(

[parameter(Mandatory=$false,ParameterSetName="Unattended")]
[alias("ua","silent","s","unattended")]
[switch]$unattend,  

[parameter(Mandatory=$true,ParameterSetName="NormalRun")]
[alias("sa")]
[ValidateScript({
 
        if  ($_ -match ".\\.")    {
    
        $True
        } 

        else {

        Throw "Please use the format Domain\Username for the NDES Service Account variable."

        }

        $EnteredDomain = $_.split("\")
        $ads = New-Object -ComObject ADSystemInfo
        $Domain = $ads.GetType().InvokeMember('DomainShortName','GetProperty', $Null, $ads, $Null)
    
            if ($EnteredDomain -like "$Domain") {

            $True

            }

            else {
          
                Throw "Incorrect Domain. Ensure domain is '$($Domain)\<USERNAME>'" 
            }

       }
        
    
)]  
[string]$NDESServiceAccount,

[parameter(Mandatory=$true,ParameterSetName="NormalRun")]
[alias("ca")]
[ValidateScript({
    $Domain =  ((Get-WmiObject Win32_ComputerSystem).domain).split(".\")[0]
        if    ($_ -match $Domain)    {

        $True

        }

        else {
   
        Throw "The Network Device Enrollment Server and the Certificate Authority are not members of the same Active Directory domain. This is an unsupported configuration."

        }

    }
)]
[string]$IssuingCAServerFQDN,

[parameter(Mandatory=$true,ParameterSetName="NormalRun")]
[alias("t")]
[string]$SCEPUserCertTemplate,

[parameter(ParameterSetName="Help")]
[alias("h","?","/?")]
[switch]$help,

[parameter(ParameterSetName="Help")]
[alias("u")]
[switch]$usage
 
)

#######################################################################

Function Log-ScriptEvent {

[CmdletBinding()]

Param(
      [parameter(Mandatory=$True)]
      [String]$LogFilePath,

      [parameter(Mandatory=$True)]
      [String]$Value,

      [parameter(Mandatory=$True)]
      [String]$Component,

      [parameter(Mandatory=$True)]
      [ValidateRange(1,3)]
      [Single]$Severity
      )

$DateTime = New-Object -ComObject WbemScripting.SWbemDateTime 
$DateTime.SetVarDate($(Get-Date))
$UtcValue = $DateTime.Value
$UtcOffset = $UtcValue.Substring(21, $UtcValue.Length - 21)

$LogLine =  "<![LOG[$Value]LOG]!>" +`
            "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
            "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
            "component=`"$Component`" " +`
            "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
            "type=`"$Severity`" " +`
            "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
            "file=`"`">"

Add-Content -Path $LogFilePath -Value $LogLine

}

##########################################################################################################

function Show-Usage {

    Write-Output ""
    Write-Output "-help                       -h         Displays the help."
    Write-Output "-usage                      -u         Displays this usage information."
    Write-Output "-NDESExternalHostname       -ed        External DNS name for the NDES server (SSL certificate subject will be checked for this. It should be in the SAN of the certificate if" 
    Write-Output "                                       clients communicate directly with the NDES server)"
    Write-Output "-NDESServiceAccount         -sa        Username of the NDES service account. Format is Domain\sAMAccountName, such as Contoso\NDES_SVC."
    Write-Output "-IssuingCAServerFQDN        -ca        Name of the issuing CA to which you'll be connecting the NDES server.  Format is FQDN, such as 'MyIssuingCAServer.contoso.com'."
    Write-Output "-SCEPUserCertTemplate       -t         Name of the SCEP Certificate template. Please note this is _not_ the display name of the template. Value should not contain spaces." 
    Write-Output ""
}

#######################################################################

function Get-NDESHelp {

    Write-Output ""
    Write-Output "Verifies if the NDES server meets all the required configuration. "
    Write-Output ""
    Write-Output "The NDES server role is required as back-end infrastructure for Intune Standalone for delivering VPN and Wi-Fi certificates via the SCEP protocol to mobile devices and desktop clients."
    Write-Output "See https://docs.microsoft.com/en-us/intune/certificates-scep-configure."
    Write-Output ""
}

#######################################################################
function Set-ServiceAccountisLocalSystem {
Param(
    [parameter(Mandatory=$true)]
    [bool]$isSvcAcctLclSystem
    )

    $Script:SvcAcctIsComputer = $isSvcAcctLclSystem
    Log-ScriptEvent $LogFilePath "Service account is local system (computer) account = $isSvcAcctLclSystem" NDES_Validation 1
    }

#######################################################################
function Get-NDESServiceAcct {
    
    if (  ($null -eq $NDESServiceAccount) -or ($NDESServiceAccount -eq "") ) {


        if ( (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector\CA*").UseSystemAccount -eq 1) {
            $NDESServiceAccount = (Get-ADDomain).NetBIOSName + "`\" + $env:computerName  
            Set-ServiceAccountisLocalSystem $true

        }
        elseif (    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector\CA*").Username -ne "" ) {
             $NDESServiceAccount =  (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector\CA*").Username 
        }
    }
    Log-ScriptEvent $LogFilePath "Service Account detected = $NDESServiceAccount" NDES_Validation 1
    
    $NDESServiceAccount

}

#######################################################################
    if ($help){

        Get-NDESHelp
        break

    }

    if ($usage){

        Show-Usage
        break
    }

#######################################################################

#Requires -version 3.0
#Requires -RunAsAdministrator

#######################################################################

$parent = [System.IO.Path]::GetTempPath()
[string] $name = [System.Guid]::NewGuid()
New-Item -ItemType Directory -Path (Join-Path $parent $name) | Out-Null
$TempDirPath = "$parent$name"
$LogFilePath = "$($TempDirPath)\Validate-NDESConfig.log"


#######################################################################

#region Proceed with Variables...
    # Flag to query computer vs user properties from AD
    [bool]$SvcAcctIsComputer = $false

    $NDESServiceAccount = Get-NDESServiceAcct

    if ($PSCmdlet.ParameterSetName -eq "Unattended") {
        
        $MscepRaEku = '1.3.6.1.4.1.311.20.2.1' # CEP Encryption
        # Get cert authority from the Certificate Request Agent cert.
        $IssuingCAServerFQDN = Get-Item 'Cert:\LocalMachine\My\*' | where { ($_.EnhancedKeyUsageList  -match $MscepRaEku) -and ($_.Extensions.Format(1)[0].split('(')[0] -replace "template="  -match "CEPEncryption" ) }
         
        $SCEPUserCertTemplate = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP).EncryptionTemplate
        $confirmation = "y"
    }
    else {
            Write-Output ""
            Write-Output "......................................................."
            Write-Output ""
            Write-Output "NDES Service Account = " -NoNewline 
            Write-Output "$($NDESServiceAccount)" 
            Write-Output ""
            Write-Output "Issuing CA Server = "
            Write-Output "$($IssuingCAServerFQDN)" 
            Write-Output ""
            Write-Output "SCEP Certificate Template = "
            Write-Output "$($SCEPUserCertTemplate)" 
            Write-Output ""
            Write-Output "......................................................."
            Write-Output ""
            Write-Output "Proceed with variables? [Y]es, [N]o"
            $confirmation = Read-Host
        }


#endregion

#######################################################################

    if ($confirmation -eq 'y'){
    Write-Output ""
    Write-Output "......................................................."
    Log-ScriptEvent $LogFilePath "Initializing log file $($TempDirPath)\Validate-NDESConfig.log"  NDES_Validation 1
    Log-ScriptEvent $LogFilePath "Proceeding with variables=YES"  NDES_Validation 1
    Log-ScriptEvent $LogFilePath "NDESServiceAccount=$($NDESServiceAccount)" NDES_Validation 1
    Log-ScriptEvent $LogFilePath "IssuingCAServer=$($IssuingCAServerFQDN)" NDES_Validation 1
    Log-ScriptEvent $LogFilePath "SCEPCertificateTemplate=$($SCEPUserCertTemplate)" NDES_Validation 1

#######################################################################

#region Install RSAT tools, Check if NDES and IIS installed

    if (-not (Get-WindowsFeature ADCS-Device-Enrollment).Installed){
    
    Write-Output "Error: NDES Not installed" 
    Write-Output "Exiting....................."
    Log-ScriptEvent $LogFilePath "NDES Not installed" NDES_Validation 3
    break

    }

Install-WindowsFeature RSAT-AD-PowerShell | Out-Null

Import-Module ActiveDirectory | Out-Null

    if (-not (Get-WindowsFeature Web-WebServer).Installed){

        $IISNotInstalled = $TRUE
        Write-Warning "IIS is not installed. Some tests will not run as we're unable to import the WebAdministration module"
        Write-Output ""
        Log-ScriptEvent $LogFilePath "IIS is not installed. Some tests will not run as we're unable to import the WebAdministration module"  NDES_Validation 2
    
    }

    else {

        Import-Module WebAdministration | Out-Null

    }

#endregion

#######################################################################

#region checking OS version
    
    Write-Output ""
    Write-Output "Checking Windows OS version..." 
    Write-Output ""
    Log-ScriptEvent $LogFilePath "Checking OS Version" NDES_Validation 1

$OSVersion = (Get-CimInstance -class Win32_OperatingSystem).Version
$MinOSVersion = "6.3"

    if ([version]$OSVersion -lt [version]$MinOSVersion){
    
        Write-Output "Error: Unsupported OS Version. NDES requires Windows Server 2012 R2 and above." 
        Log-ScriptEvent $LogFilePath "Unsupported OS Version. NDES requires Windows Server 2012 R2 and above." NDES_Validation 3
        
        } 
    
    else {
    
        Write-Output "Success: " 
        Write-Output "OS Version: $OSVersion is supported."
        Log-ScriptEvent $LogFilePath "Server is version $($OSVersion)" NDES_Validation 1
    
    }

#endregion

###########################################################################
#region Checking if Enhanced Configuration is Deactivated

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Host "Checking the Enhanced Configuration settings" -ForegroundColor Yellow
Write-Output ""

# Check for the current state of Enhanced Security Configuration
$escState = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"

# If Enhanced Security Configuration is deactivated
if ($escState.IsInstalled -eq 0) {
    Write-Host "Enhanced Security Configuration is deactivated." -ForegroundColor Green
} else {
    Write-Host "Enhanced Security Configuration is activated." -ForegroundColor Red
}


####################################################################### 
#region Checking if PFX Certificate Connector running as System/Domain Account

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Host "Checking the "Log on As" for PFX Certificate Connector for Intune" -ForegroundColor Yellow
Write-Output ""


$service = Get-Service -Name "PFXCertificateConnectorSvc"

if ($service) {
    # Get the service's process
    $serviceProcess = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $service.Name }

    # Check if the service is running as Local System or as a specific user
    if ($serviceProcess.StartName -eq "LocalSystem") {
        Write-Host "$($service.Name) is running as Local System" -ForegroundColor Green
    } else {
        Write-Host "$($service.Name) is running as $($serviceProcess.StartName)" -ForegroundColor Green
    }
} else {
    Write-Host "Service not found" -ForegroundColor Red
}

#############################################################################

#############################################################################


#region Checking NDES Service Account properties in Active Directory
$NDESServiceAccount = Get-NDESServiceAcct
Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking NDES Service Account properties in Active Directory..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking NDES Service Account properties in Active Directory" NDES_Validation 1
 
$ADAccount = $NDESServiceAccount.split("\")[1]
if ($SvcAcctIsComputer ) {
    $ADAccountProps = (Get-ADComputer $ADAccount -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut)
}
else {
    $ADAccountProps = (Get-ADUser $ADAccount -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut)
}

    if ($ADAccountProps.enabled -ne $TRUE -OR $ADAccountProps.PasswordExpired -ne $false -OR $ADAccountProps.LockedOut -eq $TRUE){
        
        Write-Output "Error: Problem with the AD account. Please see output below to determine the issue" 
        Write-Output ""
        Log-ScriptEvent $LogFilePath "Problem with the AD account. Please see output below to determine the issue"  NDES_Validation 3
        
    }
        
    else {

        Write-Output "Success: " 
        Write-Output "NDES Service Account seems to be in working order:"
        Log-ScriptEvent $LogFilePath "NDES Service Account seems to be in working order"  NDES_Validation 1
        
    }


$ADAccountProps | fl SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut
    
#endregion

#######################################################################

#region Checking NDES Service Account local permissions

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking NDES Service Account local permissions..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking NDES Service Account local permissions" NDES_Validation 1 
if ($SvcAcctIsComputer) {
    Write-Output ""
    Write-Output "......................................................."
    Write-Output ""
    Write-Output "Skipping NDES Service Account local permissions since local system is used as the service account..." 
    Write-Output ""
    Log-ScriptEvent $LogFilePath "Skipping NDES Service Account local permissions since local system is used as the service account" NDES_Validation 1 
}
else {
   if ((net localgroup) -match "Administrators"){

    $LocalAdminsMember = ((net localgroup Administrators))

        if ($LocalAdminsMember -like "*$NDESServiceAccount*"){
        
            Write-Warning "NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use the IIS_IUSERS local group instead."
            Log-ScriptEvent $LogFilePath "NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use IIS_IUSERS instead."  NDES_Validation 2

        }

        else {

            Write-Output "Success: " 
            Write-Output "NDES Service account is not a member of the Local Administrators group"
            Log-ScriptEvent $LogFilePath "NDES Service account is not a member of the Local Administrators group"  NDES_Validation 1
    
        }

    Write-Output ""
    Write-Output "Checking NDES Service account is a member of the IIS_IUSR group..." 
    Write-Output ""
    if ((net localgroup) -match "IIS_IUSRS"){

        $IIS_IUSRMembers = ((net localgroup IIS_IUSRS))

        if ($IIS_IUSRMembers -like "*$NDESServiceAccount*"){

            Write-Output "Success: " 
            Write-Output "NDES Service Account is a member of the local IIS_IUSR group"
            Log-ScriptEvent $LogFilePath "NDES Service Account is a member of the local IIS_IUSR group" NDES_Validation 1
    
        }
    
        else {

            Write-Output "Error: NDES Service Account is not a member of the local IIS_IUSR group" 
            Log-ScriptEvent $LogFilePath "NDES Service Account is not a member of the local IIS_IUSR group"  NDES_Validation 3 

            Write-Output ""
            Write-Output "Checking Local Security Policy for explicit rights via gpedit..." 
            Write-Output ""
            $TempFile = [System.IO.Path]::GetTempFileName()
            & "secedit" "/export" "/cfg" "$TempFile" | Out-Null
            $LocalSecPol = Get-Content $TempFile
            $ADAccount = $NDESServiceAccount.split("\")[1]
            # we should only be checking user accounts. If local system is the service account, we can skip this event
            $ADAccountProps = (Get-ADUser $ADAccount -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut)
         
            $NDESSVCAccountSID = $ADAccountProps.SID.Value 
            $LocalSecPolResults = $LocalSecPol | Select-String $NDESSVCAccountSID

                if ($LocalSecPolResults -match "SeInteractiveLogonRight" -AND $LocalSecPolResults -match "SeBatchLogonRight" -AND $LocalSecPolResults -match "SeServiceLogonRight"){
            
                    Write-Output "Success: " 
                    Write-Output "NDES Service Account has been assigned the Logon Locally, Logon as a Service and Logon as a batch job rights explicitly."
                    Log-ScriptEvent $LogFilePath "NDES Service Account has been assigned the Logon Locally, Logon as a Service and Logon as a batch job rights explicitly." NDES_Validation 1
                    Write-Output ""
                    Write-Output "Note:" 
                    Write-Output " The Logon Locally is not required in normal runtime."
                    Write-Output ""
                    Write-Output "Note:" 
                    Write-Output 'Consider using the IIS_IUSERS group instead of explicit rights as documented under "Step 1 - Create an NDES service account".'
                    Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            
                }
            
                else {

                    Write-Output "Error: NDES Service Account has _NOT_ been assigned the Logon Locally, Logon as a Service or Logon as a batch job rights _explicitly_."  
                    Write-Output 'Please review "Step 1 - Create an NDES service account".' 
                    Write-Output "https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
                    Log-ScriptEvent $LogFilePath "NDES Service Account has _NOT_ been assigned the Logon Locally, Logon as a Service or Logon as a batch job rights _explicitly_." NDES_Validation 3
            
                }
    
        }

    }

    else {

        Write-Output "Error: No IIS_IUSRS group exists. Ensure IIS is installed."  
        Write-Output 'Please review "Step 3.1 - Configure prerequisites on the NDES server".' 
        Write-Output "https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "No IIS_IUSRS group exists. Ensure IIS is installed." NDES_Validation 3
    
    }

    }

   else {

        Write-Warning "No local Administrators group exists, likely due to this being a Domain Controller or renaming the group. It is not recommended to run NDES on a Domain Controller."
        Log-ScriptEvent $LogFilePath "No local Administrators group exists, likely due to this being a Domain Controller or renaming the group. It is not recommended to run NDES on a Domain Controller." NDES_Validation 2
    
    }

}

#endregion

#######################################################################

#region Checking Windows Features are installed.

Write-Output ""
Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking Windows Features are installed..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking Windows Features are installed..." NDES_Validation 1

$WindowsFeatures = @("Web-Filtering","Web-Net-Ext45","NET-Framework-45-Core","NET-WCF-HTTP-Activation45","Web-Metabase","Web-WMI")

foreach($WindowsFeature in $WindowsFeatures){

$Feature =  Get-WindowsFeature $WindowsFeature
$FeatureDisplayName = $Feature.displayName

    if($Feature.installed){
    
        Write-Output "Success:" 
        Write-Output "$FeatureDisplayName Feature Installed"
        Log-ScriptEvent $LogFilePath "$($FeatureDisplayName) Feature Installed"  NDES_Validation 1
    
    }

    else {

        Write-Output "Error: $FeatureDisplayName Feature not installed!"  
        Write-Output 'Please review "Step 3.1b - Configure prerequisites on the NDES server".' 
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "$($FeatureDisplayName) Feature not installed"  NDES_Validation 3
    
    }

}

#endregion

#################################################################

#region Checking NDES Install Paramaters

$ErrorActionPreference = "SilentlyContinue"

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking NDES Install Paramaters..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking NDES Install Paramaters" NDES_Validation 1

$InstallParams = @(Get-WinEvent -LogName "Microsoft-Windows-CertificateServices-Deployment/Operational" | Where-Object {$_.id -eq "105"}|
Where-Object {$_.message -match "Install-AdcsNetworkDeviceEnrollmentService"}| Sort-Object -Property TimeCreated -Descending | Select-Object -First 1)

    if ($InstallParams.Message -match '-SigningProviderName "Microsoft Strong Cryptographic Provider"' -AND ($InstallParams.Message -match '-EncryptionProviderName "Microsoft Strong Cryptographic Provider"')) {

        Write-Output "Success: " 
        Write-Output "Correct CSP used in install parameters"
        Write-Output ""
        Write-Output $InstallParams.Message
        Log-ScriptEvent $LogFilePath "Correct CSP used in install parameters:"  NDES_Validation 1
        Log-ScriptEvent $LogFilePath "$($InstallParams.Message)"  NDES_Eventvwr 1

    }

    else {

        Write-Output "Error: Incorrect CSP selected during install. NDES only supports the CryptoAPI CSP." 
        Write-Output ""
        Write-Output $InstallParams.Message
        Log-ScriptEvent $LogFilePath "Error: Incorrect CSP selected during install. NDES only supports the CryptoAPI CSP"  NDES_Validation 3 
        Log-ScriptEvent $LogFilePath "$($InstallParams.Message)"  NDES_Eventvwr 3
    }

$ErrorActionPreference = "Continue"

#endregion

#################################################################

#region Checking IIS Application Pool health

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking IIS Application Pool health..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking IIS Application Pool health" NDES_Validation 1

    if (-not ($IISNotInstalled -eq $TRUE)){

        # If SCEP AppPool Exists    
        if (Test-Path 'IIS:\AppPools\SCEP'){

        $IISSCEPAppPoolAccount = Get-Item 'IIS:\AppPools\SCEP' | select -expandproperty processmodel | select -Expand username
            
            if ((Get-WebAppPoolState "SCEP").value -match "Started"){
            
                $SCEPAppPoolRunning = $TRUE
            
            }

        }

        else {

            Write-Output "Error: SCEP Application Pool missing!"  
            Write-Output 'Please review "Step 3.1 - Configure prerequisites on the NDES server"'. 
            Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure" 
            Log-ScriptEvent $LogFilePath "SCEP Application Pool missing"  NDES_Validation 3
        
        }
    
        if ($SvcAcctIsComputer) {
            Write-Output ""
            Write-Output "......................................................."
            Write-Output ""
            Write-Output "Skipping application pool account check since local system is used as the service account..." 
            Write-Output ""
            Log-ScriptEvent $LogFilePath "Skipping application pool account check since local system is used as the service account" NDES_Validation 1 
        }
        else {
            if ($IISSCEPAppPoolAccount -contains "$NDESServiceAccount"){
            
            Write-Output "Success: " 
            Write-Output "Application Pool is configured to use "
            Write-Output "$($IISSCEPAppPoolAccount)"
            Log-ScriptEvent $LogFilePath "Application Pool is configured to use $($IISSCEPAppPoolAccount)"  NDES_Validation 1
            
            }
            
            else {

            Write-Output "Error: Application Pool is not configured to use the NDES Service Account"  
            Write-Output 'Please review "Step 4.1 - Configure NDES for use with Intune".' 
            Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure" 
            Log-ScriptEvent $LogFilePath "Application Pool is not configured to use the NDES Service Account"  NDES_Validation 3
            
            }
        }
                
        if ($SCEPAppPoolRunning){
                
            Write-Output "Success: " 
            Write-Output "SCEP Application Pool is Started "
            Log-ScriptEvent $LogFilePath "SCEP Application Pool is Started"  NDES_Validation 1
                
        }
                
        else {

            Write-Output "Error: SCEP Application Pool is stopped!"  
            Write-Output "Please start the SCEP Application Pool via IIS Management Console. You should also review the Application Event log output for errors"
            Log-ScriptEvent $LogFilePath "SCEP Application Pool is stopped"  NDES_Validation 3
                
        }

    }

    else {

        Write-Output "IIS is not installed." 
        Log-ScriptEvent $LogFilePath "IIS is not installed"  NDES_Validation 3 

    }

#endregion

#################################################################

#region Checking registry has been set to allow long URLs

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output 'Checking registry "HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters" has been set to allow long URLs...' 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking registry (HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters) has been set to allow long URLs" NDES_Validation 1

    if (-not ($IISNotInstalled -eq $TRUE)){

        If ((Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxFieldLength).MaxfieldLength -notmatch "65534"){

            Write-Output "Error: MaxFieldLength not set to 65534 in the registry!" 
            Write-Output ""
            Write-Output 'Please review "Step 4.3 - Configure NDES for use with Intune".'
            Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            Log-ScriptEvent $LogFilePath "MaxFieldLength not set to 65534 in the registry" NDES_Validation 3
        } 

        else {

            Write-Output "Success: " 
            Write-Output "MaxFieldLength set correctly"
            Log-ScriptEvent $LogFilePath "MaxFieldLength set correctly"  NDES_Validation 1
    
        }
		
        if ((Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxRequestBytes).MaxRequestBytes -notmatch "65534"){

            Write-Output "MaxRequestBytes not set to 65534 in the registry!" 
            Write-Output ""
            Write-Output 'Please review "Step 4.3 - Configure NDES for use with Intune".'
            Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure'"
            Log-ScriptEvent $LogFilePath "MaxRequestBytes not set to 65534 in the registry" NDES_Validation 3 

        }
        
        else {

            Write-Output "Success: " 
            Write-Output "MaxRequestBytes set correctly"
            Log-ScriptEvent $LogFilePath "MaxRequestBytes set correctly"  NDES_Validation 1
        
        }

    }

    else {

        Write-Output "IIS is not installed." 
        Log-ScriptEvent $LogFilePath "IIS is not installed." NDES_Validation 3

    }

#endregion

#################################################################

#region Checking SPN has been set...

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking SPN has been set..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking SPN has been set" NDES_Validation 1

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname

$spn = setspn.exe -L $ADAccount

    if ($spn -match $hostname){
    
        Write-Output "Success: " 
        Write-Output "Correct SPN set for the NDES service account:"
        Write-Output ""
        Write-Output $spn 
        Log-ScriptEvent $LogFilePath "Correct SPN set for the NDES service account: $($spn)"  NDES_Validation 1
    
    }
    
    else {

        Write-Output "Error: Missing or Incorrect SPN set for the NDES Service Account!"  
        Write-Output 'Please review "Step 3.1c - Configure prerequisites on the NDES server".'
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "Missing or Incorrect SPN set for the NDES Service Account"  NDES_Validation 3 
    
    }

#endregion

#################################################################

#region Checking there are no intermediate certs are in the Trusted Root store
       
Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking there are no intermediate certs are in the Trusted Root store..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking there are no intermediate certs are in the Trusted Root store" NDES_Validation 1

$IntermediateCertCheck = Get-Childitem cert:\LocalMachine\root -Recurse | Where-Object {$_.Issuer -ne $_.Subject}

    if ($IntermediateCertCheck){
    
        Write-Output "Error: Intermediate certificate found in the Trusted Root store. This can cause undesired effects and should be removed."  
        Write-Output "Certificates:"
        Write-Output ""
        Write-Output $IntermediateCertCheck
        Log-ScriptEvent $LogFilePath "Intermediate certificate found in the Trusted Root store: $($IntermediateCertCheck)"  NDES_Validation 3
    
    }
    
    else {

        Write-Output "Success: " 
        Write-Output "Trusted Root store does not contain any Intermediate certificates."
        Log-ScriptEvent $LogFilePath "Trusted Root store does not contain any Intermediate certificates."  NDES_Validation 1
    
    }

#endregion

#################################################################

#region Checking the EnrollmentAgentOffline and CEPEncryption are present

$ErrorActionPreference = "Silentlycontinue"

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking the EnrollmentAgentOffline and CEPEncryption are present..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking the EnrollmentAgentOffline and CEPEncryption are present" NDES_Validation 1

$certs = Get-ChildItem cert:\LocalMachine\My\

    # Looping through all certificates in LocalMachine Store
    Foreach ($item in $certs){
      
    $Output = ($item.Extensions| where-object {$_.oid.FriendlyName -like "**"}).format(0).split(",")

        if ($Output -match "EnrollmentAgentOffline"){
        
            $EnrollmentAgentOffline = $TRUE
        
        }
            
        if ($Output -match "CEPEncryption"){
            
            $CEPEncryption = $TRUE
            
        }

    } 
    
    # Checking if EnrollmentAgentOffline certificate is present
    if ($EnrollmentAgentOffline){
    
        Write-Output "Success: " 
        Write-Output "EnrollmentAgentOffline certificate is present"
        Log-ScriptEvent $LogFilePath "EnrollmentAgentOffline certificate is present"  NDES_Validation 1
    
    }
    
    else {

        Write-Output "Error: EnrollmentAgentOffline certificate is not present!"  
        Write-Output "This can take place when an account without Enterprise Admin permissions installs NDES. You may need to remove the NDES role and reinstall with the correct permissions." 
        Write-Output 'Please review "Step 3.1 - Configure prerequisites on the NDES server".' 
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "EnrollmentAgentOffline certificate is not present"  NDES_Validation 3 
    
    }
    
    # Checking if CEPEncryption is present
    if ($CEPEncryption){
        
        Write-Output "Success: " 
        Write-Output "CEPEncryption certificate is present"
        Log-ScriptEvent $LogFilePath "CEPEncryption certificate is present"  NDES_Validation 1
        
    }
        
    else {

        Write-Output "Error: CEPEncryption certificate is not present!"  
        Write-Output "This can take place when an account without Enterprise Admin permissions installs NDES. You may need to remove the NDES role and reinstall with the correct permissions." 
        Write-Output 'Please review "Step 3.1 - Configure prerequisites on the NDES server".' 
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "CEPEncryption certificate is not present"  NDES_Validation 3
        
    }

$ErrorActionPreference = "Continue"

#endregion

#################################################################         

#region Checking registry has been set with the SCEP certificate template name

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output 'Checking registry "HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP" has been set with the SCEP certificate template name...' 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking registry (HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP) has been set with the SCEP certificate template name" NDES_Validation 1

    if (-not (Test-Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP)){

        Write-Output "Error: Registry key does not exist. This can occur if the NDES role has been installed but not configured." 
        Write-Output 'Please review "Step 3 - Configure prerequisites on the NDES server".'
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "MSCEP Registry key does not exist."  NDES_Validation 3 

    }

    else {

    $SignatureTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name SignatureTemplate).SignatureTemplate
    $EncryptionTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name EncryptionTemplate).EncryptionTemplate
    $GeneralPurposeTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name GeneralPurposeTemplate).GeneralPurposeTemplate 
    $DefaultUsageTemplate = "IPSECIntermediateOffline"

        if ($SignatureTemplate -match $DefaultUsageTemplate -AND $EncryptionTemplate -match $DefaultUsageTemplate -AND $GeneralPurposeTemplate -match $DefaultUsageTemplate){
        
            Write-Output "Error: Registry has not been configured with the SCEP Certificate template name. Default values have _not_ been changed." 
            Write-Output 'Please review "Step 3.1 - Configure prerequisites on the NDES server".' 
            Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            Write-Output ""
            Log-ScriptEvent $LogFilePath "Registry has not been configured with the SCEP Certificate template name. Default values have _not_ been changed."  NDES_Validation 3
            $FurtherReading = $FALSE
        
        }

        else {

            Write-Output "One or more default values have been changed."
            Write-Output ""
            Write-Output "Checking SignatureTemplate key..."
            Write-Output ""
            if ($SignatureTemplate -match $SCEPUserCertTemplate){

                Write-Output "Success: " 
                Write-Output "SCEP certificate template '$($SCEPUserCertTemplate)' has been written to the registry under the _SignatureTemplate_ key. Ensure this aligns with the usage specificed on the SCEP template."
                Write-Output ""
                Log-ScriptEvent $LogFilePath "SCEP certificate template $($SCEPUserCertTemplate)' has been written to the registry under the _SignatureTemplate_ key"  NDES_Validation 1

            }

            else {
        
                Write-Warning '"SignatureTemplate key does not match the SCEP certificate template name. Unless your template is explicitly set for the "Signature" purpose, this can safely be ignored."'
                Write-Output ""
                Write-Output "Registry value: "
                Write-Output "$($SignatureTemplate)" 
                Write-Output ""
                Write-Output "SCEP certificate template value: "
                Write-Output "$($SCEPUserCertTemplate)" 
                Write-Output ""
                Log-ScriptEvent $LogFilePath "SignatureTemplate key does not match the SCEP certificate template name.Registry value=$($SignatureTemplate)|SCEP certificate template value=$($SCEPUserCertTemplate)"  NDES_Validation 2
        
            }
                
                Write-Output "......................."
                Write-Output ""
                Write-Output "Checking EncryptionTemplate key..."
                Write-Output ""
                if ($EncryptionTemplate -match $SCEPUserCertTemplate){
            
                    Write-Output "Success: " 
                    Write-Output "SCEP certificate template '$($SCEPUserCertTemplate)' has been written to the registry under the _EncryptionTemplate_ key. Ensure this aligns with the usage specificed on the SCEP template."
                    Write-Output ""
                    Log-ScriptEvent $LogFilePath "SCEP certificate template $($SCEPUserCertTemplate) has been written to the registry under the _EncryptionTemplate_ key"  NDES_Validation 1

            
                }
            
                else {

                    Write-Warning '"EncryptionTemplate key does not match the SCEP certificate template name. Unless your template is explicitly set for the "Encryption" purpose, this can safely be ignored."'
                    Write-Output ""
                    Write-Output "Registry value: "
                    Write-Output "$($EncryptionTemplate)" 
                    Write-Output ""
                    Write-Output "SCEP certificate template value: "
                    Write-Output "$($SCEPUserCertTemplate)" 
                    Write-Output ""
                    Log-ScriptEvent $LogFilePath "EncryptionTemplate key does not match the SCEP certificate template name.Registry value=$($EncryptionTemplate)|SCEP certificate template value=$($SCEPUserCertTemplate)"  NDES_Validation 2

            
                }
                
                    Write-Output "......................."
                    Write-Output ""
                    Write-Output "Checking GeneralPurposeTemplate key..."
                    Write-Output ""
                    if ($GeneralPurposeTemplate -match $SCEPUserCertTemplate){
                
                        Write-Output "Success: " 
                        Write-Output "SCEP certificate template '$($SCEPUserCertTemplate)' has been written to the registry under the _GeneralPurposeTemplate_ key. Ensure this aligns with the usage specificed on the SCEP template"
                        Log-ScriptEvent $LogFilePath "SCEP certificate template $($SCEPUserCertTemplate) has been written to the registry under the _GeneralPurposeTemplate_ key"  NDES_Validation 1

                    }
                
                    else {

                        Write-Warning '"GeneralPurposeTemplate key does not match the SCEP certificate template name. Unless your template is set for the "Signature and Encryption" (General) purpose, this can safely be ignored."'
                        Write-Output ""
                        Write-Output "Registry value: "
                        Write-Output "$($GeneralPurposeTemplate)" 
                        Write-Output ""
                        Write-Output "SCEP certificate template value: "
                        Write-Output "$($SCEPUserCertTemplate)" 
                        Write-Output ""
                        Log-ScriptEvent $LogFilePath "GeneralPurposeTemplate key does not match the SCEP certificate template name.Registry value=$($GeneralPurposeTemplate)|SCEP certificate template value=$($SCEPUserCertTemplate)"  NDES_Validation 2

                
                    }

        }

        if ($furtherreading-EQ $true){
        
            Write-Output "......................."
            Write-Output ""
            Write-Output 'For further reading, please review "Step 4.2 - Configure NDES for use with Intune".'
            Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"

        }

    }
        
$ErrorActionPreference = "Continue"

#endregion

#################################################################

#region Checking server certificate.

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking IIS SSL certificate is valid for use..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking IIS SSL certificate is valid for use" NDES_Validation 1

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
$serverAuthEKU = "1.3.6.1.5.5.7.3.1" # Server Authentication
$allSSLCerts = Get-ChildItem Cert:\LocalMachine\My
$BoundServerCert = netsh http show sslcert
    
    foreach ($Cert in $allSSLCerts) {       

    $ServerCertThumb = $cert.Thumbprint

        if ($BoundServerCert -match $ServerCertThumb){

            $BoundServerCertThumb = $ServerCertThumb

        }

    }

$ServerCertObject = Get-ChildItem Cert:\LocalMachine\My\$BoundServerCertThumb

    if ($ServerCertObject.Issuer -match $ServerCertObject.Subject){

        $SelfSigned = $true

    }

    else {
    
        $SelfSigned = $false
    
    }

        if ($ServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU -AND (($ServerCertObject.Subject -match $hostname) -or ($ServerCertObject.DnsNameList -match $hostname)) -AND $ServerCertObject.Issuer -notmatch $ServerCertObject.Subject){

            Write-Output "Success: " 
            Write-Output "Certificate bound in IIS is valid:"
            Write-Output ""
            Write-Output "Subject: "
            Write-Output "$($ServerCertObject.Subject)" 
            Write-Output ""
            Write-Output "Thumbprint: "
            Write-Output "$($ServerCertObject.Thumbprint)" 
            Write-Output ""
            Write-Output "Valid Until: "
            Write-Output "$($ServerCertObject.NotAfter)" 
            Write-Output ""
            Write-Output "If this NDES server is in your perimeter network, please ensure the external hostname is shown below:"  
            $DNSNameList = $ServerCertObject.DNSNameList.unicode
            Write-Output ""
            Write-Output "Internal and External hostnames: "
            Write-Output "$($DNSNameList)" 
            Log-ScriptEvent $LogFilePath "Certificate bound in IIS is valid. Subject:$($ServerCertObject.Subject)|Thumbprint:$($ServerCertObject.Thumbprint)|ValidUntil:$($ServerCertObject.NotAfter)|Internal&ExternalHostnames:$($DNSNameList)" NDES_Validation 1

            }
    
        else {

        Write-Output "Error: The certificate bound in IIS is not valid for use. Reason:"  
        Write-Output ""
                if ($ServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU) {
                
                    $EKUValid = $true

                }

                else {
                
                    $EKUValid = $false

                    Write-Output "Correct EKU: "
                    Write-Output "$($EKUValid)" 
                    Write-Output ""
                }

                if ($ServerCertObject.Subject -match $hostname) {
                
                    $SubjectValid = $true

                }

                else {
                
                    $SubjectValid = $false

                    Write-Output "Correct Subject: "
                    Write-Output "$($SubjectValid)" 
                    Write-Output ""
                }

                if ($SelfSigned -eq $false){
               
                    Out-Null
                
                }

                else {
                
                    Write-Output "Is Self-Signed: "
                    Write-Output "$($SelfSigned)" 
                    Write-Output ""
                }

        Write-Output 'Please review "Step 4 - Configure NDES for use with Intune>To Install and bind certificates on the NDES Server".'
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "The certificate bound in IIS is not valid for use. CorrectEKU=$($EKUValid)|CorrectSubject=$($SubjectValid)|IsSelfSigned=$($SelfSigned)"  NDES_Validation 3

}
        
#endregion

#################################################################

#region Checking Client certificate.

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking encrypting certificate is valid for use..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking encrypting certificate is valid for use..." NDES_Validation 1

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
$clientAuthEku = "1.3.6.1.5.5.7.3.2" # Client Authentication
$NDESCertThumbprint = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector -Name EncryptionCertThumbprint).EncryptionCertThumbprint
$ClientCertObject = Get-ChildItem Cert:\LocalMachine\My\$NDESCertThumbprint

    if ($ClientCertObject.Issuer -match $ClientCertObject.Subject){

        $ClientCertSelfSigned = $true

    }

    else {
    
        $ClientCertSelfSigned = $false
    
    }

        if ($ClientCertObject.EnhancedKeyUsageList -match $clientAuthEku  -AND $ClientCertObject.Issuer -notmatch $ClientCertObject.Subject){

            Write-Output "Success: " 
            Write-Output "Client certificate bound to NDES Connector is valid:"
            Write-Output ""
            Write-Output "Subject: "
            Write-Output "$($ClientCertObject.Subject)" 
            Write-Output ""
            Write-Output "Thumbprint: "
            Write-Output "$($ClientCertObject.Thumbprint)" 
            Write-Output ""
            Write-Output "Valid Until: "
            Write-Output "$($ClientCertObject.NotAfter)" 
            Log-ScriptEvent $LogFilePath "Client certificate bound to NDES Connector is valid. Subject:$($ClientCertObject.Subject)|Thumbprint:$($ClientCertObject.Thumbprint)|ValidUntil:$($ClientCertObject.NotAfter)"  NDES_Validation 1

        }
    
        else {

        Write-Output "Error: The certificate bound to the NDES Connector is not valid for use. Reason:"  
        Write-Output ""
                if ($ClientCertObject.EnhancedKeyUsageList -match $clientAuthEku) {
                
                    $ClientCertEKUValid = $true

                }

                else {
                
                    $ClientCertEKUValid = $false

                    Write-Output "Correct EKU: "
                    Write-Output "$($ClientCertEKUValid)" 
                    Write-Output ""
                }

 
                if ($ClientCertSelfSigned -eq $false){
               
                    Out-Null
                
                }

                else {
                
                    Write-Output "Is Self-Signed: "
                    Write-Output "$($ClientCertSelfSigned)" 
                    Write-Output ""
                }

        Write-Output 'Please review "Step 4 - Configure NDES for use with Intune>To Install and bind certificates on the NDES Server".'
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "The certificate bound to the NDES Connector is not valid for use. CorrectEKU=$($ClientCertEKUValid))|IsSelfSigned=$($ClientCertSelfSigned)"  NDES_Validation 3


}
        
#endregion

#################################################################

#region Checking behaviour of internal NDES URL

Write-Output ""
Write-Output "......................................................."
$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
Write-Output ""
Write-Output "Checking behaviour of internal NDES URL: " 
Write-Output "https://$hostname/certsrv/mscep/mscep.dll" 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking behaviour of internal NDES URL" NDES_Validation 1
Log-ScriptEvent $LogFilePath "Https://$hostname/certsrv/mscep/mscep.dll" NDES_Validation 1

$Statuscode = try {(Invoke-WebRequest -Uri https://$hostname/certsrv/mscep/mscep.dll).statuscode} catch {$_.Exception.Response.StatusCode.Value__}

    if ($statuscode -eq "200"){

    Write-Output "Error: https://$hostname/certsrv/mscep/mscep.dll returns 200 OK. This usually signifies an error with the Intune Connector registering itself or not being installed." 
    Log-ScriptEvent $LogFilePath "https://$hostname/certsrv/mscep/mscep.dll returns 200 OK. This usually signifies an error with the Intune Connector registering itself or the service is not installed"  NDES_Validation 3
    } 

    elseif ($statuscode -eq "403"){

    Write-Output "Trying to retrieve CA Capabilitiess..." 
    Write-Output ""
    $Newstatuscode = try {(Invoke-WebRequest -Uri "https://$hostname/certsrv/mscep/mscep.dll?operation=GetCACaps&message=test").statuscode} catch {$_.Exception.Response.StatusCode.Value__}

        if ($Newstatuscode -eq "200"){

        $CACaps = (Invoke-WebRequest -Uri "https://$hostname/certsrv/mscep?operation=GetCACaps&message=test").content

        }

            if ($CACaps){

            Write-Output "Success: " 
            Write-Output "CA Capabilities retrieved:"
            Write-Output ""
            Write-Output $CACaps
            Log-ScriptEvent $LogFilePath "CA Capabilities retrieved:$CACaps"  NDES_Validation 1
                
            }

    }
                    
    else {
    
        Write-Output "Error: Unexpected Error code! This usually signifies an error with the Intune Connector registering itself or not being installed" 
        Write-Output "Expected value is a 403. We received a $($Statuscode). This could be down to a missing reboot post policy module install. Verify last boot time and module install time further down the validation."
        Log-ScriptEvent $LogFilePath "Unexpected Error code. Expected: 403 | Received: $Statuscode"  NDES_Validation 3
    
   }
        
#endregion

#################################################################

#region Checking Servers last boot time

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking Servers last boot time..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking Servers last boot time" NDES_Validation 1

$LastBoot = (Get-WmiObject win32_operatingsystem | select csname, @{LABEL='LastBootUpTime'
;EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}).lastbootuptime

Write-Output "Server last rebooted: $($LastBoot). `r`n" 
Write-Output "Please ensure a reboot has taken place _after_ all registry changes and installing the NDES Connector. IISRESET is _not_ sufficient."
Log-ScriptEvent $LogFilePath "LastBootTime:$LastBoot"  NDES_Validation 1

#endregion

#################################################################

#region Checking Intune Connector is installed

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking Intune Connector is installed..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking Intune Connector is installed" NDES_Validation 1 

    if ($IntuneConnector = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ? {$_.DisplayName -eq "Certificate Connector for Microsoft Intune"}){

        $installDate = [datetime]::ParseExact($IntuneConnector.InstallDate, 'yyyymmdd', $null).tostring('dd-mm-yyyy')
        Write-Output "Success: " 
        Write-Output "$($IntuneConnector.DisplayName) was installed on $installDate and is version $($IntuneConnector.DisplayVersion)" 
        Write-Output ""
        Log-ScriptEvent $LogFilePath "ConnectorVersion: $IntuneConnector"  NDES_Validation 1

    }

    else {

        Write-Output "Error: Intune Connector not installed"  
        Write-Output 'Please review "Step 5 - Enable, install, and configure the Intune certificate connector".'
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Write-Output ""
        Log-ScriptEvent $LogFilePath "ConnectorNotInstalled"  NDES_Validation 3 
        
    }


#endregion

#################################################################

#region Checking Intune Connector registry keys (KeyRecoveryAgentCertificate, PfxSigningCertificate and SigningCertificate)

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking Intune Connector registry keys are intact" 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking Intune Connector registry keys are intact" NDES_Validation 1
$ErrorActionPreference = "SilentlyContinue"

$KeyRecoveryAgentCertificate = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\KeyRecoveryAgentCertificate"
$PfxSigningCertificate = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\PfxSigningCertificate"
$SigningCertificate = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\SigningCertificate"

    if (-not ($KeyRecoveryAgentCertificate)){

        Write-Output "Error: KeyRecoveryAgentCertificate Registry key does not exist." 
        Write-Output ""
        Log-ScriptEvent $LogFilePath "KeyRecoveryAgentCertificate Registry key does not exist."  NDES_Validation 3 

    }

        else {

        $KeyRecoveryAgentCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name KeyRecoveryAgentCertificate).KeyRecoveryAgentCertificate

            if (-not ($KeyRecoveryAgentCertificatePresent)) {
    
                Write-Warning "KeyRecoveryAgentCertificate registry key exists but has no value"
                Log-ScriptEvent $LogFilePath "KeyRecoveryAgentCertificate missing value"  NDES_Validation 2

            }

            else {
    
                Write-Output "Success: " 
                Write-Output "KeyRecoveryAgentCertificate registry key exists"
                Log-ScriptEvent $LogFilePath "KeyRecoveryAgentCertificate registry key exists"  NDES_Validation 1

            }



    }

    if (-not ($PfxSigningCertificate)){

        Write-Output "Error: PfxSigningCertificate Registry key does not exist." 
        Write-Output ""
        Log-ScriptEvent $LogFilePath "PfxSigningCertificate Registry key does not exist."  NDES_Validation 3 


        }

        else {

        $PfxSigningCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name PfxSigningCertificate).PfxSigningCertificate

            if (-not ($PfxSigningCertificatePresent)) {
    
                Write-Warning "PfxSigningCertificate registry key exists but has no value"
                Log-ScriptEvent $LogFilePath "PfxSigningCertificate missing Value"  NDES_Validation 2

            }

            else {
    
                Write-Output "Success: " 
                Write-Output "PfxSigningCertificate registry keys exists"
                Log-ScriptEvent $LogFilePath "PfxSigningCertificate registry key exists"  NDES_Validation 1

        }



    }

    if (-not ($SigningCertificate)){

        Write-Output "Error: SigningCertificate Registry key does not exist." 
        Write-Output ""
        Log-ScriptEvent $LogFilePath "SigningCertificate Registry key does not exist"  NDES_Validation 3  

    }

        else {

        $SigningCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name SigningCertificate).SigningCertificate

            if (-not ($SigningCertificatePresent)) {
    
                Write-Warning "SigningCertificate registry key exists but has no value"
                Log-ScriptEvent $LogFilePath "SigningCertificate registry key exists but has no value"  NDES_Validation 2


            }

            else {
    
                Write-Output "Success: " 
                Write-Output "SigningCertificate registry key exists"
                Log-ScriptEvent $LogFilePath "SigningCertificate registry key exists"  NDES_Validation 1


            }



    }

$ErrorActionPreference = "Continue"

#endregion

#################################################################

#region Checking eventlog for pertinent errors

$ErrorActionPreference = "SilentlyContinue"
$EventLogCollDays = ((Get-Date).AddDays(-5)) #Number of days to go back in the event log

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Checking Event logs for pertinent errors..." 
Write-Output ""
Log-ScriptEvent $LogFilePath "Checking Event logs for pertinent errors" NDES_Validation 1

    if (-not (Get-EventLog -LogName "Microsoft Intune Connector" -EntryType Error -After $EventLogCollDays -ErrorAction silentlycontinue)) {

        Write-Output "Success: " 
        Write-Output "No errors found in the Microsoft Intune Connector"
        Write-Output ""
        Log-ScriptEvent $LogFilePath "No errors found in the Microsoft Intune Connector"  NDES_Validation 1

    }

    else {

        Write-Warning "Errors found in the Microsoft Intune Connector Event log. Please see below for the most recent 5, and investigate further in Event Viewer."
        Write-Output ""
        $EventsCol1 = (Get-EventLog -LogName "Microsoft Intune Connector" -EntryType Error -After $EventLogCollDays -Newest 5 | select TimeGenerated,Source,Message)
        $EventsCol1 | fl
        Log-ScriptEvent $LogFilePath "Errors found in the Microsoft Intune Connector Event log"  NDES_Eventvwr 3
        $i = 0
        $count = @($EventsCol1).count

        foreach ($item in $EventsCol1) {

            Log-ScriptEvent $LogFilePath "$($EventsCol1[$i].TimeGenerated);$($EventsCol1[$i].Message);$($EventsCol1[$i].Source)"  NDES_Eventvwr 3
            $i++

            }
            
        }

            if (-not (Get-EventLog -LogName "Application" -EntryType Error -Source NDESConnector,Microsoft-Windows-NetworkDeviceEnrollmentService -After $EventLogCollDays -ErrorAction silentlycontinue)) {

            Write-Output "Success: " 
            Write-Output "No errors found in the Application log from source NetworkDeviceEnrollmentService or NDESConnector"
            Write-Output ""
            Log-ScriptEvent $LogFilePath "No errors found in the Application log from source NetworkDeviceEnrollmentService or NDESConnector"  NDES_Validation 1

            }

    else {

        Write-Warning "Errors found in the Application Event log for source NetworkDeviceEnrollmentService or NDESConnector. Please see below for the most recent 5, and investigate further in Event Viewer."
        Write-Output ""
        $EventsCol2 = (Get-EventLog -LogName "Application" -EntryType Error -Source NDESConnector,Microsoft-Windows-NetworkDeviceEnrollmentService -After $EventLogCollDays -Newest 5 | select TimeGenerated,Source,Message)
        $EventsCol2 |fl
        $i = 0
        $count = @($EventsCol2).count

        foreach ($item in $EventsCol2) {

            Log-ScriptEvent $LogFilePath "$($EventsCol2[$i].TimeGenerated);$($EventsCol2[$i].Message);$($EventsCol2[$i].Source)"  NDES_Eventvwr 3
            $i++

    }

}

$ErrorActionPreference = "Continue"

#endregion

#################################################################

#region Zip up logfiles

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Log Files..." 
Write-Output ""
if ($PSCmdlet.ParameterSetName -eq "Unattended") {
    Write-Output "Automatically gathering files."
    $LogFileCollectionConfirmation = "y"
    }
else {
    Write-Output "Do you want to gather troubleshooting files? This includes IIS, NDES Connector, NDES Plugin, CRP, and MSCEP log files, in addition to the SCEP template configuration.  [Y]es, [N]o:"
    $LogFileCollectionConfirmation = Read-Host
    }
    
    if ($LogFileCollectionConfirmation -eq "y"){

    $IISLogPath = (Get-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name logfile.directory).Value + "\W3SVC1" -replace "%SystemDrive%",$env:SystemDrive
    $IISLogs = Get-ChildItem $IISLogPath| Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
    $NDESConnectorLogs = Get-ChildItem "$env:SystemRoot\System32\Winevt\Logs\Microsoft-Intune-CertificateConnectors*"   

    foreach ($IISLog in $IISLogs){

    Copy-Item -Path $IISLog.FullName -Destination $TempDirPath

    }

    foreach ($NDESConnectorLog in $NDESConnectorLogs){

    Copy-Item -Path $NDESConnectorLog.FullName -Destination $TempDirPath

    }

    foreach ($NDESPluginLog in $NDESPluginLogs){

    Copy-Item -Path $NDESPluginLog.FullName -Destination $TempDirPath

    }

    foreach ($MSCEPLog in $MSCEPLogs){

    Copy-Item -Path $MSCEPLog.FullName -Destination $TempDirPath

    }

    foreach ($CRPLog in $CRPLogs){

    Copy-Item -Path $CRPLogs.FullName -Destination $TempDirPath

    }

    $SCEPUserCertTemplateOutputFilePath = "$($TempDirPath)\SCEPUserCertTemplate.txt"
    certutil -v -template $SCEPUserCertTemplate > $SCEPUserCertTemplateOutputFilePath

    Log-ScriptEvent $LogFilePath "Collecting server logs"  NDES_Validation 1

    Add-Type -assembly "system.io.compression.filesystem"
    $Currentlocation =  $env:temp
    $date = Get-Date -Format ddMMyyhhmmss
    [io.compression.zipfile]::CreateFromDirectory($TempDirPath, "$($Currentlocation)\$($date)-CertConnectorLogs-$($hostname).zip")

    Write-Output ""
    Write-Output "Success: " 
    Write-Output "Log files copied to $($Currentlocation)\$($date)-CertConnectorLogs-$($hostname).zip"
    Write-Output ""
    #Show in Explorer
    Start-Process $Currentlocation
    }

    else {

    Log-ScriptEvent $LogFilePath "Do not collect logs"  NDES_Validation 1
    $WriteLogOutputPath = $True

    }


#endregion

#################################################################

#region Ending script

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "End of NDES configuration validation" 
Write-Output ""
    if ($WriteLogOutputPath -eq $True) {

        Write-Output "Log file copied to $($LogFilePath)"
        Write-Output ""
        # for ODC
        $copyPath = "$env:temp\CollectedData\Intune\Files\NDES"
        if ($PSCmdlet.ParameterSetName -eq "Unattended"  ){
            if ( -not (test-path $copyPath) ) { mkdir $copyPath -Force }
            copy $LogFilePath $copyPath
            }


    }
Write-Output "Ending script..." 
Write-Output ""
#endregion

#################################################################

}

else {

Write-Output ""
Write-Output "......................................................."
Write-Output ""
Write-Output "Incorrect variables. Please run the script again..." 
Write-Output ""
Write-Output "Exiting................................................"
Write-Output ""
exit

}
 
