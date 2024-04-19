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
[string]$NDESServiceAccount = "",

[parameter(Mandatory=$true,ParameterSetName="NormalRun")]
[alias("ca")]
[ValidateScript({
    $Domain =  ((Get-WmiObject Win32_ComputerSystem).domain).split(".\")[0]
        if    ($_ -match $Domain)    {
            $true
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
[switch]$usage,

[switch]$toStdOut,
[switch]$SkipHTML,
[switch]$ODC
 
) 

<#
.Synopsis
    Writes color-coded results to PowerShell window
.DESCRIPTION
      Displays results of tests and progress messages to the
   PowerShell window. Color-codes results for ease of reading.
.EXAMPLE
   Write-Interactive -ResultBlob $ResultBlob
.EXAMPLE
   $ResultBlob | Write-Interactive
.EXAMPLE
    # Will write in default white text with a severity of 'Information'
    Write-Interactive "hi"
#>
function Write-Interactive
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Message help description
        [Parameter(Mandatory=$true,
        ValueFromPipeline,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $ResultBlob,
        [Parameter(Mandatory=$false)]
        $Result
    )

    Begin
    {
    }
    Process
    {

    switch ($($ResultBlob.GetType()).FullName) {
        System.Management.Automation.PSCustomObject
        {

            Write-Host "Rule:        " -ForegroundColor Gray -NoNewline
            Write-Host  $ResultBlob.RuleId -ForegroundColor White
            Write-Host "Description: " -ForegroundColor Gray -NoNewline
            Write-Host $ResultBlob.RuleDescription -ForegroundColor White
            
            Write-Host "Result:      " -ForegroundColor Gray -NoNewline
            switch($ResultBlob.CheckResult) {
                "Passed"
                {
                   Write-Host  $ResultBlob.CheckResult -ForegroundColor Green
                }
                "Failed"
                { 
                    Write-Host $ResultBlob.CheckResult -ForegroundColor Red  
                }
                "Warning"
                { 
                    Write-Host $ResultBlob.CheckResult -ForegroundColor Yellow  
                }
            }

            Write-Host "Message:     " -ForegroundColor Gray -NoNewline
            Write-Host "$($ResultBlob.CheckResultMessage)`r`n" -ForegroundColor White
        
        }
       
       default {
         switch($Result){

            { ($_ -in ( "Passed", "1") )} {
                $ResultBlob | Write-Host -ForegroundColor White
            }
            { ($_ -in ( "Warning", "2") )} {
                $ResultBlob | Write-Host -ForegroundColor Yellow
            }
            { ($_ -in ( "Failed", "3") )} {
                $ResultBlob | Write-Host -ForegroundColor Red
            }

            Default {
                $ResultBlob | Write-Host -ForegroundColor White
            }
         }
       }

       }
    }
         
    End
    {

    }
}

function New-LogEntry {
        <#
      .SYNOPSIS
       Script-wide logging function
      .DESCRIPTION
       Writes debug logging statements to script log file
      .EXAMPLE
          New-LogEntry "Entering function"
          Write log entry with information level
      
      .EXAMPLE
          New-LogEntry -Level Error -WriteStdOut "Error"
          Write error to log and also show in PowerShell output
       
      .NOTES
      NAME: New-LogEntry 
      
      Set $global:LogName at the beginning of the script
      #>
      
        [CmdletBinding()]
        param(
          [parameter(Mandatory=$true, ValueFromPipeline = $true, Position = 0)]
          [string]$Message,
      
          [Parameter(Position = 1)] 
          # 1 = Information
          # 2 = Warning
          # 3 = Error
          # 4 = Verbose
          [ValidateSet(1,2,3,4)]
          [string]$Severity = '1',
             
          [Parameter()]
          # create log in format 
          [string]$LogName = $Script:LogFilePath,

          # Write plain text to stdout instead of colorful text to host
          [Parameter()]
          [switch]
          $WriteStdOut,

          # Skip HTML output
          [Parameter()]
          [Switch]
          $NoHTML
       
        )
      
        BEGIN {
          if ( ($null -eq $LogName) -or ($LogName -eq "")) { Write-Error "Please set variable `$script`:LogFilePath." }
        }
        PROCESS {
          # only log verbose if flag is set
          if ( ($Level -eq "4") -and ( -not ($debugMode) ) ) {
            # don't log events unless flag is set
          } else {
               
            [pscustomobject]@{
              Time    = (Get-Date -f u)   
              Line    = "`[$($MyInvocation.ScriptLineNumber)`]"          
              Level   = $Level
              Message = $Message
                  
            } |  Export-Csv -Path $LogName -Append -Force -NoTypeInformation -Encoding Unicode 
      
#[switch]$toStdOut,
#[switch]$SkipHTML##
            if ($toStdOut -or  $WriteStdOut -or ( ($Level -eq "Verbose") -and $debugMode) ) { Write-Output $Message }
            else { Write-Interactive $Message -Result $Severity}
          }
        }
        END {}
      }

function Write-StatusMessage {  
        param(
            
        [parameter(Mandatory=$true, ValueFromPipeline = $true, Position = 0)]
        [string]$Message,
      
        [Parameter(Position = 1)]  
        [ValidateSet(1,2,3,4)]
        [string]$Severity = '1')
 
        [string]$FormattedMessage = ""
       
        $FormattedMessage ="`r`n$line`r`n$message`r`n`r`n$line`r`n"

        New-LogEntry $FormattedMessage -Severity $Severity
 }

function Show-Usage {

     
    New-LogEntry @"
    `r`n`r`n$line
                        Usage
$line

    Switch                 | Alias  | Explanation 
      -help                  -h     Displays help message
      -usage                 -u     Displays this usage information
      -NDESExternalHostname  -ed    External DNS name for the NDES server (SSL certificate subject will be checked for this. 
                                    It should be in the SAN of the certificate if clients communicate directly with the NDES server)
      -NDESServiceAccount    -sa    Username of the NDES service account. Format is Domain\sAMAccountName, such as Contoso\NDES_SVC.
      -IssuingCAServerFQDN   -ca    Name of the issuing CA to which you'll be connecting the NDES server.  
                                    Format is FQDN, such as 'MyIssuingCAServer.contoso.com'.
      -SCEPUserCertTemplate  -t     Name of the SCEP Certificate template. Please note this is _not_ the display name of the template.
                                        Value should not contain spaces.                                        
`r`n$line`r`n`r`n
"@      

} 

function Get-NDESHelp {

    Write-StatusMessage @'
    Verifies if the NDES server meets all the required configuration.
     
    The NDES server role is required as back-end infrastructure for Intune for delivering VPN and Wi-Fi certificates via the SCEP protocol to mobile devices and desktop clients.

    See https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure.
'@ -Severity 2

    
} 

function Confirm-Variables {
    param (
        [string]$NDESServiceAccount,
        [string]$IssuingCAServerFQDN,
        [string]$SCEPUserCertTemplate
    )

    if ($PSCmdlet.ParameterSetName -eq "Unattended") {
        $MscepRaEku = '1.3.6.1.4.1.311.20.2.1' # CEP Encryption
        # Get cert authority from the Certificate Request Agent cert.
        $IssuingCAServerFQDN = Get-Item 'Cert:\LocalMachine\My\*' | Where-Object { ($_.EnhancedKeyUsageList -match $MscepRaEku) -and ($_.Extensions.Format(1)[0].split('(')[0] -replace "template=" -match "CEPEncryption" ) }
        $SCEPUserCertTemplate = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP).EncryptionTemplate
        $confirmation = "y"
    }
    else {
        Write-StatusMessage @"

        NDES Service Account      = $NDESServiceAccount
        Issuing CA Server         = $IssuingCAServerFQDN
        SCEP Certificate Template = $SCEPUserCertTemplate

        $line
        Proceed with variables?
"@ -Severity 1
        $confirmation = Read-Host -Prompt "[Y]es, [N]" 
    }

    if ($confirmation -eq 'y') {
 
        Write-StatusMessage  @" 
        NDESServiceAccount= $NDESServiceAccount
        IssuingCAServer= $IssuingCAServerFQDN
        SCEPCertificateTemplate= $SCEPUserCertTemplate
"@ -Severity 1
    }
}

function Set-ServiceAccountisLocalSystem {
Param(
    [parameter(Mandatory=$true)]
    [bool]$isSvcAcctLclSystem
    )

    $Script:SvcAcctIsComputer = $isSvcAcctLclSystem
    New-LogEntry "Service account is local system (computer) account = $isSvcAcctLclSystem" -Severity 1
    }
 
<# Returns the name of the service account#>
function Get-NDESServiceAcct {
        [string]$NDESServiceAccount = ""

        $CARegPath = "HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector\CA*"

        if (Test-Path $CARegPath ) {
            if ( (Get-ItemProperty $CARegPath).UseSystemAccount -eq 1) {
                $NDESServiceAccount = (Get-WmiObject Win32_ComputerSystem).Domain + "`\" + $env:computerName  
                Set-ServiceAccountisLocalSystem $true
            }
            elseif (    (Get-ItemProperty $CARegPath).Username -ne "" ) {
                $NDESServiceAccount =  (Get-ItemProperty $CARegPath).Username 
            }
        }
        else {
            New-LogEntry "No certificate found in $CARegPath. Please resolve this issue and run the script again." -Severity 3

            break
        }
 
    New-LogEntry "Service Account detected = $NDESServiceAccount" -Severity 1 
    [string]$NDESServiceAccount
}

function Test-IsNDESInstalled {
        if (-not (Get-Service PFXCertificateConnectorSvc) ){    
            New-LogEntry "Error: NDES Not installed.`r`nExiting....................." -Severity 3
        break
    }
}

function Test-IsRSATADInstalled {

    [bool]$isRSATADInstalled = $false

    if ( (Get-WindowsOptionalFeature -Online -FeatureName  RSAT-AD-Tools-Feature).State -eq "Enabled") {
        $isRSATADInstalled = $true
    }
    $isRSATADInstalled
}

function Install-RSATAD {
 
    New-LogEntry "RSAT-AD-Tools-Feature is not installed. This Windows Feature is required to continue. This is a requirement for AD tests. Install now?" -Severity 2
    $response = Read-Host -Prompt "[y/n]"
    New-LogEntry "Response $response" -Severity 1

    if ( ($response).ToLower() -eq "y" ) {
        Install-WindowsFeature RSAT-AD-Tools-Feature | Out-Null
    }
    else { 
        break
    }
}
    
function Test-IsAADModuleInstalled { 
    if (Get-Module ActiveDirectory -ListAvailable) {
        New-LogEntry "Sucess: ActiveDirectory module is installed." -Severity 1
    }
    else {
        New-LogEntry "Error: ActiveDirectory module is not installed. Please run this command to install it and re-run the script:`r`nInstall-Module ActiveDirectory" -Severity 3 
        break
    }

}
function Test-IsIISInstalled {
    if (-not (Get-WindowsFeature Web-WebServer).Installed){
        $script:IISNotInstalled = $true
        New-LogEntry "IIS is not installed. Some tests will not run as we're unable to import the WebAdministration module" -Severity 2
    }
    else {
        $null = Import-Module WebAdministration 
    }
}

function Test-OSVersion {
    Write-StatusMessage    "Checking Windows OS version..." -Severity 1

    $OSVersion = (Get-CimInstance -class Win32_OperatingSystem).Version
    $MinOSVersion = "6.3"

        if ([version]$OSVersion -lt [version]$MinOSVersion){         
            New-LogEntry "Error: Unsupported OS Version. NDES requires Windows Server 2012 R2 and above." -Severity 3            
            } 
        else {        
            New-LogEntry "Success: OS Version $OSVersion is supported."  -Severity 1        
        }
}

function Test-IEEnhancedSecurityMode {
    #   Checking if IE Enhanced Security Configuration is Deactivated
    Write-StatusMessage "Checking Internet Explorer Enhanced Security Configuration settings"  -Severity 1 

    # Check for the current state of Enhanced  Security Configuration; 0 = not configured
    $escState = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
 
    if ($escState.IsInstalled -eq 0) { 
        New-LogEntry "Success: Enhanced Security Configuration is not configured." -Severity 1
    } else { 
        New-LogEntry "Error: Enhanced Security Configuration is configured." -Severity 3
    }
}

function Test-PFXCertificateConnector {
    Write-StatusMessage "Checking the `"Log on As`" for PFX Certificate Connector for Intune"  -Severity 1
    $service = Get-Service -Name "PFXCertificateConnectorSvc"

    if ($service) {
        # Get the service's process
        $serviceProcess = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $service.Name }

        # Check if the service is running as Local System or as a specific user
        if ($serviceProcess.StartName -eq "LocalSystem") {
            New-LogEntry "$($service.Name) is running as Local System"  
        } else {
            New-LogEntry "$($service.Name) is running as $($serviceProcess.StartName)"  
        }
    } else {
        New-LogEntry "PFXCertificateConnectorSvc service not found" -Severity 3  
    }
}
 
function Test-Variables {
    if ($PSCmdlet.ParameterSetName -eq "Unattended") {
        $MscepRaEku = '1.3.6.1.4.1.311.20.2.1' # CEP Encryption
        # Get cert authority from the Certificate Request Agent cert.
        $IssuingCAServerFQDN = Get-Item 'Cert:\LocalMachine\My\*' | Where-Object { ($_.EnhancedKeyUsageList -match $MscepRaEku) -and ($_.Extensions.Format(1)[0].split('(')[0] -replace "template=" -match "CEPEncryption" ) }
         
        $SCEPUserCertTemplate = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP).EncryptionTemplate
       
    }
    else {
        Write-StatusMessage @"
        NDES Service Account      = $($NDESServiceAccount)          
        Issuing CA Server         = $($IssuingCAServerFQDN)
        SCEP Certificate Template = $($SCEPUserCertTemplate)        
        $line
        
        Proceed with variables? [Y]es, [N]
"@
        $confirmation = Read-Host
        $confirmation
    }
}

function Initialize-LogFile {
      
    Write-StatusMessage @"
    Initializing log file:
         $LogFilePath 
    Proceeding with variables=YES 
    NDESServiceAccount = $NDESServiceAccount
    IssuingCAServer= $IssuingCAServerFQDN
     SCEPCertificateTemplate= $SCEPUserCertTemplate
"@ -Severity 1
}

function Test-InstallRSATTools {
    Test-IsNDESInstalled

    if ( -not ( Test-IsRSATADInstalled) ){
        Install-RSATAD
    }

}

function Test-WindowsFeaturesInstalled {
    param (
        [string]$LogFilePath
    )

    Write-StatusMessage "Checking Windows Features are installed..." -Severity 1  

    $WindowsFeatures = @("Web-Filtering","Web-Net-Ext45","NET-Framework-45-Core","NET-WCF-HTTP-Activation45","Web-Metabase","Web-WMI")

    foreach($WindowsFeature in $WindowsFeatures){
        $Feature = Get-WindowsFeature $WindowsFeature
        $FeatureDisplayName = $Feature.displayName

        if($Feature.installed){
            New-LogEntry "Success: $($FeatureDisplayName) feature is installed" -Severity 1  
        }
        else {
            New-LogEntry "Error: Required feature $FeatureDisplayName is not installed." -Severity 3  
        }
    }
} 

function Test-IISApplicationPoolHealth {
    Write-StatusMessage "Checking IIS Application Pool health..." -Severity 1
    
        if (-not ($IISNotInstalled -eq $true)){
    
            # If SCEP AppPool Exists    
            if (Test-Path 'IIS:\AppPools\SCEP'){
    
                $IISSCEPAppPoolAccount = Get-Item 'IIS:\AppPools\SCEP' | Select-Object -expandproperty processmodel | Select-Object -Expand username
                
                if ( (Get-WebAppPoolState "SCEP").value -match "Started" ){            
                    $SCEPAppPoolRunning = $true            
                }
            }    
            else {    
                New-LogEntry @"
                Error: SCEP Application Pool missing.
                Please review this document: 
                URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure 
"@ -Severity 3            
            }
        
            if ($SvcAcctIsComputer) {                  
                New-LogEntry "Skipping application pool account check since local system is used as the service axccount" -Severity 2
            }
            else {
                if ($IISSCEPAppPoolAccount -contains "$NDESServiceAccount"){                
                    New-LogEntry "Success: Application Pool is configured to use " -Severity 1 
                    New-LogEntry "Application Pool is configured to use $($IISSCEPAppPoolAccount)" -Severity 1                
                }                
                else {    
                    New-LogEntry @"
                    Error: Application Pool is not configured to use the NDES Service Account
                    Please review this article:
                    URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure" 
                    Application Pool is not configured to use the NDES Service Account
"@ -Severity 3                
                }
            }
                    
            if ($SCEPAppPoolRunning){                    
                New-LogEntry "Success: SCEP Application Pool is Started" -Severity 1                    
            }                    
            else {    
                New-LogEntry "Error: SCEP Application Pool is stopped.`r`n`t`tPlease start the SCEP Application Pool via IIS Management Console. You should also review the Application Event log output for errors." -Severity 3                    
            }    
        }
    
        else {     
            New-LogEntry "Error: IIS is not installed" -Severity 3     
        }
    
}
 
function Test-NDESInstallParameters {
    param ()

    $ErrorActionPreference = "SilentlyContinue"
 
    Write-StatusMessage "Checking NDES Install Parameters..."  

    $InstallParams = @(Get-WinEvent -LogName "Microsoft-Windows-CertificateServices-Deployment/Operational" | Where-Object {$_.id -eq "105"} |
        Where-Object {$_.message -match "Install-AdcsNetworkDeviceEnrollmentService"} |
        Sort-Object -Property TimeCreated -Descending | Select-Object -First 1)

    if ($InstallParams.Message -match '-SigningProviderName "Microsoft Strong Cryptographic Provider"' -and `
        ($InstallParams.Message -match '-EncryptionProviderName "Microsoft Strong Cryptographic Provider"')) 
    {

        Write-StatusMessage "Success: Correct CSP used in install parameters"
         
        New-LogEntry $InstallParams.Message
        New-LogEntry "Correct CSP used in install parameters:" -Severity 1
        New-LogEntry "$($InstallParams.Message)" NDES_Eventvwr 1

    }
    else {

        Write-StatusMessage "Error: Incorrect CSP selected during install. NDES only supports the CryptoAPI CSP." -Severity 3       
        New-LogEntry $InstallParams.Message -Severit 3
 
    } 
    $ErrorActionPreference = "Continue"
}

function Test-HTTPParamsRegKeys {
    param () 
    New-LogEntry "Checking registry (HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters) has been set to allow long URLs" -Severity 1

    if (-not ($IISNotInstalled -eq $true)) {
        $MaxFieldLength =  (Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxFieldLength).MaxfieldLength
        $MaxRequestBytes = (Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxRequestBytes).MaxRequestBytes

        if ($MaxFieldLength -notmatch "65534") {
            New-LogEntry "Error: MaxFieldLength not set to 65534 in the registry." -Severity 3             
            New-LogEntry 'Please review this article:'
            New-LogEntry "URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure"
 
        } else {
            New-LogEntry "Success: MaxFieldLength set correctly" -Severity 1
        }

        if ($MaxRequestBytes -notmatch "65534") {
            New-LogEntry "MaxRequestBytes not set to 65534 in the registry." -Severity 3             
            New-LogEntry 'Please review this article:'
            New-LogEntry "URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure'"
 
        } else {
            New-LogEntry "Success: MaxRequestBytes set correctly" -Severity 1
        }
    } else {
        New-LogEntry "IIS is not installed." -Severity 3
    }
}
 
function Test-SPN {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ADAccount
    )

    Write-StatusMessage "Checking SPN has been set..."  -Severity 1

    $hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname

    $spn = setspn.exe -L $ADAccount

    if ($spn -match $hostname){
        Write-StatusMessage @"
        Success. Correct SPN set for the NDES service account:
         
        $spn
"@ 
    }
    else {
        New-LogEntry @"
        Error: Missing or Incorrect SPN set for the NDES Service Account.
        Please review this article:
        URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure 
"@ -Severity 3 
    }
}
 
function Test-IntermediateCerts {
    param ()

    Write-StatusMessage "Checking there are no intermediate certs are in the Trusted Root store..." -Severity 1

    $IntermediateCertCheck = Get-Childitem cert:\LocalMachine\root -Recurse | Where-Object {$_.Issuer -ne $_.Subject}

    if ($IntermediateCertCheck){
        New-LogEntry "Error: Intermediate certificate found in the Trusted Root store. This can cause undesired effects and should be removed."  -Severity 3
        New-LogEntry "Certificates:`r`n"   -Severity 3      
        New-LogEntry $IntermediateCertCheck -Severity 3
    }
    else {
        New-LogEntry "Success:`r`nTrusted Root store does not contain any Intermediate certificates." -Severity 1
    }
} 

function Test-Certificates {
    param ()

    # Set ErrorActionPreference to SilentlyContinue
    $ErrorActionPreference = "Silentlycontinue"

    Write-StatusMessage "Checking the EnrollmentAgentOffline and CEPEncryption are present..."   -Severity 1

    $certs = Get-ChildItem cert:\LocalMachine\My\

    $EnrollmentAgentOffline = $false
    $CEPEncryption = $false

    # Loop through all certificates in LocalMachine Store
    foreach ($item in $certs) {
        $Output = ($item.Extensions | Where-Object {$_.oid.FriendlyName -like "**"}).format(0).split(",")

        if ($Output -match "EnrollmentAgentOffline") {
            $EnrollmentAgentOffline = $true
        }
            
        if ($Output -match "CEPEncryption") {
            $CEPEncryption = $true
        }
    } 
    
    # Check if EnrollmentAgentOffline certificate is present
    if ($EnrollmentAgentOffline) {
        New-LogEntry "Success: EnrollmentAgentOffline certificate is present" -Severity 1
    }
    else {
        New-LogEntry @"
            Error: EnrollmentAgentOffline certificate is not present. 
            This can occur when an account without Enterprise Admin permissions installs NDES. You may need to remove the NDES role and reinstall with the correct permissions. 
            Please refer to this article:
            URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
"@    -Severity 3 
    }
    
    # Check if CEPEncryption certificate is present
    if ($CEPEncryption) {
        New-LogEntry "Success: CEPEncryption certificate is present" -Severity 1
    }
    else {
        New-LogEntry @"
          Error: CEPEncryption certificate is not present. 
          This can occur when an account without Enterprise Admin permissions installs NDES. You may need to remove the NDES role and reinstall with the correct permissions.  
          Please review this article:
          URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
          CEPEncryption certificate is not present
"@ -Severity 3
    }

    # Set ErrorActionPreference back to Continue
    $ErrorActionPreference = "Continue"
}

function Test-TemplateNameRegKey {
    param (
        [string]$SCEPUserCertTemplate
    )

    Write-StatusMessage "Checking registry 'HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP' has been set with the SCEP certificate template name..."
    New-LogEntry "Checking registry (HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP) has been set with the SCEP certificate template name" -Severity 1

    if (-not (Test-Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP)) {
        New-LogEntry @"
                    Error: Registry key does not exist. This can occur if the NDES role has been installed but not configured.
                    Please review this article:
                    URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
"@ -Severity 3
    }
    else {
        $SignatureTemplate       = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name SignatureTemplate).SignatureTemplate
        $EncryptionTemplate      = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name EncryptionTemplate).EncryptionTemplate
        $GeneralPurposeTemplate  = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name GeneralPurposeTemplate).GeneralPurposeTemplate
        $DefaultUsageTemplate    = "IPSECIntermediateOffline"

        if ($SignatureTemplate -match $DefaultUsageTemplate -and $EncryptionTemplate -match $DefaultUsageTemplate -and $GeneralPurposeTemplate -match $DefaultUsageTemplate) {
            New-LogEntry @"
            Error: Registry has not been configured with the SCEP Certificate template name. Default values have _not_ been changed.
            Please review this article: 
            URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
"@ -Severity 3 
        }
        else {
            New-LogEntry "One or more default values have been changed."             
            New-LogEntry "Checking SignatureTemplate key..."
             
            if ($SignatureTemplate -match $SCEPUserCertTemplate) {
                New-LogEntry "Success:`r`nSCEP certificate template '$($SCEPUserCertTemplate)' has been written to the registry under the _SignatureTemplate_ key.`r`nEnsure this aligns with the usage specified on the SCEP template." -Severity 1
            }
            else {  
                New-LogEntry "Registry value:`r`n$($SignatureTemplate)"                 
                New-LogEntry "SCEP certificate template value:`r`n$($SCEPUserCertTemplate)"                 
                New-LogEntry "SignatureTemplate key does not match the SCEP certificate template name. Registry value=$($SignatureTemplate)  |  SCEP certificate template value=$($SCEPUserCertTemplate)" -Severity 2
            }

            Write-StatusMessage "Checking EncryptionTemplate key..." -Severity 1
            if ($EncryptionTemplate -match $SCEPUserCertTemplate) {
                New-LogEntry "Success: `r`nSCEP certificate template '$($SCEPUserCertTemplate)' has been written to the registry under the _EncryptionTemplate_ key. Ensure this aligns with the usage specified on the SCEP template." 
            }
            else {
                New-LogEntry '"EncryptionTemplate key does not match the SCEP certificate template name. Unless your template is explicitly set for the "Encryption" purpose, this can safely be ignored." -Severity 2'
                 
                New-LogEntry "Registry value: "
                New-LogEntry "$($EncryptionTemplate)"
                 
                New-LogEntry "SCEP certificate template value: "
                New-LogEntry "$($SCEPUserCertTemplate)"
                 
                New-LogEntry "EncryptionTemplate key does not match the SCEP certificate template name.Registry value=$($EncryptionTemplate)|SCEP certificate template value=$($SCEPUserCertTemplate)" -Severity 2
            } 
             
            Write-StatusMessage "Checking GeneralPurposeTemplate key..." -Severity 1
             
            if ($GeneralPurposeTemplate -match $SCEPUserCertTemplate) {
                New-LogEntry "Success: "
                New-LogEntry "SCEP certificate template '$($SCEPUserCertTemplate)' has been written to the registry under the _GeneralPurposeTemplate_ key. Ensure this aligns with the usage specified on the SCEP template." -Severity 1
            }
            else {
                New-LogEntry '"GeneralPurposeTemplate key does not match the SCEP certificate template name. Unless your template is set for the "Signature and Encryption" (General) purpose, this can safely be ignored." -Severity 2'                 
                New-LogEntry "Registry value:`r`n$($GeneralPurposeTemplate)" -Severity 2                 
                New-LogEntry "SCEP certificate template value:`r`n$($SCEPUserCertTemplate)" -Severity 2                 
                New-LogEntry "GeneralPurposeTemplate key does not match the SCEP certificate template name.Registry value=$($GeneralPurposeTemplate)|SCEP certificate template value=$($SCEPUserCertTemplate)" -Severity 2
            }
        }
    }

    $ErrorActionPreference = "Continue"
}

function Test-ServerCertificate {
    Write-StatusMessage "Checking IIS SSL certificate is valid for use...Checking IIS SSL certificate is valid for use" -Severity 1

    $hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
    $serverAuthEKU = "1.3.6.1.5.5.7.3.1" # Server Authentication
    $allSSLCerts = Get-ChildItem Cert:\LocalMachine\My
    $BoundServerCert = netsh http show sslcert

    foreach ($Cert in $allSSLCerts) {
        $ServerCertThumb = $Cert.Thumbprint

        if ($BoundServerCert -match $ServerCertThumb) {
            $BoundServerCertThumb = $ServerCertThumb
        }
    }

    $ServerCertObject = Get-ChildItem Cert:\LocalMachine\My\$BoundServerCertThumb

    if ($ServerCertObject.Issuer -match $ServerCertObject.Subject) {
        $SelfSigned = $true
    } else {
        $SelfSigned = $false
    }

    if ($ServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU -and (($ServerCertObject.Subject -match $hostname) -or `
        ($ServerCertObject.DnsNameList -match $hostname)) -and ($ServerCertObject.Issuer -notmatch $ServerCertObject.Subject)) {

        New-LogEntry "Success: "
        New-LogEntry "Certificate bound in IIS is valid:"
         
        New-LogEntry "Subject: "
        New-LogEntry "$($ServerCertObject.Subject)"
         
        New-LogEntry "Thumbprint: "
        New-LogEntry "$($ServerCertObject.Thumbprint)"
         
        New-LogEntry "Valid Until: "
        New-LogEntry "$($ServerCertObject.NotAfter)"
         
        New-LogEntry "If this NDES server is in your perimeter network, please ensure the external hostname is shown below:"
        $DNSNameList = $ServerCertObject.DNSNameList.unicode
         
        New-LogEntry "Internal and External hostnames: "
        New-LogEntry "$($DNSNameList)"
        New-LogEntry "Certificate bound in IIS is valid. Subject:$($ServerCertObject.Subject)|Thumbprint:$($ServerCertObject.Thumbprint)|ValidUntil:$($ServerCertObject.NotAfter)|Internal and ExternalHostnames:$($DNSNameList)" -Severity 1
    } else {
        New-LogEntry "Error: The certificate bound in IIS is not valid for use. Reason:"
         

        if ($ServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU) {
            $EKUValid = $true
        } else {
            $EKUValid = $false

            New-LogEntry "Correct EKU: "
            New-LogEntry "$($EKUValid)"
             
        }

        if ($ServerCertObject.Subject -match $hostname) {
            $SubjectValid = $true
        } else {
            $SubjectValid = $false

            New-LogEntry "Correct Subject: "
            New-LogEntry "$($SubjectValid)"
             
        }

        if ($SelfSigned -eq $false) {
            Out-Null
        } else {
            New-LogEntry "Is Self-Signed: "
            New-LogEntry "$($SelfSigned)"
             
        }

        New-LogEntry @"
                        Please review this article:
                        URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
                        The certificate bound in IIS is not valid for use. 
                        CorrectEKU=$($EKUValid)|CorrectSubject=$($SubjectValid)|IsSelfSigned=$($SelfSigned)
"@ -Severity 3
    }
}

function Test-ClientCertificate { 
    New-LogEntry "Checking encrypting certificate is valid for use..." -Severity 1
 
    $clientAuthEku = "1.3.6.1.5.5.7.3.2" # Client Authentication
    $NDESCertThumbprint = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector -Name EncryptionCertThumbprint).EncryptionCertThumbprint
    $ClientCertObject = Get-ChildItem Cert:\LocalMachine\My\$NDESCertThumbprint

    if ($ClientCertObject.Issuer -match $ClientCertObject.Subject) {
        $ClientCertSelfSigned = $true
    } else {
        $ClientCertSelfSigned = $false
    }

    if ($ClientCertObject.EnhancedKeyUsageList -match $clientAuthEku -and $ClientCertObject.Issuer -notmatch $ClientCertObject.Subject) {
        New-LogEntry "Success: Client certificate bound to NDES Connector is valid"         
        New-LogEntry "Subject: $($ClientCertObject.Subject)"          
        New-LogEntry "Thumbprint: $($ClientCertObject.Thumbprint)"         
        New-LogEntry "Valid Until:`r`n $($ClientCertObject.NotAfter)"  
    } else {
        New-LogEntry "Error: The certificate bound to the NDES Connector is not valid for use. Reason:" -Severity 3  
        
        if ($ClientCertObject.EnhancedKeyUsageList -match $clientAuthEku) {                
            $ClientCertEKUValid = $true
        } else {                
            $ClientCertEKUValid = $false

            New-LogEntry "Correct EKU: $($ClientCertEKUValid)" -Severity 1
             
        }

        if ($ClientCertSelfSigned -eq $false) {               
            New-LogEntry "ClientCertSelfSigned = $ClientCertSelfSigned" -Severity 3              
        } else {
            New-LogEntry "Is Self-Signed: $ClientCertSelfSigned" -Severity 1             
        }

        New-LogEntry @"
                      Please review this article: 
                      URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
                      The certificate bound to the NDES Connector is not valid for use. CorrectEKU= $ClientCertEKUValid IsSelfSigned= $ClientCertSelfSigned
"@ -Severity 3
    }
}
 
function Test-InternalNdesUrl {
      
    $hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
           
    Write-StatusMessage "Checking behaviour of internal NDES URL at Https://$hostname/certsrv/mscep/mscep.dll" -Severity 1

    $Statuscode = try {
        (Invoke-WebRequest -Uri "https://$hostname/certsrv/mscep/mscep.dll").StatusCode
    } catch { 
        $_ | New-LogEntry -Severity 3
    }

    if ($statuscode -eq "200") { 
        New-LogEntry "https://$hostname/certsrv/mscep/mscep.dll returns 200 OK. This usually signifies an error with the Intune Connector registering itself or the service is not installed" -Severity 3
    } elseif ($statuscode -eq "403") {
        New-LogEntry "Trying to retrieve CA Capabilities..." 
         
        try {
            $Newstatuscode = (Invoke-WebRequest -Uri "https://$hostname/certsrv/mscep/mscep.dll?operation=GetCACaps`&message=test").StatusCode
        } catch {
            $_.Exception.Response.StatusCode.Value__
        }

        if ($Newstatuscode -eq "200") {
            $CACaps = (Invoke-WebRequest -Uri "https://$hostname/certsrv/mscep?operation=GetCACaps`&message=test").Content
        }

        if ($CACaps) {
            New-LogEntry "Success:`r`nCA Capabilities retrieved:`r`n" -Severity 1             
            New-LogEntry $CACaps  -Severity 1
        }
    } else {
        New-LogEntry @"
        
        Error: Unexpected Error code. This usually signifies an error with the Intune Connector registering itself or not being installed.
        Expected value is a 403. We received a $($Statuscode). This could be down to a missing reboot after the policy module installation. 
        Verify last boot time and module install time further down the validation.
"@ -Severity 3
 
    }
   }
        
#endregion

function Test-LastBootTime {
      
    Write-StatusMessage "Checking last boot time of the server" -Severity 1

    $LastBoot = (Get-WmiObject win32_operatingsystem | Select-Object csname, @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}).lastbootuptime

    New-LogEntry @"
        Server last rebooted: $LastBoot

        Please ensure a reboot has taken place _after_ all registry changes and installing the NDES Connector. IISRESET is _not_ sufficient.
"@ -Severity 1
}

function Test-IntuneConnectorInstall {
    Write-StatusMessage "Checking if Intune Connector is installed..." -Severity 1

    if ($IntuneConnector = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object {$_.DisplayName -eq "Certificate Connector for Microsoft Intune"}) {
        $installDate = [datetime]::ParseExact($IntuneConnector.InstallDate, 'yyyymmdd', $null).ToString('dd-mm-yyyy')
        New-LogEntry "Success: $($IntuneConnector.DisplayName) was installed on $installDate and is version $($IntuneConnector.DisplayVersion)"
         
        New-LogEntry "ConnectorVersion: $IntuneConnector" -Severity 1 
    } else {
        New-LogEntry @"
        
        Error: Intune Connector not installed 

        New-LogEntry ''Please review this article: 
        New-LogEntry "URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
"@ -Severity 3
 
    }
}

function Test-IIS_Log {

    # Specify the path to the IIS log files
    $logPath = "C:\inetpub\logs\LogFiles\W3SVC1"
    $logObjects = @()

    # Specify the pattern to search for in the log files
    $logPattern = "*certsrv/mscep/mscep.dll*"

    # Get the latest log file
    $logFiles = Get-ChildItem -Path $logPath | Sort-Object LastWriteTime -Descending | Select-Object -First 2

    if ($null -ne $logFiles) {
        
        foreach ($logFile in $logFiles) {
        # Read the log file
        $logContent = Get-Content -Path $logFile.FullName| Where-Object { $_ -like $logPattern }

        foreach ($entry in $logContent) {
    
            # Split the log entry into fields
            $fields = $entry -split "\s+"
            
            # Create an object for the log entry
            $logObject = [PSCustomObject]@{
            # Date = get-date $fields[0]
            # Time = $fields[1]
                Date = get-date "$($fields[0]) $($fields[1])"
                SIP = $fields[2]
                Method = $fields[3]
                URIStem = $fields[4]
                URIQuery = $fields[5]
                SPort = $fields[6]
                Username = $fields[7]
                CIP = $fields[8]
                UserAgent = $fields[9]
                Referer = $fields[10]
                StatusCode = $fields[11]
                SubStatusCode = $fields[12]
                Win32StatusCode = $fields[13]
                TimeTaken = $fields[14]
            }
            # Add the log object to the array
            $logObjects += $logObject
        }
        # Output the log objects
        $RecentrequestinIIS = $logObjects | Select-Object -First 9

        New-LogEntry $RecentrequestinIIS
    }
    } else {
        New-LogEntry "No log files found in the specified path."
    }
}

function Test-IntuneConnectorRegKeys {
      
    New-LogEntry "Checking Intune Connector registry keys are intact" -Severity 1
    $ErrorActionPreference = "SilentlyContinue"

    $KeyRecoveryAgentCertificate = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\KeyRecoveryAgentCertificate"
    $PfxSigningCertificate = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\PfxSigningCertificate"
    $SigningCertificate = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\SigningCertificate"

    if (-not (Test-Path $KeyRecoveryAgentCertificate)) {
        New-LogEntry "Error: KeyRecoveryAgentCertificate Registry key does not exist." 
         
        New-LogEntry "KeyRecoveryAgentCertificate Registry key does not exist." -Severity 3 
    }
    else {
        $KeyRecoveryAgentCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name KeyRecoveryAgentCertificate).KeyRecoveryAgentCertificate

        if (-not ($KeyRecoveryAgentCertificatePresent)) {
            New-LogEntry "KeyRecoveryAgentCertificate registry key exists but has no value" -Severity 2 
        }
        else {
            New-LogEntry "Success: `r`nKeyRecoveryAgentCertificate registry key exists" -Severity 1
        }
    }

    if (-not (Test-Path $PfxSigningCertificate)) { 
        New-LogEntry "PfxSigningCertificate Registry key does not exist." -Severity 3 
    }
    else {
        $PfxSigningCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name PfxSigningCertificate).PfxSigningCertificate

        if (-not ($PfxSigningCertificatePresent)) {
            New-LogEntry "PfxSigningCertificate registry key exists but has no value" -Severity 2 
        }
        else {
            New-LogEntry "Success: `r`nPfxSigningCertificate registry key exists" -Severity 1
        }
    }

    if (-not (Test-Path $SigningCertificate)) { 
        New-LogEntry "SigningCertificate Registry key does not exist" -Severity 3  
    }
    else {
        $SigningCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name SigningCertificate).SigningCertificate

        if (-not ($SigningCertificatePresent)) {
            New-LogEntry "SigningCertificate registry key exists but has no value" -Severity 2
        }
        else {
            New-LogEntry "Success: SigningCertificate registry key exists" -Severity 1
        }
    }

    $ErrorActionPreference = "Continue"
}

function Get-EventLogData {
    param (
        [int]$EventLogCollDays = 5
    )

    $ErrorActionPreference = "SilentlyContinue"
 
    Write-StatusMessage "Checking Event logs for relevent errors" -Severity 1

    if (-not (Get-EventLog -LogName "Microsoft Intune Connector" -EntryType Error -After (Get-Date).AddDays(-$EventLogCollDays) -ErrorAction SilentlyContinue)) {
 
        New-LogEntry "Success: No errors found in the Microsoft Intune Connector" -Severity 1
    }
    else {
        New-LogEntry "Errors found in the Microsoft Intune Connector Event log. Please see below for the most recent 5, and investigate further in Event Viewer." -Severity 2
         
        $EventsCol1 = Get-EventLog -LogName "Microsoft Intune Connector" -EntryType Error -After (Get-Date).AddDays(-$EventLogCollDays) -Newest 5 | Select-Object TimeGenerated, Source, Message
        $EventsCol1 | Format-List
        New-LogEntry "Errors found in the Microsoft Intune Connector Event log" NDES_Eventvwr 3
        $i = 0 

        foreach ($item in $EventsCol1) {
            New-LogEntry "$($EventsCol1[$i].TimeGenerated);$($EventsCol1[$i].Message);$($EventsCol1[$i].Source)" NDES_Eventvwr 3
            $i++
        }
    }

    if (-not (Get-EventLog -LogName "Application" -EntryType Error -Source NDESConnector, Microsoft-Windows-NetworkDeviceEnrollmentService -After (Get-Date).AddDays(-$EventLogCollDays) -ErrorAction SilentlyContinue)) {
          New-LogEntry "Success: No errors found in the Application log from source NetworkDeviceEnrollmentService or NDESConnector" -Severity 1
    }
    else {
        New-LogEntry "Errors found in the Application Event log for source NetworkDeviceEnrollmentService or NDESConnector. Please see below for the most recent 5, and investigate further in Event Viewer." -Severity 2
         
        $EventsCol2 = Get-EventLog -LogName "Application" -EntryType Error -Source NDESConnector, Microsoft-Windows-NetworkDeviceEnrollmentService -After (Get-Date).AddDays(-$EventLogCollDays) -Newest 5 | Select-Object TimeGenerated, Source, Message
        $EventsCol2 | Format-List
        $i = 0 

        foreach ($item in $EventsCol2) {
            New-LogEntry "$($EventsCol2[$i].TimeGenerated);$($EventsCol2[$i].Message);$($EventsCol2[$i].Source)" -Severity 3
            $i++
        }
    }

    $ErrorActionPreference = "Continue"
}
 
function Test-NDESServiceAccountProperties {
    param (
        [string]$NDESServiceAccount
    )
 
    Write-StatusMessage "Checking NDES Service Account $NDESServiceAccount properties in Active Directory" -Severity 1

    $ADAccount = $NDESServiceAccount.split("\")[1]
    if ($SvcAcctIsComputer) {
        $ADAccountProps = Get-ADComputer $ADAccount -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut
    }
    else {
        $ADAccountProps = Get-ADUser $ADAccount -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut
    }

    if ($ADAccountProps.enabled -ne $true -OR $ADAccountProps.PasswordExpired -ne $false -OR $ADAccountProps.LockedOut -eq $true) {
        Write-StatusMessage "Error: Problem with the AD account. Please see output below to determine the issue" -Severity 3
    }
    else {
        Write-StatusMessage "Success:`r`nNDES Service Account seems to be in working order:"  -Severity 1
    }

    $msg = $ADAccountProps | Format-List SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut | Out-String
     
    New-LogEntry "$msg" -Severity 1
} 

function Test-NDESServiceAccountLocalPermissions {
    Write-StatusMessage "Checking NDES Service Account local permissions..."   -Severity 1 

    if ($SvcAcctIsComputer) { 
        Write-StatusMessage "Skipping NDES Service Account local permissions since local system is used as the service account..." -Severity 1 
    }
    else {
        if ((net localgroup) -match "Administrators"){
            $LocalAdminsMember = ((net localgroup Administrators))

            if ($LocalAdminsMember -like "*$NDESServiceAccount*"){
                New-LogEntry "NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use the IIS_IUSERS local group instead." -Severity 2 
            }
            else {
                Write-StatusMessage "Success:`r`nNDES Service account is not a member of the local Administrators group"
            }
        }
    }
}

function Test-Connectivity {
    param(
        [string]$uniqueURL = "autoupdate.msappproxy.net",
        [int]$port = 443
    )

    Write-StatusMessage "Checking Connectivity to $uniqueURL" -Severity 1

    try {
        $error.Clear()
        $connectionTest = $false

        $connection = New-Object System.Net.Sockets.TCPClient
        $connection.ReceiveTimeout = 500
        $connection.SendTimeout = 500 
        $result = $connection.BeginConnect($uniqueURL, $port, $null, $null)
        $wait = $result.AsyncWaitHandle.WaitOne(5000, $false)

        if ($wait -and (-not $connection.Client.Connected) ){
            $connection.Close()
            $connectionTest = $false
        } elseif (-not $wait) {
            $connection.Close()
            $connectionTest = $false
        } else {
            $null = $connection.EndConnect($result) 
            $connectionTest = $connection.Connected
        }
        
        if ($connectionTest) {
            New-LogEntry "Connection to $uniqueURL on port $port is successful."  -Severity 1
        } else {
            New-LogEntry "Connection to $uniqueURL on port $port failed." -Severity 3  
        }
    }
    catch {
        New-LogEntry "Error connecting to $uniqueURL. Please test that the service account has internet access." -Severity 3
   
    }
} 

  
 

function Test-NDESServiceAccountLocalPermissions {
    Write-StatusMessage "Checking NDES Service Account local permissions..." -Severity 1 
    if ($SvcAcctIsComputer) { 
        Write-StatusMessage "Skipping NDES Service Account local permissions since local system is used as the service account..." -Severity 1 
    }
    else {
        if ((net localgroup) -match "Administrators"){

            $LocalAdminsMember = ((net localgroup Administrators))

            if ($LocalAdminsMember -like "*$NDESServiceAccount*"){

                New-LogEntry "NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use the IIS_IUSERS local group instead." -Severity 2 
            }
            else {
                New-LogEntry "Success:`r`nNDES Service account is not a member of the local Administrators group" -Severity 1    
            }
        }
           else { 
                New-LogEntry "No local Administrators group exists, likely due to this being a Domain Controller or renaming the group. It is not recommended to run NDES on a Domain Controller." -Severity 2
    
        }

    }
} 
 
Function Test-IIS_IUSR_Membership {
    Write-StatusMessage "Checking if the NDES service account is a member of the IIS_IUSR group..." -Severity 1
    if ((net localgroup) -match "IIS_IUSRS"){

        $IIS_IUSRMembers = ((net localgroup IIS_IUSRS))

        if ($IIS_IUSRMembers -like "*$NDESServiceAccount*"){
            New-LogEntry "NDES service account is a member of the local IIS_IUSR group" -Severity 1    
        }

        else {
 
            New-LogEntry "Error: NDES Service Account is not a member of the local IIS_IUSR group" -Severity 3 

            Write-StatusMessage "Checking Local Security Policy for explicit rights via gpedit..." -Severity 1
             
            $TempFile = [System.IO.Path]::GetTempFileName()
            & "secedit" "/export" "/cfg" "$TempFile" | Out-Null
            $LocalSecPol = Get-Content $TempFile
            $ADAccount = $NDESServiceAccount.split("\")[1]
            # we should only be checking user accounts. If local system is the service account, we can skip this event
            $ADAccountProps = (Get-ADUser $ADAccount -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut)
            
            $NDESSVCAccountSID = $ADAccountProps.SID.Value 
            $LocalSecPolResults = $LocalSecPol | Select-String $NDESSVCAccountSID

                if ($LocalSecPolResults -match "SeInteractiveLogonRight" -and $LocalSecPolResults -match "SeBatchLogonRight" -and $LocalSecPolResults -match "SeServiceLogonRight"){
            
                    New-LogEntry @"                    
                        Success: 
                        NDES Service Account has been assigned 'Logon Locally', 'Logon as a Service' and 'Logon as a batch job' rights explicitly.

                        Note:
                        Consider using the IIS_IUSERS group instead of explicit rights as described in this article:
                        https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
"@ -Severity 1

                }
            
                else {
                    New-LogEntry "NDES Service Account has _NOT_ been assigned the Logon Locally, Logon as a Service or Logon as a batch job rights _explicitly." -Severity 3        
                }
             }

    }

    else {
   
        New-LogEntry @"
                        No IIS_IUSRS group exists. Ensure IIS is installed.

                        Please review the following article for more information:
                            https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
"@ -Severity 3

    }

}
 
Function Test-PFXCertificateConnectorService {
    Write-StatusMessage "Checking the `"Log on As`" account for the PFX Certificate Connector for Intune" -Severity 1
    $service = Get-Service -Name "PFXCertificateConnectorSvc"

    if ($service) {
        # Get the service's process
        $serviceProcess = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $service.Name }

        # Check if the service is running as Local System or as a specific user
        if ($serviceProcess.StartName -eq "LocalSystem") {
            New-LogEntry "$($service.Name) is running as Local System" -Severity 1  
        }
        else {
            New-LogEntry "$($service.Name) is running as $($serviceProcess.StartName)" -Severity 1  
        }
    } 
    else {
        New-LogEntry "PFXCertificateConnectorSvc service not found" -Severity 3  
    }

}

function Compress-LogFiles {
    param ()

    Write-StatusMessage "Gathering log files..."
    
    if ($PSCmdlet.ParameterSetName -eq "Unattended") {
        New-LogEntry "Automatically gathering files."
        $LogFileCollectionConfirmation = "y"
    }
    else {
        New-LogEntry "Do you want to gather troubleshooting files? This includes IIS, NDES Connector, NDES Plugin, CRP, and MSCEP log files, in addition to the SCEP template configuration.  [Y]es, [N]o:"
        $LogFileCollectionConfirmation = Read-Host
    }
    
    if ($LogFileCollectionConfirmation -eq "y") {
        $IISLogPath = (Get-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name logfile.directory).Value + "\W3SVC1" -replace "%SystemDrive%",$env:SystemDrive
        $IISLogs = Get-ChildItem $IISLogPath | Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
        $NDESConnectorLogs = Get-ChildItem "$env:SystemRoot\System32\Winevt\Logs\Microsoft-Intune-CertificateConnectors*"
        $NDESConnectorUpdateAgentLogs = Get-ChildItem "$env:SystemRoot\System32\Winevt\Logs\Microsoft-AzureADConnect-AgentUpdater*"

        $ApplicationEventLogFile = Get-WinEvent -ListLog "Application" | Select-Object -ExpandProperty LogFilePath
        $ApplicationLogFilePath = [System.Environment]::ExpandEnvironmentVariables( $ApplicationEventLogFile)

        $SystemEventLogFile = Get-WinEvent -ListLog "System" | Select-Object -ExpandProperty LogFilePath
        $SystemLogFilePath = [System.Environment]::ExpandEnvironmentVariables( $SystemEventLogFile)
    
        foreach ($IISLog in $IISLogs) {
            Copy-Item -Path $IISLog.FullName -Destination $TempDirPath
        }

        foreach ($NDESConnectorLog in $NDESConnectorLogs) {
            Copy-Item -Path $NDESConnectorLog.FullName -Destination $TempDirPath
        }

        foreach ($NDESConnectorUpdateAgentLog in $NDESConnectorUpdateAgentLogs) {
            Copy-Item -Path $NDESConnectorUpdateAgentLog.FullName -Destination $TempDirPath
        }

        foreach ($NDESPluginLog in $NDESPluginLogs) {
            Copy-Item -Path $NDESPluginLog.FullName -Destination $TempDirPath
        }

        foreach ($MSCEPLog in $MSCEPLogs) {
            Copy-Item -Path $MSCEPLog.FullName -Destination $TempDirPath
        }

        foreach ($CRPLog in $CRPLogs) {
            Copy-Item -Path $CRPLogs.FullName -Destination $TempDirPath
        }

        Copy-Item -Path $ApplicationLogFilePath -Destination $TempDirPath
        Copy-Item -Path $SystemLogFilePath -Destination $TempDirPath

        $GPresultPath = "$($TempDirPath)\gpresult_temp.html"
        gpresult /h $GPresultPath

        $SCEPUserCertTemplateOutputFilePath = "$($TempDirPath)\SCEPUserCertTemplate.txt"
        certutil -v -template $SCEPUserCertTemplate > $SCEPUserCertTemplateOutputFilePath

        New-LogEntry "Collecting server logs" -Severity 1

        Add-Type -assembly "system.io.compression.filesystem"
        $Currentlocation = $env:temp
        $date = Get-Date -Format ddMMyyhhmmss
        Copy-Item $LogFilePath .
        [io.compression.zipfile]::CreateFromDirectory($Script:TempDirPath, "$($Currentlocation)\$($date)-CertConnectorLogs-$($hostname).zip")

        New-LogEntry @"
        Success: Log files copied to $($Currentlocation)\$($date)-CertConnectorLogs-$($hostname).zip"

"@

        # Show in Explorer
        Start-Process $Currentlocation
    }
    else {
        New-LogEntry "Do not collect logs" -Severity 1
        $Script:WriteLogOutputPath = $true
    }
}

function Format-Log {
    <# Remove quotes from CSV #>
    param($logname = $Script:LogFilePath)

    $Contents = Get-Content $logname
    $FormattedContent = ($Contents -replace '("$|,"|",{1,2}")', '  ') -replace '^"', '' 
    $FormattedContent | Out-File $logname -Encoding utf8 -Force
}

#  Script requirements

#Requires -version 3.0
#Requires -RunAsAdministrator 
##   #Requires -module ActiveDirectory

# Script-wide Variables
[string] $name = [System.Guid]::NewGuid()
$Script:TempDirPath = Join-Path $env:temp $name
New-Item -ItemType Directory -Path $TempDirPath -Force | Out-Null
$Script:LogFilePath = "$($Script:TempDirPath)\Validate-NDESConfig.log"

# Flag to query computer vs user properties from AD
[bool]$SvcAcctIsComputer = $false
$line = "." * 60

if ($help){
    Get-NDESHelp
    break
}

if ($usage){
    Show-Usage
    break
} 
 


if ( -not ( Test-IsRSATADInstalled) ){
    Install-RSATAD
} 

Initialize-LogFile
if ($NDESServiceAccount -eq "" -or $null -eq $NDESServiceAccount) {
    $NDESServiceAccount = Get-NDESServiceAcct
}
Test-Variables
Confirm-Variables -NDESServiceAccount $NDESServiceAccount -IssuingCAServerFQDN $IssuingCAServerFQDN -SCEPUserCertTemplate $SCEPUserCertTemplate
Test-IsNDESInstalled
Test-IsAADModuleInstalled
Test-IsIISInstalled
Test-OSVersion
Test-IEEnhancedSecurityMode
Test-NDESServiceAccountProperties -NDESServiceAccount $NDESServiceAccount
Test-PFXCertificateConnector
Test-Connectivity
Test-InstallRSATTools
Test-IISApplicationPoolHealth
Test-NDESInstallParameters  
Test-HTTPParamsRegKeys  
Test-IntermediateCerts  
Test-TemplateNameRegKey -SCEPUserCertTemplate "YourSCEPCertificateTemplateName"
Test-Certificates  
Test-ServerCertificate
Test-InternalNdesUrl
Test-LastBootTime
Test-IntuneConnectorInstall
Test-IntuneConnectorRegKeys
Test-ClientCertificate
Test-WindowsFeaturesInstalled 
Test-NDESServiceAccountLocalPermissions -NDESServiceAccount $NDESServiceAccount
Test-SPN -ADAccount "NDES_Service_Account"  
Test-PFXCertificateConnectorService
Test-IIS_IUSR_Membership
Test-IIS_Log 
Get-EventLogData
Format-Log
Compress-LogFiles

#endregion 
 

#region Ending script
 
Write-StatusMessage  "End of NDES configuration validation" 
 
if ($WriteLogOutputPath) {

        New-LogEntry "Log file copied to $($LogFilePath)" -Severity 1

        # for ODC
        $copyPath = "$env:temp\CollectedData\Intune\Files\NDES"
        if ($PSCmdlet.ParameterSetName -eq "Unattended"  ){
            if ( -not (Test-Path $copyPath) ) { mkdir $copyPath -Force }
            Copy-Item $Script:LogFilePath $copyPath
            }
           
        Write-StatusMessage "Ending script..." -Severity 1
    }  
 else { 
    New-LogEntry "Skipping log copy based on command line switches" -Severity 1
 }

#endregion