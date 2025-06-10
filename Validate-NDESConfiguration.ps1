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
v1.0 - 01/29/2024 - Initial release. Copy/paste from ODC (https://aka.ms/IntuneODC) to allow for standalone use.
v1.1 - 05/04/2024 - Updated to support system account as service account
v1.2 - 06/09/2025 - Updated Test-NDESServiceAccountProperties function to support MSA (Managed Service Account detection / legacy service accounts detection), replaced $ResultsText call from a file (not it's an array) by Thiago Beier https://github.com/thiagogbeier

#>
[CmdletBinding(DefaultParameterSetName = "Unattended")]

Param(

    [parameter(Mandatory = $false, ParameterSetName = "Unattended")]
    [alias("ua", "silent", "s", "unattended")]
    [switch]$unattend,  

    [parameter(Mandatory = $true, ParameterSetName = "NormalRun")]
    [alias("sa")]
    [string]$NDESServiceAccount = "",

    [parameter(Mandatory = $true, ParameterSetName = "NormalRun")]
    [alias("ca")]
    [ValidateScript({
            $Domain = ((Get-WmiObject Win32_ComputerSystem).domain).split(".\")[0]
            if ($_ -match $Domain) {
                $true
            }
            else {   
                Throw "The Network Device Enrollment Server and the Certificate Authority are not members of the same Active Directory domain. This is an unsupported configuration."
            }
        }
    )]
    [string]$IssuingCAServerFQDN,

    [parameter(Mandatory = $true, ParameterSetName = "NormalRun")]
    [alias("t")]
    [string]$SCEPUserCertTemplate,

    [parameter(ParameterSetName = "Help")]
    [alias("h", "?", "/?")]
    [switch]$help,

    [parameter(ParameterSetName = "Help")]
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
   Write-Interactive -ResultBlob $Script:ResultBlob
.EXAMPLE
   $Script:ResultBlob | Write-Interactive
.EXAMPLE
    # Will write in default white text with a severity of 'Information'
    Write-Interactive "hi"
#>
function Write-Interactive {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Message help description
        [Parameter(Mandatory = $true,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        $ResultBlob,
        [Parameter(Mandatory = $false)]
        $Result
    )

    Begin {
    }
    Process {

        switch ($($Script:ResultBlob.GetType()).FullName) {
            System.Management.Automation.PSCustomObject {

                Write-Host "Rule:        " -ForegroundColor Gray -NoNewline
                Write-Host  $ResultBlob.RuleId -ForegroundColor White
                Write-Host "Description: " -ForegroundColor Gray -NoNewline
                Write-Host $ResultBlob.RuleDescription -ForegroundColor White
            
                Write-Host "Result:      " -ForegroundColor Gray -NoNewline
                switch ($ResultBlob.CheckResult) {
                    "Passed" {
                        Write-Host  $ResultBlob.CheckResult -ForegroundColor Green
                    }
                    "Failed" { 
                        Write-Host $ResultBlob.CheckResult -ForegroundColor Magenta # Red  
                    }
                    "Warning" { 
                        Write-Host $ResultBlob.CheckResult -ForegroundColor Yellow  
                    }
                }

                Write-Host "Message:     " -ForegroundColor Gray -NoNewline
                Write-Host "$($ResultBlob.CheckResultMessage)`r`n" -ForegroundColor White
        
            }
       
            default {
                switch ($Result) {

                    { ($_ -in ( "Passed", "1") ) } {
                        $ResultBlob | Write-Host -ForegroundColor White
                    }
                    { ($_ -in ( "Warning", "2") ) } {
                        $ResultBlob | Write-Host -ForegroundColor Yellow
                    }
                    { ($_ -in ( "Failed", "3") ) } {
                        $ResultBlob | Write-Host -ForegroundColor Red
                    }

                    Default {
                        $ResultBlob | Write-Host -ForegroundColor White
                    }
                }
            }

        }
    }
         
    End {

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
        [parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$Message,
      
        [Parameter(Position = 1)] 
        # 1 = Information
        # 2 = Warning
        # 3 = Error
        # 4 = Verbose
        [ValidateSet(1, 2, 3, 4)]
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
        }
        else {
               
            [pscustomobject]@{
                Time    = (Get-Date -f u)   
                Line    = "`[$($MyInvocation.ScriptLineNumber)`]"          
                Level   = $Level
                Message = $Message
                  
            } |  Export-Csv -Path $LogName -Append -Force -NoTypeInformation -Encoding Unicode 
      
            #[switch]$toStdOut,
            #[switch]$SkipHTML##
            if ($toStdOut -or $WriteStdOut -or ( ($Level -eq "Verbose") -and $debugMode) ) { Write-Output $Message }
            else { Write-Interactive $Message -Result $Severity }
        }
    }
    END {}
}

function Write-StatusMessage {  
    param(
            
        [parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$Message,
      
        [Parameter(Position = 1)]  
        [ValidateSet(1, 2, 3, 4)]
        [string]$Severity = '1')
 
    [string]$FormattedMessage = ""
       
    $FormattedMessage = "`r`n$line`r`n$message`r`n`r`n$line`r`n"

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
function Set-ServiceAccountisLocalSystem {
    Param(
        [parameter(Mandatory = $true)]
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
        if ( (Get-ItemProperty $CARegPath -ErrorAction SilentlyContinue).UseSystemAccount -eq 1) {
            $NDESServiceAccount = (Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain + "`\" + $env:computerName  
            Set-ServiceAccountisLocalSystem $true
        }
        elseif (    (Get-ItemProperty $CARegPath).Username -ne "" ) {
            $NDESServiceAccount = (Get-ItemProperty $CARegPath -ErrorAction SilentlyContinue).Username 
        }
    }
    else {
        New-LogEntry "No certificate found in $CARegPath. Please resolve this issue and run the script again." -Severity 3

    }
 
    New-LogEntry "Service Account detected = $NDESServiceAccount" -Severity 1 
    $NDESServiceAccount
}

function Test-IsNDESInstalled {
    Write-StatusMessage "Checking to see that NDES is installed" -Severity 1
    if ( Get-Service PFXCertificateConnectorSvc) {    
        $ruleResult = New-TestResult  -Result "Passed" -MoreInformation "NDES is installed."
    }
    else {
        $ruleResult = New-TestResult   -Result "Failed" -MoreInformation "NDES is not installed. Cannot find PFXCertificateConnectorSvc service."
        New-LogEntry "Error: NDES Not installed.`r`nExiting....................." -Severity 3
    }
             
    $ruleResult

}

function Test-IsRSATADInstalled {

    [bool]$isRSATADInstalled = $false

    if ($isadmin) {
        if ( (Get-WindowsOptionalFeature -Online -FeatureName RSAT-AD-Tools-Feature -ErrorAction SilentlyContinue).State -eq "Enabled") {
            $isRSATADInstalled = $true
        }
    }
    else {
        New-LogEntry "$skipInstall" -Severity 2
    }

    $isRSATADInstalled
}

function Install-RSATAD {
 
    if ($isadmin) {
        New-LogEntry "The RSAT-AD-Tools Windows feature is not installed. This Windows Feature is required to continue. This is a requirement for AD tests. Install now?" -Severity 2
        $response = Read-Host -Prompt "[y/n]"
        New-LogEntry "Response $response" -Severity 1

        if ( ($response).ToLower() -eq "y" ) {
            Install-WindowsFeature -Name  RSAT-AD-Tools 
        }
        else { 
            $msg = @"
            RSAT-AD-Tools-Feature was not installed successfully. Please try running this command in an elevated PowerShell window:
            
            Install-WindowsFeature -Name  RSAT-AD-Tools

"@
            New-LogEntry $msg -Severity 3
            $ResultsText = New-TestResult -TestName "Test-IsRSATAD-Installed" -Result Failed -MoreInformation $msg
        }
    }
    else {
        $msg = "Please install RSAT-AD-Tools from an elevated PowerShell window by running the command 'Install-WindowsFeature -Name  RSAT-AD-Tools'."
        New-LogEntry $msg -Severity 2
        $ResultsText = New-TestResult -TestName "Test-IsRSATAD-Installed" -MoreInformation $msg
    }
    $ResultsText  
}
    
function Test-IsAADModuleInstalled { 
    Write-StatusMessage "Testing if Entra ID module is installed."

    if (Get-Module ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue) {
        New-LogEntry "Success: ActiveDirectory module is installed." -Severity 1
        $ruleResult = New-TestResult  -result Passed -MoreInformation "Entra ID PowerShell module is installed"
    }
    else {
        $msg = "Error: ActiveDirectory module is not installed. Please run this command to install it and re-run the script:`r`nInstall-Module ActiveDirectory" 
        New-LogEntry $msg -Severity 3 
        $ruleResult = New-TestResult  -result Failed -MoreInformation $msg
    }

    $ruleResult
}
function Test-IsIISInstalled {
    if (-not (Get-WindowsFeature Web-WebServer -ErrorAction SilentlyContinue).Installed) {
        $script:IISNotInstalled = $true
        New-LogEntry "IIS is not installed. Some tests will not run as we're unable to import the WebAdministration module" -Severity 2
        $ruleResult = New-TestResult -Result Failed
    }
    else {
        $null = Import-Module WebAdministration 
        $ruleResult = New-TestResult -Result Passed
    }
    $ruleResult
}

function Test-OSVersion {
    Write-StatusMessage    "Checking Windows OS version..." -Severity 1

    $OSVersion = (Get-CimInstance -class Win32_OperatingSystem -ErrorAction SilentlyContinue).Version
    $MinOSVersion = "6.3"

    if ([version]$OSVersion -lt [version]$MinOSVersion) {         
        New-LogEntry "Error: Unsupported OS Version. NDES requires Windows Server 2012 R2 and above." -Severity 3
        $ruleResult = New-TestResult -Result Failed         
    } 
    else {        
        New-LogEntry "Success: OS Version $OSVersion is supported."  -Severity 1    
        $ruleResult = New-TestResult -Result Passed    
    }
    $ruleResult
}

function Test-IEEnhancedSecurityMode {
    #   Checking if IE Enhanced Security Configuration is Deactivated
    Write-StatusMessage "Checking Internet Explorer Enhanced Security Configuration settings"  -Severity 1 

    # Check for the current state of Enhanced  Security Configuration; 0 = not configured
    $escState = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -ErrorAction SilentlyContinue
 
 
    if ($escState.IsInstalled -eq 0) { 
        New-LogEntry "Success: Enhanced Security Configuration is not configured." -Severity 1
        $ruleResult = New-TestResult -Result Passed 
    }
    else { 
        New-LogEntry "Error: Enhanced Security Configuration is configured." -Severity 3
        $ruleResult = New-TestResult -Result Failed 
    }
    $ruleResult
 
}

function Test-PFXCertificateConnector {
    Write-StatusMessage "Checking the `"Log on As`" for PFX Certificate Connector for Intune"  -Severity 1
    $service = Get-Service -Name "PFXCertificateConnectorSvc" -ErrorAction SilentlyContinue

    if ($service) {
        # Get the service's process
        $serviceProcess = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $service.Name } -ErrorAction SilentlyContinue

        # Check if the service is running as Local System or as a specific user
        if ($serviceProcess.StartName -eq "LocalSystem") {
            $msg = "$($service.Name) is running as Local System"  
            New-LogEntry $msg
            $ruleResult = New-TestResult -Result Information -MoreInformation $msg
        }
        else {
            $msg = "$($service.Name) is running as service account $($serviceProcess.StartName)"  
            New-LogEntry  $msg
            $ruleResult = New-TestResult -Result Information -MoreInformation $msg
        }
    }
    else {
        $msg = "PFXCertificateConnectorSvc service not found"  
        New-LogEntry $msg -Severity 3
        $ruleResult = New-TestResult -Result Failed -MoreInformation $msg
        
    }
    $ruleResult
} 

function Get-TCAInfo {
    # Fetching the Template Info that is published in CA
    Write-StatusMessage "Checking the published templates"
    

    try {
        # Execute certutil -TCAInfo command
        $output = certutil.exe -TCAInfo
        if ($output) {
            $formattedOutput = $output | Out-String
            $msg = "TCAInfo:`r`n $formattedOutput"
            New-LogEntry $msg -Severity 1
            $ResultsText = New-TestResult -Result Information -MoreInformation "Successfully wrote TCA information to log."
        }
        else {
            $msg = "Cannot fetch the published template details."              
            New-LogEntry $msg -Severity 3
            $ResultsText = New-TestResult -Result Warning -MoreInformation $msg
        }
    }
    catch {
        $msg = "Template Details cannot be fetched."
        New-LogEntry $msg -Severity 3
        $ResultsText = New-TestResult -Result Warning -MoreInformation $msg
    }
    $ResultsText
}

function Get-IntuneServices {
    # Fetching the Services for Intune
    write-StatusMessage "Checking all the intune services" 

    # Define the list of services to check
    $services = @(
        "AzureADConnectAgentUpdater",
        "PFXCertificateConnectorSvc",
        "PkiCreateConnectorSvc",
        "PfxCreateLegacyConnectorSvc",
        "PkiRevokeConnectorSvc"
        "PKIConnectorSvc",
        "WAPCSvc",
        "WAPCUpdaterSvc"
    )

    # Iterate through each service and check its status
    foreach ($service in $services) {
        $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue


        if ($serviceStatus) {
            $msg = "$service is $($serviceStatus.Status)"
            New-LogEntry $msg
        	
        }
        else {
            $msg = "$service not found"
            New-LogEntry $msg
        }
    }
}
function Get-ConnectorCertificate {
    #Checking the validity of the Microsoft Intune ImportPFX Connector Certificate"
    Write-StatusMessage "Checking Microsoft Itnne ImportPFX Connector Certificate"

    $issuer = "Microsoft Intune ImportPFX Connector CA"
    $certs = Get-ChildItem -Path cert:\LocalMachine -Recurse -ErrorAction SilentlyContinue
    $matchingCerts = $certs | Where-Object { $_.Issuer -match $issuer }


    if ($matchingCerts.Count -gt 0) {
        if ($matchingCerts.Count -gt 1) {
            Write-Output "$($matchingCerts.Count) certificates issued by '$issuer' found."
        
        }
    
        foreach ($cert in $matchingCerts) {
       
            $validFromDate = $cert.NotBefore
            $validToDate = $cert.NotAfter       
            if ($validToDate -gt (Get-Date)) {
                Write-output "Certificate is valid from: $($validFromDate) until: $($validToDate)"
            
            }
            else {
                Write-output "Certificate is expired! Expiration date: $($validToDate)"
            
            }
        }
    }
    else {
        Write-Output "No certificate issued by '$issuer' found."
    
    }
}
 
function Initialize-LogFile {
    Write-StatusMessage "Initializing log file: $LogFilePath" -Severity 1
}

function Test-InstallRSATTools {
    if ( -not ( Test-IsRSATADInstalled) ) {
        Install-RSATAD
    }
}

function Test-WindowsFeaturesInstalled {
    param (
        [string]$LogFilePath
    )

    Write-StatusMessage "Checking Windows Features are installed..." -Severity 1  

    $WindowsFeatures = @("Web-Filtering", "Web-Net-Ext45", "NET-Framework-45-Core", "NET-WCF-HTTP-Activation45", "Web-Metabase", "Web-WMI")

    foreach ($WindowsFeature in $WindowsFeatures) {
        $Feature = Get-WindowsFeature $WindowsFeature
        $FeatureDisplayName = $Feature.displayName

        if ($Feature.installed) {
            New-LogEntry "Success: $($FeatureDisplayName) feature is installed" -Severity 1  
        }
        else {
            New-LogEntry "Error: Required feature $FeatureDisplayName is not installed." -Severity 3  
        }
    }
} 

function Test-IISApplicationPoolHealth {
    Write-StatusMessage "Checking IIS Application Pool health..." -Severity 1
    
    if (-not ($IISNotInstalled -eq $true)) {
        # If SCEP AppPool Exists    
        if (Test-Path 'IIS:\AppPools\SCEP') {
            $IISSCEPAppPoolAccount = Get-Item 'IIS:\AppPools\SCEP' | Select-Object -expandproperty processmodel | Select-Object -ExpandProperty username
            
            if ( (Get-WebAppPoolState "SCEP").value -match "Started" ) {            
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
            New-LogEntry "Skipping application pool account check since local system is used as the service account" -Severity 2
        }
        else {
            if ($IISSCEPAppPoolAccount -contains "$NDESServiceAccount") {                
                New-LogEntry "Application Pool is configured to use $($IISSCEPAppPoolAccount)" -Severity 1                
            }
            else {    
                New-LogEntry @"
                Error: Application Pool is not configured to use the NDES Service Account
                Please review this article:
                URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure 
"@ -Severity 3                
            }
        }
                
        if ($SCEPAppPoolRunning) {                    
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

    $InstallParams = @(Get-WinEvent -LogName "Microsoft-Windows-CertificateServices-Deployment/Operational" | Where-Object { $_.id -eq "105" } |
        Where-Object { $_.message -match "Install-AdcsNetworkDeviceEnrollmentService" } |
        Sort-Object -Property TimeCreated -Descending | Select-Object -First 1)

    if ($InstallParams.Message -match '-SigningProviderName "Microsoft Strong Cryptographic Provider"' -and `
        ($InstallParams.Message -match '-EncryptionProviderName "Microsoft Strong Cryptographic Provider"')) {

        Write-StatusMessage "Success: Correct CSP used in install parameters"
         
        New-LogEntry $InstallParams.Message
        New-LogEntry "Correct CSP used in install parameters:" -Severity 1
        New-LogEntry "$($InstallParams.Message)" -Severity 1

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
        $MaxFieldLength = (Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxFieldLength).MaxfieldLength
        $MaxRequestBytes = (Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxRequestBytes).MaxRequestBytes

        if ($MaxFieldLength -notmatch "65534") {
            New-LogEntry "Error: MaxFieldLength not set to 65534 in the registry." -Severity 3             
            New-LogEntry 'Please review this article:'
            New-LogEntry "URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure"
 
        }
        else {
            New-LogEntry "Success: MaxFieldLength set correctly" -Severity 1
        }

        if ($MaxRequestBytes -notmatch "65534") {
            New-LogEntry "MaxRequestBytes not set to 65534 in the registry." -Severity 3             
            New-LogEntry 'Please review this article:'
            New-LogEntry "URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure'"
 
        }
        else {
            New-LogEntry "Success: MaxRequestBytes set correctly" -Severity 1
        }
    }
    else {
        New-LogEntry "IIS is not installed." -Severity 3
    }
}
 
function Test-SPN {
    Write-StatusMessage "Checking SPN has been set..." -Severity 1
    $hostname = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).hostname
    $svcaccount = Get-Item "IIS:\AppPools\SCEP" | Select-Object -ExpandProperty processmodel | Select-Object -ExpandProperty username
    $spn = & setspn.exe -L $svcaccount

    if ($spn -match $hostname) {
        $msg = "Success. Correct SPN set for the NDES service account: $spn"
        New-LogEntry $msg -Severity 1
        $TestResult = New-TestResult -Result Passed -MoreInformation $msg
    }
    else {
        $msg = @"
Error: Missing or Incorrect SPN set for the NDES Service Account.
Please review this article:
URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
"@
        New-LogEntry $msg -Severity 3
        $TestResult = New-TestResult -Result Failed -MoreInformation $msg
    }
}

 
function Test-IntermediateCerts {
    param ()

    Write-StatusMessage "Checking there are no intermediate certs are in the Trusted Root store..." -Severity 1

    $IntermediateCertCheck = Get-Childitem cert:\LocalMachine\root -Recurse | Where-Object { $_.Issuer -ne $_.Subject }

    if ($IntermediateCertCheck) {
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

    #get current time
    $currentDate = Get-Date

    $EnrollmentAgentOffline = $false
    $CEPEncryption = $false

    # Loop through all certificates in LocalMachine Store
    foreach ($item in $certs) {
        
        $Output = ($item.Extensions | Where-Object { $_.oid.FriendlyName -like "**" }).format(0).split(",")
        $expirationDate = $item.NotAfter
        
        if (($Output -match "EnrollmentAgentOffline") -and ($expirationDate -gt $currentDate)) {
    
            $EnrollmentAgentOffline = $true
            $EnrollmentAgentOfflineNotAfter = $expirationDate
    
        }
      
        if (($Output -match "CEPEncryption") -and ($expirationDate -gt $currentDate)) {
        
            $CEPEncryption = $true
            $CEPEncryptionNotAfter = $expirationDate
            
        }
    } 
    
    # Check if EnrollmentAgentOffline certificate is present

    if ($EnrollmentAgentOffline) {    
        New-LogEntry "Success: EnrollmentAgentOffline certificate is present and valid till: $($EnrollmentAgentOfflineNotAfter)" -Severity 1
        c    
    }
    else {
       
        New-LogEntry @"
            Error: EnrollmentAgentOffline certificate is not present or expired. 
            This can occur when an account without Enterprise Admin permissions installs NDES. You may need to remove the NDES role and reinstall with the correct permissions. 
            Please refer to this article:
            URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
"@    -Severity 3 
    }
    
    # Check if CEPEncryption certificate is present
    if ($CEPEncryption) {
        New-LogEntry "Success: CEPEncryption certificate is present and valid till: $($CEPEncryptionNotAfter)" -Severity 1
    }
    else { 
        New-LogEntry @"
          Error: CEPEncryption certificate is not present or expired. 
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
    param ()

    Write-StatusMessage "Checking if registry 'HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP' has been set with the SCEP certificate template name..."

    if (-not (Test-Path "HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP")) {
        $msg = @"
                    Error: Registry key does not exist. This can occur if the NDES role has been installed but not configured.
                    Please review this article:
                        https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
"@
        New-LogEntry -Message $msg -Severity 3
        $TestResult = New-TestResult -Result "Failed" -MoreInformation $msg
    }
    else {
        $SignatureTemplate = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP" -Name "SignatureTemplate").SignatureTemplate
        $EncryptionTemplate = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP" -Name "EncryptionTemplate").EncryptionTemplate
        $GeneralPurposeTemplate = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP" -Name "GeneralPurposeTemplate").GeneralPurposeTemplate
        $DefaultUsageTemplate = "IPSECIntermediateOffline"

        $msg = @"
        Signature Template Configured is: $SignatureTemplate
        Encryption Template Configured is: $EncryptionTemplate
        General Purpose Template Configured is: $GeneralPurposeTemplate
"@

        New-LogEntry -Message $msg -Severity 1
    }
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
    }
    else {
        $SelfSigned = $false
    }

    if ($ServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU -and (($ServerCertObject.Subject -match $hostname) -or `
            ($ServerCertObject.DnsNameList -match $hostname)) -and ($ServerCertObject.Issuer -notmatch $ServerCertObject.Subject)) {

        New-LogEntry "Success: Certificate bound in IIS is valid:"
         
        New-LogEntry "Subject: "
        New-LogEntry "$($ServerCertObject.Subject)"
         
        New-LogEntry "Thumbprint: "
        New-LogEntry "$($ServerCertObject.Thumbprint)"
         
        New-LogEntry "Valid Until: "
        New-LogEntry "$($ServerCertObject.NotAfter)"
         
        New-LogEntry "If this NDES server is in your perimeter network, please ensure the external hostname is shown below:"
        $DNSNameList = $ServerCertObject.DNSNameList.unicode
        $script:DNSNameList = $DNSNameList
        New-LogEntry "Internal and External hostnames: "
        New-LogEntry "$($DNSNameList)"
        New-LogEntry "Certificate bound in IIS is valid. Subject:$($ServerCertObject.Subject)|Thumbprint:$($ServerCertObject.Thumbprint)|ValidUntil:$($ServerCertObject.NotAfter)|Internal and ExternalHostnames:$($DNSNameList)" -Severity 1
    }
    else {
        New-LogEntry "Error: The certificate bound in IIS is not valid for use. Reason:"
         

        if ($ServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU) {
            $EKUValid = $true
        }
        else {
            $EKUValid = $false
                  
        }
        New-LogEntry "Correct EKU: $EKUValid"      
        if ($ServerCertObject.Subject -match $hostname) {
            $SubjectValid = $true
        }
        else {
            $SubjectValid = $false
                       
        }
        New-LogEntry "Correct Subject: $SubjectValid"  
        if ($SelfSigned -eq $false) {
            Out-Null
        }
        else {
            New-LogEntry "Is Self-Signed: $SelfSigned"             
        }

        New-LogEntry @"
                        Please review this article:
                        URL: https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
                        The certificate bound in IIS is not valid for use. 
                        CorrectEKU=$($EKUValid)|CorrectSubject=$($SubjectValid)|IsSelfSigned=$($SelfSigned)
"@ -Severity 3
    }
}

Function Test-EntraAppProxy {
    #Checks if SSL cert binding to IIS has .msappproxy.net in its URL and test its connection, EXPECTING a 403 Forbidden response.
    $script:DNSNameList | ForEach-Object {
        if ($_ -like "*msappproxy.net*") {
            $url = "https://$_/certsrv/mscep/mscep.dll/"
            try {
                $response = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
                $msg = "SUCCESS: $url responded with status code $($response.StatusCode)"
                New-LogEntry $msg -Severity 1
                return New-TestResult -TestName "Test-EntraAppProxy" -Result "Passed" -MoreInformation $msg
            }
            catch {
                if ($_.Exception.Response.StatusCode.value__ -eq 403) {
                    #$msg = "EXPECTED: $url returned 403 Forbidden"
                    $msg = "$url"
                    $script:EntraAppProxyurlDNSName = $url
                    New-LogEntry $msg -Severity 1
                    return New-TestResult -TestName "Test-EntraAppProxy" -Result "Passed" -MoreInformation $msg
                }
                else {
                    $msg = "ERROR: $url returned $($_.Exception.Message)"
                    New-LogEntry $msg -Severity 3
                    return New-TestResult -TestName "Test-EntraAppProxy" -Result "Failed" -MoreInformation $msg
                }
            }
        }
        else {
            $msg = "Entra App Proxy CNAME not found in SSL CERT for $_"
            New-LogEntry $msg -Severity 3
            return New-TestResult -TestName "Test-EntraAppProxy" -Result "Warning" -MoreInformation $msg
        }
    }
}


function Test-ClientCertificate { 
    New-LogEntry "Checking encrypting certificate is valid for use..." -Severity 1
 
    $clientAuthEku = "1.3.6.1.5.5.7.3.2" # Client Authentication
    $NDESCertThumbprint = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector -Name EncryptionCertThumbprint).EncryptionCertThumbprint
    $ClientCertObject = Get-ChildItem Cert:\LocalMachine\My\$NDESCertThumbprint

    if ($ClientCertObject.Issuer -match $ClientCertObject.Subject) {
        $ClientCertSelfSigned = $true
    }
    else {
        $ClientCertSelfSigned = $false
    }

    if ($ClientCertObject.EnhancedKeyUsageList -match $clientAuthEku -and $ClientCertObject.Issuer -notmatch $ClientCertObject.Subject) {
        New-LogEntry "Success: Client certificate bound to NDES Connector is valid"         
        New-LogEntry "Subject: $($ClientCertObject.Subject)"          
        New-LogEntry "Thumbprint: $($ClientCertObject.Thumbprint)"         
        New-LogEntry "Valid Until:`r`n $($ClientCertObject.NotAfter)"  
    }
    else {
        New-LogEntry "Error: The certificate bound to the NDES Connector is not valid for use. Reason:" -Severity 3  
        
        if ($ClientCertObject.EnhancedKeyUsageList -match $clientAuthEku) {                
            $ClientCertEKUValid = $true
        }
        else {                
            $ClientCertEKUValid = $false

            New-LogEntry "Correct EKU: $($ClientCertEKUValid)" -Severity 1
             
        }

        if ($ClientCertSelfSigned -eq $false) {               
            New-LogEntry "ClientCertSelfSigned = $ClientCertSelfSigned" -Severity 3              
        }
        else {
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

    # URL To check
    $hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
    $url = "https://$hostname/certsrv/mscep/mscep.dll"  # Replace with the desired URL

    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing
        Write-statusmessage "$($response.StatusCode)"
    }
    catch [System.Net.WebException] {
        $webResponse = $_.Exception.Response
        if ($webResponse -ne $null) {
            $statusCode = [int]$webResponse.StatusCode
            if ($statusCode -eq 403) {
                $msg = "URL Response is 403 - Intune Connector is installed"
                New-LogEntry $msg -Severity 1
            }
            else {
                $msg = "URL response $($Statuscode) : Unexpected Error code. This usually signifies an error with the Intune Connector registering itself or not being installed.
                     Expected value is a 403. We received a $($Statuscode). This could be down to a missing reboot after the policy module installation. 
                     Verify last boot time and module install time further down the validation." 
                New-LogEntry $msg -Severity 3
            
            }
        }
        else {
            Write-Output "Error: Unable to reach $($url)"
        }
    }
    catch {
        Write-Output "An unexpected error occurred"
    }
}
function Test-ExternalNdesUrl {
    # Extract hostname from full URL
    try {
        $uri = [System.Uri]$script:EntraAppProxyurlDNSName
        $hostname = $uri.Host
    }
    catch {
        New-LogEntry "Invalid URL format in EntraAppProxyurlDNSName: $script:EntraAppProxyurlDNSName" -Severity 3
        return
    }

    Write-StatusMessage "Checking behaviour of external NDES URL at https://$hostname/certsrv/mscep/mscep.dll" -Severity 1

    $url = "https://$hostname/certsrv/mscep/mscep.dll"

    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing
        Write-StatusMessage "$($response.StatusCode)"
    }
    catch [System.Net.WebException] {
        $webResponse = $_.Exception.Response
        if ($webResponse -ne $null) {
            $statusCode = [int]$webResponse.StatusCode
            if ($statusCode -eq 403) {
                $msg = "URL Response is 403 - Intune NDES External URL is responsive"
                New-LogEntry $msg -Severity 1
            }
            else {
                $msg = "URL response $statusCode : Unexpected Error code. This usually signifies an error with the Intune Connector registering itself or not being installed.
                     Expected value is a 403. We received a $statusCode. This could be down to a missing reboot after the policy module installation. 
                     Verify last boot time and module install time further down the validation." 
                New-LogEntry $msg -Severity 3
            }
        }
        else {
            Write-Output "Error: Unable to reach $url"
        }
    }
    catch {
        Write-Output "An unexpected error occurred"
    }
}


function Test-LastBootTime {
      
    Write-StatusMessage "Checking last boot time of the server" -Severity 1

    $LastBoot = (Get-WmiObject win32_operatingsystem | Select-Object csname, @{LABEL = 'LastBootUpTime'; EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) } }).lastbootuptime

    New-LogEntry @"
        Server last rebooted: $LastBoot

        Please ensure a reboot has taken place _after_ all registry changes and installing the NDES Connector. IISRESET is _not_ sufficient.
"@ -Severity 1
}

function Test-IntuneConnectorInstall {
    Write-StatusMessage "Checking if Intune Connector is installed..." -Severity 1

    if ($IntuneConnector = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName -eq "Certificate Connector for Microsoft Intune" }) {
        $installDate = [datetime]::ParseExact($IntuneConnector.InstallDate, 'yyyymmdd', $null).ToString('dd-mm-yyyy')
        $ResultsText = New-TestResult -Result Passed -MoreInformation "Success: $($IntuneConnector.DisplayName) was installed on $installDate and is version $($IntuneConnector.DisplayVersion)"
         
        New-LogEntry "ConnectorVersion: $IntuneConnector" -Severity 1 
    }
    else {
        New-LogEntry @"
        
        Error: Intune Connector not installed 
        Please review this article:
            https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
"@ -Severity 3
        $ResultsText = New-TestResult "Intune Certificate Connector is not installed" -Result Failed
    }
    $ResultsText
}

function Test-IIS_Log {

    if ($isadmin) {
        # Specify the path to the IIS log files
        $IISlogPath = (Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter "system.applicationHost/sites/siteDefaults/logFile" -Name "directory").Value + "\W3SVC1"
      
        $logObjects = @()

        # Specify the pattern to search for in the log files
        $logPattern = "*certsrv/mscep/mscep.dll*"

        # Get the latest log file
        if (Test-Path $IISlogPath) {
            $logFiles = Get-ChildItem -Path $IISlogPath | Sort-Object LastWriteTime -Descending | Select-Object -First 2

            if ($null -ne $logFiles) {
            
                foreach ($logFile in $logFiles) {
                    $logContent = Get-Content -Path $logFile.FullName | Where-Object { $_ -like $logPattern }

                    foreach ($entry in $logContent) {
        
                        # Split the log entry into fields
                        $fields = $entry -split "\s+"
                
                        # Create an object for the log entry
                        $logObject = [PSCustomObject]@{
                            # Date = get-date $fields[0]
                            # Time = $fields[1]
                            Date            = get-date "$($fields[0]) $($fields[1])"
                            SIP             = $fields[2]
                            Method          = $fields[3]
                            URIStem         = $fields[4]
                            URIQuery        = $fields[5]
                            SPort           = $fields[6]
                            Username        = $fields[7]
                            CIP             = $fields[8]
                            UserAgent       = $fields[9]
                            Referer         = $fields[10]
                            StatusCode      = $fields[11]
                            SubStatusCode   = $fields[12]
                            Win32StatusCode = $fields[13]
                            TimeTaken       = $fields[14]
                        }
                        # Add the log object to the array
                        $logObjects += $logObject
                    }
                    # Output the log objects
                    $RecentrequestinIIS = $logObjects | Select-Object -First 9
                }

                if ($RecentrequestinIIS) {

                    New-LogEntry "Found SCEP request in IIS log: " -Severity 1 
                    foreach ($CertRequest in $RecentrequestinIIS) {
                        New-LogEntry "$($CertRequest)" -Severity 1 
                    }
                    $ResultsText = New-TestResult -Result Passed -MoreInformation $RecentrequestinIIS[0].ToString()   
                }
            }
            else {
                $msg = "No log files found in the specified path." 
                New-LogEntry $msg -Severity 2
                $ResultsText = New-TestResult -Result Warning -MoreInformation $msg
            }
        }
        else {
            
            $msg = "Cannot find path $IISlogPath." 
            New-LogEntry $msg -Severity 2
            $ResultsText = New-TestResult -Result Warning -MoreInformation $msg
        }
    }
    else {
        $msg = "Skipping IIS logs. Please re-run this script in an elevated PowerShell window to collect."
        New-LogEntry $msg -Severity 2
        $ResultsText = New-TestResult -Result Warning -MoreInformation $msg 
    }
    $ResultsText
}

function Get-EventLogData {
    param (
        [int]$EventLogCollDays = 5
    )
    Write-StatusMessage "Checking Event logs for relevent errors" -Severity 1

    $ConnectorlogAdmin = "Microsoft-Intune-CertificateConnectors/Admin"
    #check last 2 days event log
    $EventstartTime = (Get-Date).AddDays(-2)    

    # if (-not (Get-EventLog -LogName "Microsoft Intune Connector" -EntryType Error -After (Get-Date).AddDays(-$EventLogCollDays) -ErrorAction SilentlyContinue)) {
    #Get-eventlog doesn't work for non-system build-in event, use get-winEventinstead
    if (-not (Get-WinEvent -FilterHashtable @{LogName = $ConnectorlogAdmin; StartTime = $EventstartTime; ID = '1001', '1201', '2001', '3001', '4001', '4002' } -MaxEvents 5 -ErrorAction SilentlyContinue)) {
        New-LogEntry "Success: No errors found in the Microsoft Intune Connector" -Severity 1
    }
    else {
        New-LogEntry "Errors found in the Microsoft Intune Connector Event log. Please see below for the most recent 5, and investigate further in Event Viewer." -Severity 2
         
        # $EventsCol1 = Get-EventLog -LogName "Microsoft Intune Connector" -EntryType Error -After (Get-Date).AddDays(-$EventLogCollDays) -Newest 5 | Select-Object TimeGenerated, Source, Message
        $EventsCol1 = Get-WinEvent -FilterHashtable @{LogName = $ConnectorlogAdmin; StartTime = $EventstartTime } -MaxEvents 5 -ErrorAction SilentlyContinue
        $EventsCol1 | Format-List
        New-LogEntry "Errors found in the Microsoft Intune Connector Event log" -Severity 3
        $i = 0 

        foreach ($item in $EventsCol1) {
            New-LogEntry "$($EventsCol1[$i].TimeGenerated);$($EventsCol1[$i].Message);$($EventsCol1[$i].Source)" -Severity 3
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

}
 
function Test-NDESServiceAccountProperties {
    param (
        [string]$NDESServiceAccount,
        [bool]$SvcAcctIsComputer = $false
    )

    Write-StatusMessage "Checking NDES Service Account $NDESServiceAccount properties in Active Directory" -Severity 1

    $ADAccount = $NDESServiceAccount.Split("\")[-1]
    $ADAccountProps = $null

    if ($SvcAcctIsComputer) {
        # Check if the account is a computer object
        $ADAccountProps = Get-ADComputer $ADAccount -Properties SamAccountName, Enabled, AccountExpirationDate, AccountExpires, AccountLockoutTime, PasswordExpired, PasswordLastSet, PasswordNeverExpires, LockedOut -ErrorAction SilentlyContinue
    }
    elseif ($ADAccount.EndsWith("$")) {
        # Likely a Managed Service Account (MSA or gMSA)
        Write-Host "Checking MSA"
        $ADAccountProps = Get-ADServiceAccount -Filter { SamAccountName -eq $ADAccount } -Properties SamAccountName, Enabled, AccountExpirationDate, AccountExpires, AccountLockoutTime, PasswordExpired, PasswordLastSet, PasswordNeverExpires, LockedOut -ErrorAction SilentlyContinue
    }
    else {
        # Regular user account
        Write-Host "Checking legacy service account" #some NDES deployment might still have legacy way to setup service accounts
        $ADAccountProps = Get-ADUser $ADAccount -Properties SamAccountName, Enabled, AccountExpirationDate, AccountExpires, AccountLockoutTime, PasswordExpired, PasswordLastSet, PasswordNeverExpires, LockedOut -ErrorAction SilentlyContinue
    }

    if ($null -eq $ADAccountProps) {
        Write-StatusMessage "Error: Could not find account $ADAccount in Active Directory." -Severity 3
        return
    }

    if ($ADAccountProps.Enabled -ne $true -or $ADAccountProps.PasswordExpired -ne $false -or $ADAccountProps.LockedOut -eq $true) {
        Write-StatusMessage "Error: Problem with the AD account. Please see output below to determine the issue" -Severity 3
    }
    else {
        Write-StatusMessage "Success:`r`nNDES Service Account seems to be in working order:" -Severity 1
    }

    $msg = $ADAccountProps | Format-List SamAccountName, Enabled, AccountExpirationDate, AccountExpires, AccountLockoutTime, PasswordExpired, PasswordLastSet, PasswordNeverExpires, LockedOut | Out-String

    New-LogEntry "$msg" -Severity 1
    $ResultsText = New-TestResult -TestName "Test-NDESServiceAccountProperties" -MoreInformation $msg -Result Information
    Write-Host $ResultsText
    return $ResultsText
}


function Test-NDESServiceAccountLocalPermissions {
    Write-StatusMessage "Checking NDES Service Account local permissions..."

    if ($SvcAcctIsComputer) { 
        Write-StatusMessage "Skipping NDES Service Account local permissions since local system is used as the service account..." -Severity 1
        $ResultsText = New-TestResult "Skipping NDES Service Account local permissions since local system is used as the service account..." -Result Information
    }
    else {
        if ((net localgroup) -match "Administrators") {
            $LocalAdminsMember = (net localgroup Administrators)

            if ($LocalAdminsMember -like "*$NDESServiceAccount*") {
                $msg = "NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use the IIS_IUSERS local group instead."
                $ResultsText = New-TestResult $msg -Result Warning
            }
            else {
                $msg = "Success:`r`nNDES Service account is not a member of the local Administrators group"
                New-LogEntry $msg -Severity 3
                $ResultsText = New-TestResult $msg -Result Failed
            }
            
        }
    }
    $ResultsText
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

        if ($wait -and (-not $connection.Client.Connected) ) {
            $connection.Close()
            $connectionTest = $false
        }
        elseif (-not $wait) {
            $connection.Close()
            $connectionTest = $false
        }
        else {
            $null = $connection.EndConnect($result) 
            $connectionTest = $connection.Connected
        }
        
        if ($connectionTest) {
            $msg = "Connection to $uniqueURL on port $port is successful."  
            New-LogEntry $msg -Severity 1
            $ResultsText = New-TestResult -Result Passed -MoreInformation $msg
        }
        else {
            $msg = "Connection to $uniqueURL on port $port failed."
            New-LogEntry $msg -Severity 3
            $ResultsText = New-TestResult -Result Failed -MoreInformation $msg
        }
    }
    catch {
        $msg = "Error connecting to $uniqueURL. Please test that the service account has internet access."
        New-LogEntry $msg -Severity 3
        $ResultsText = New-TestResult -Result Failed -MoreInformation $msg
   
    }
    $ResultsText
} 

function Test-NDESServiceAccountLocalPermissions {
    Write-StatusMessage "Checking NDES Service Account local permissions..." -Severity 1 
    if ($SvcAcctIsComputer) { 
        $msg = "Skipping NDES Service Account local permissions since local system is used as the service account..."
        New-LogEntry $msg -Severity 1 
        $ResultsText = New-TestResult -Result Information -MoreInformation $msg
    }
    else {
        if ( (net localgroup) -match "^`*Administrators$") {

            $LocalAdminsMembers = (net localgroup Administrators)
               
            if ($LocalAdminsMembers -like "*$NDESServiceAccount*") {
                $msg = "NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use the IIS_IUSERS local group instead."
                New-LogEntry $msg -Severity 2
                $ResultsText = New-TestResult -Result Warning -MoreInformation $msg
            }
            else {             
                $msg = "Success:`r`nNDES Service account is not a member of the local Administrators group" 
                New-LogEntry $msg-Severity 1    
                $ResultsText = New-TestResult -Result Passed -MoreInformation $msg
            }
        }
        else { 
            $msg = "No local Administrators group exists, likely due to this being a Domain Controller or renaming the group. It is not recommended to run NDES on a Domain Controller." 
            New-LogEntry $msg-Severity 2
            $ResultsText = New-TestResult -Result Warning -MoreInformation $msg
        }   
    }
    $ResultsText
} 
 
Function Test-IIS_IUSR_Membership {
    Write-StatusMessage "Checking if the NDES service account is a member of the IIS_IUSR group..." -Severity 1

    if ($SvcAcctIsComputer) {
        $msg = "NDES service account is running as local system. Skipping test for local IIS_IUSR group membership." 
        New-LogEntry $msg -Severity 1    
        $ResultsText = New-TestResult $msg -Result Information
    }
    else {
        if ((net localgroup) -match "IIS_IUSRS") {

            $IIS_IUSRMembers = (net localgroup IIS_IUSRS)

            if ($IIS_IUSRMembers -like "*$NDESServiceAccount*") {
                New-LogEntry "NDES service account is a member of the local IIS_IUSR group" -Severity 1    
            }
            else {
    
                New-LogEntry "Error: NDES Service Account is not a member of the local IIS_IUSR group" -Severity 3 
                
                $TempFile = [System.IO.Path]::GetTempFileName()
                & "secedit" "/export" "/cfg" "$TempFile" | Out-Null
                $LocalSecPol = Get-Content $TempFile
                $ADAccount = $NDESServiceAccount.split("\")[1]
                # we should only be checking user accounts. If local system is the service account, we can skip this event
                $ADAccountProps = (Get-ADUser $ADAccount -Properties SamAccountName, enabled, AccountExpirationDate, accountExpires, accountlockouttime, PasswordExpired, PasswordLastSet, PasswordNeverExpires, LockedOut)
                
                $NDESSVCAccountSID = $ADAccountProps.SID.Value 
                $LocalSecPolResults = $LocalSecPol | Select-String $NDESSVCAccountSID

                if ($LocalSecPolResults -match "SeInteractiveLogonRight" -and $LocalSecPolResults -match "SeBatchLogonRight" -and $LocalSecPolResults -match "SeServiceLogonRight") {
            
                    $msg = @"                    
                    Success: 
                    NDES Service Account has been assigned 'Logon Locally', 'Logon as a Service' and 'Logon as a batch job' rights explicitly.
                    
                    Note:
                    Consider using the IIS_IUSERS group instead of explicit rights as described in this article:
                    https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
"@
                    New-LogEntry $msg -Severity 1
                    $ResultsText = New-TestResult -Result Passed -MoreInformation $msg

                }            
                else {
                    $msg = "NDES Service Account has _NOT_ been assigned the Logon Locally, Logon as a Service or Logon as a batch job rights _explicitly."
                    New-LogEntry $msg -Severity 3   
                    $ResultsText = New-TestResult -Result failed -MoreInformation $msg     
                }
            }
        }
        else {
    
            $msg = @"
            No IIS_IUSRS group exists. Ensure IIS is installed.
            Please review the following article for more information:
            https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
"@ 
            New-LogEntry $msg -Severity 3
            $ResultsText = New-TestResult -Result Failed -MoreInformation $msg

        }

    }
    $ResultsText
}
 
Function Test-PFXCertificateConnectorService {
    Write-StatusMessage "Checking the `"Log on As`" account for the PFX Certificate Connector for Intune" -Severity 1
    $service = Get-Service -Name "PFXCertificateConnectorSvc"

    if ($service) {
        # Get the service's process
        $serviceProcess = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $service.Name }

        # Check if the service is running as Local System or as a specific user
        if ($serviceProcess.StartName -eq "LocalSystem") {
            $msg = "$($service.Name) is running as Local System"
            New-LogEntry $msg -Severity 1  
        }
        else {
            $msg = "$($service.Name) is running as $($serviceProcess.StartName)" 
            New-LogEntry $msg -Severity 1  
        }
        $ResultsText = New-TestResult -Result Passed -MoreInformation $msg
    } 
    else {
        $msg = "PFXCertificateConnectorSvc service not found" 
        New-LogEntry $msg -Severity 3
        $ResultsText = New-TestResult -Result Failed -MoreInformation $msg 
    }
    $ResultsText
}
function Compress-LogFiles {
    param ()

    Write-StatusMessage "Gathering log files..."
    
    if ($PSCmdlet.ParameterSetName -eq "Unattended" ) {
        New-LogEntry "Automatically gathering files."
        $LogFileCollectionConfirmation = "y"
    }
    else {
        New-LogEntry "Do you want to gather troubleshooting files? This includes IIS, NDES Connector, NDES Plugin, CRP, and MSCEP log files, in addition to the SCEP template configuration.  [Y]es, [N]o:"
        $LogFileCollectionConfirmation = Read-Host
    }
    
    if ($LogFileCollectionConfirmation -eq "y") {
        $IISLogPath = (Get-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name logfile.directory).Value + "\W3SVC1" -replace "%SystemDrive%", $env:SystemDrive
        $IISLogs = Get-ChildItem $IISLogPath | Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
        $NDESConnectorLogs = Get-ChildItem "$env:SystemRoot\System32\Winevt\Logs\Microsoft-Intune-CertificateConnectors*"
        $NDESConnectorUpdateAgentLogs = Get-ChildItem "$env:SystemRoot\System32\Winevt\Logs\Microsoft-AzureADConnect-AgentUpdater*"
        $CAPI2Logs = Get-ChildItem "$env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-CAPI2%4Operational*"
        
        $ApplicationEventLogFile = Get-WinEvent -ListLog "Application" | Select-Object -ExpandProperty LogFilePath
        $ApplicationLogFilePath = [System.Environment]::ExpandEnvironmentVariables( $ApplicationEventLogFile)

        $SystemEventLogFile = Get-WinEvent -ListLog "System" | Select-Object -ExpandProperty LogFilePath
        $SystemLogFilePath = [System.Environment]::ExpandEnvironmentVariables( $SystemEventLogFile)
        $registryPath = "HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector"

        if (Test-Path $IISLogPath) {
            foreach ($IISLog in $IISLogs) {
                Copy-Item -Path $IISLog.FullName -Destination $TempDirPath
            }
        }
        else {
            New-LogEntry "Unable to find $IISLogPath" -Severity 2
        }

        foreach ($NDESConnectorLog in $NDESConnectorLogs) {
            Copy-Item -Path $NDESConnectorLog.FullName -Destination $TempDirPath
        }

        foreach ($CAPI2Logs in $CAPI2Logs) {
            Copy-Item -Path $CAPI2Logs.FullName -Destination $TempDirPath
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

        #Collect Registry Details
        $outputFilePath = "$($TempDirPath)\registry.txt"
        Get-ItemProperty -Path $registryPath | Out-File -FilePath $outputFilePath -Force
        Get-ChildItem -Path $registryPath | Out-File -FilePath $outputFilePath -Append -Force
        
        $SCEPUserCertTemplate = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP).EncryptionTemplate
        $SCEPUserCertTemplateOutputFilePath = "$($TempDirPath)\SCEPUserCertTemplate.txt"
        certutil -v -template $SCEPUserCertTemplate > $SCEPUserCertTemplateOutputFilePath

        New-LogEntry "Collecting server logs" -Severity 1

        Add-Type -assembly "system.io.compression.filesystem"
        $Currentlocation = $env:temp
        $date = Get-Date -Format ddMMyyhhmmss
        Copy-Item $LogFilePath .
        [io.compression.zipfile]::CreateFromDirectory($Script:TempDirPath, "$($Currentlocation)\$($date)-CertConnectorLogs-$($env:COMPUTERNAME).zip")

        New-LogEntry @"
        Success: Log files copied to $($Currentlocation)\$($date)-CertConnectorLogs-$($env:COMPUTERNAME).zip"

"@

        # Show in Explorer
        Start-Process $Currentlocation
    }
    else {
        New-LogEntry "Do not collect logs" -Severity 1
       
    }
}
function Format-Log {
    <# Remove quotes from CSV #>
    param($logname = $Script:LogFilePath)

    $Contents = Get-Content $logname
    $FormattedContent = ($Contents -replace '("$|,"|",{1,2}")', '  ') -replace '^"', '' 
    $FormattedContent | Out-File $logname -Encoding utf8 -Force
}
 
function Get-CSVInfo {
    Param ([string]$fileName = "test.csv") 
    if (Test-Path $fileName) {
        # Read the CSV file
        $csvData = Import-Csv $fileName 
        $Results = @{}

        foreach ($row in $csvData) {
            $Results.add( $row.TestName, @{ "Passed" = $row.Passed; "Failed" = $row.Failed } )
        }
    }
    else {
        New-LogEntry "File not found: $fileName" -Severity 3    
        break
    }
    $Results
        
}


function New-HTMLReport {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$resultBlob
    )

    $head = @'
    <style>
    body { background-color:#ffffff; font-family:Tahoma; font-size:12pt; }
    table { border-spacing: 0; width: 100%; border: 1px solid #ddd; margin: auto; }
    th { background-color: #6495ED; cursor: pointer; }
    th, td { border: 1px solid #ddd; text-align: left; padding: 10px; }
    td.green { color: green; }
    td.orange { color: orange; }
    td.red { color: red; }
    .active { color: #efefef; font-style: italic; }
    </style>
'@

    $preContent = "<h1>NDES Validation Results</h1>"

    $script = @'
    <script>
    window.onload = function() {
        const headings = document.querySelectorAll('tr th');
        const col = Array.from(headings).find(hd => hd.innerHTML === "Test Result");
        const inx = Array.from(col.parentNode.children).indexOf(col);
        const cells = col.closest('table').querySelectorAll(`td:nth-child(${inx+1})`);
        Array.from(cells).forEach(td => {
            switch (td.innerHTML.trim()) {
                case "Passed": td.classList.add("green"); break;
                case "Warning": td.classList.add("orange"); break;
                case "Failed": td.classList.add("red"); break;
            }
        });
    }
    </script>
'@

    # Filter out empty or malformed entries
    $filteredBlob = $resultBlob | Where-Object {
        $_.'Test Name' -and $_.'Test Result' -and $_.'Test Name'.Trim() -ne "" -and $_.'Test Result'.Trim() -ne ""
    }

    $html = $filteredBlob | ConvertTo-Html -Head $head -Body $script -PreContent $preContent
    $now = (Get-Date).ToString("ddMMyyyyhhmmss")
    $HTMLFileName = Join-Path $pwd "Validate-NDESConfiguration-$now.html"
    $html | Out-File -FilePath $HTMLFileName -Force
    return $HTMLFileName
}

function New-TestResult {

    <#
    .SYNOPSIS
    Helper function to return a formatted rule output object
    .DESCRIPTION
    Returns a rule result object for reporting
    .EXAMPLE
    New-TestResult

    .NOTES
    NAME: New-TestResult
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$TestName = $(Get-PSCallStack)[0].Command, 
        [ValidateSet("Passed", "Warning", "Failed", "Information")]
        [string]$Result = "Information", 
        [string]$MoreInformation = "" 
    )


    $TestResult = [PSCustomObject] [Ordered] @{ 
        'Test Name'        = $TestName
        'Test Result'      = $Result     
        'More information' = $MoreInformation
    }
 
 
    $TestResult
}

Function Test-IsAdmin {
    ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent() `
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}



#endregion


#  Script requirements

#Requires -version 3.0
# y#Requires -RunAsAdministrator 
##   #Requires -module ActiveDirectory

# Script-wide Variables
[string] $name = [System.Guid]::NewGuid()
$Script:TempDirPath = Join-Path $env:temp $name
New-Item -ItemType Directory -Path $TempDirPath -Force | Out-Null
[string]$Script:LogFilePath = "$($Script:TempDirPath)\Validate-NDESConfig.log"
[PSCustomObject[]]$ResultBlob = @()
[bool]$isadmin = Test-IsAdmin


# ✅ OS Type Check: Ensure script runs only on Windows Server (ProductType 2 or 3)
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $productType = $osInfo.ProductType
    $caption = $osInfo.Caption

    New-LogEntry "Detected OS: $caption (ProductType: $productType)" -Severity 1

    if ($productType -eq 1) {
        $msg = "This script is intended to run only on Windows Server. Detected: $caption. Exiting..."
        New-LogEntry $msg -Severity 3
        Write-Host $msg -ForegroundColor Red
        exit
    }
}
catch {
    $msg = "Unable to determine OS type. Exiting for safety."
    New-LogEntry $msg -Severity 3
    Write-Host $msg -ForegroundColor Red
    exit
}



# Flag to query computer vs user properties from AD
[bool]$SvcAcctIsComputer = $false
$line = "." * 60
# common messages
[string]$skipInstall = "Skipping installation. Please re-run the script in an elevated PowerShell window."

Initialize-LogFile
#$ResultsText = ".\ResultMessages.csv" | Import-Csv #updated by an array below by Thiago Beier on 06/09/2025

$ResultsText = @{
    "Test-IsNDESInstalled"                    = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-NDESServiceAccountProperties"       = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-Certificates"                       = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-ServerCertificate"                  = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-IntuneConnectorInstall"             = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-IISApplicationPoolHealth"           = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-WindowsFeaturesInstalled"           = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-OSVersion"                          = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-SPN"                                = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-IsIISInstalled"                     = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-InstallRSATTools"                   = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-InternalNdesUrl"                    = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-IIS_Log"                            = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-IEEnhancedSecurityMode"             = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-NDESInstallParameters"              = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-TemplateNameRegKey"                 = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-IntermediateCerts"                  = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-Connectivity"                       = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-IsAADModuleInstalled"               = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-LastBootTime"                       = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-IntuneConnectorRegKeys"             = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-PFXCertificateConnector"            = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-NDESServiceAccountLocalPermissions" = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-ClientCertificate"                  = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-HTTPParamsRegKeys"                  = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-IIS_IUSR_Membership"                = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-PFXCertificateConnectorPermissions" = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-EntraAppProxy"                      = @{ Passed = "Passed"; Failed = "Failed" }
    "Test-ExternalNdesUrl"                    = @{ Passed = "Passed"; Failed = "Failed" } #not in use
}


$ResultsText
if ($help) {
    Get-NDESHelp
    break
}

if ($usage) {
    Show-Usage
    break
} 
 
if ( Test-IsRSATADInstalled) {
    $mi = "RSAT AD tools are installed."
    $ResultBlob += New-TestResult -TestName "Test-ISRSATADInstalled"  -Result "Passed" -MoreInformation $mi
}
else {
    if ($isadmin) {
        Install-RSATAD
    }
    else {
        $ResultBlob += New-TestResult -TestName "Test-ISRSATADInstalled" -Result "Warning" -MoreInformation "Unable to install RSAT AD tools. Please install from an elevated PowerShell window and then run this script again."
    }
}

if ($NDESServiceAccount -eq "" -or $null -eq $NDESServiceAccount) {
    $NDESServiceAccount = Get-NDESServiceAcct
}

#Test-Variables
#$ResultsText = Get-CSVInfo -fileName ".\ResultMessages.csv" #updated by the following array


$ResultBlob += Test-IsNDESInstalled
$ResultBlob += Test-IsAADModuleInstalled
$ResultBlob += Test-IsIISInstalled
$ResultBlob += Test-OSVersion
$ResultBlob += Test-IEEnhancedSecurityMode
$ResultBlob += Test-NDESServiceAccountProperties -NDESServiceAccount $NDESServiceAccount
$ResultBlob += Test-PFXCertificateConnector
$ResultBlob += Test-Connectivity
$ResultBlob += Test-InstallRSATTools
$ResultBlob += Test-IISApplicationPoolHealth
$ResultBlob += Test-NDESInstallParameters  
$ResultBlob += Test-HTTPParamsRegKeys  
$ResultBlob += Test-IntermediateCerts   
$ResultBlob += Test-TemplateNameRegKey
$ResultBlob += Test-Certificates  
$ResultBlob += Test-ServerCertificate
$ResultBlob += Test-InternalNdesUrl
$ResultBlob += Test-LastBootTime
$ResultBlob += Test-IntuneConnectorInstall 
$ResultBlob += Test-ClientCertificate
$ResultBlob += Test-WindowsFeaturesInstalled 
$ResultBlob += Test-NDESServiceAccountLocalPermissions -NDESServiceAccount $NDESServiceAccount
$ResultBlob += Test-SPN -ADAccount $NDESServiceAccount
$ResultBlob += Test-IIS_IUSR_Membership
$ResultBlob += Test-IIS_Log
$ResultBlob += Get-TCAInfo
$ResultBlob += Get-IntuneServices
$ResultBlob += Test-EntraAppProxy
#$ResultBlob += Test-ExternalNdesUrl #not in use

if ($isadmin) {
    Get-EventLogData
}
else { New-LogEntry -Message "Unable to gather evtx logs as non-admin. Please run script elevated to collect." }
 
Format-Log
Compress-LogFiles
  
foreach ($entry in $ResultBlob) {
    if ( $entry.'More Information' -eq "" ) { 
        switch ($entry.'Test Result') {
            'Passed' { $entry.'More Information' = $ResultsText[$entry.'Test Name'].Passed } 
            'Failed' { $entry.'More Information' = $ResultsText[$entry.'Test Name'].Failed } 
            'Warning' { $entry.'More Information' = $ResultsText[$entry.'Test Name'].Warning } 
            'Information' { $entry.'More Information' = $ResultsText[$entry.'Test Name'].Information } 

        }
    }
} 
$HTMLFileName = New-HTMLReport -resultBlob $ResultBlob
$ResultBlob | Out-File -FilePath .\Validate-NDESConfig-Testresults.txt -Encoding utf8 -Force -Width 1000


if (Test-Path $HTMLFileName) {
    Start-Process $HTMLFileName
}
 
 
#endregion 
 

#region Ending script
 
Write-StatusMessage  "End of NDES configuration validation" 
 
if ($odc) {

    New-LogEntry "Log file copied to $($LogFilePath)" -Severity 1

    # for ODC
    $copyPath = "$env:temp\CollectedData\Intune\Files\NDES"
    if ($PSCmdlet.ParameterSetName -eq "Unattended"  ) {
        if ( -not (Test-Path $copyPath) ) { mkdir $copyPath -Force }
        Copy-Item $Script:LogFilePath $copyPath
    }
           
    Write-StatusMessage "Ending script..." -Severity 1
}  
 

#endregion
