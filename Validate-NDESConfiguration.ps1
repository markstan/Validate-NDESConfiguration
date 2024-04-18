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
        if ($PSCmdlet.ParameterSetName -eq "Unattended"){
            Write-Output "Skipping service account tests for unattend"
        }         
        else { 
            if  ($_ -match ".\\.")    {    
            $true
            }
            else {
                Throw "Please use the format Domain\Username for the NDES Service Account variable."
            }
        
            $EnteredDomain = $_.split("\")
            $ads = New-Object -ComObject ADSystemInfo
            $Domain = $ads.GetType().InvokeMember('DomainShortName','GetProperty', $Null, $ads, $Null)
        
                if ($EnteredDomain -like "$Domain") {
                    $true
                }
                else {            
                    Throw "Incorrect Domain. Ensure domain is '$($Domain)\<USERNAME>'" 
                }
       }
    })]  
[string]$NDESServiceAccount,

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
[switch]$SkipHTML
 
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

            Write-Host "Rule:        "  -ForegroundColor Gray -NoNewline
            Write-Host  $ResultBlob.RuleId  -ForegroundColor White
            Write-Host "Description: "  -ForegroundColor Gray -NoNewline
            Write-Host $ResultBlob.RuleDescription  -ForegroundColor White
            
            Write-Host "Result:      "  -ForegroundColor Gray -NoNewline
            switch($ResultBlob.CheckResult) {
                "Passed"
                {
                   Write-Host  $ResultBlob.CheckResult  -ForegroundColor Green
                }
                "Failed"
                { 
                    Write-Host $ResultBlob.CheckResult  -ForegroundColor Red  
                }
                "Warning"
                { 
                    Write-Host $ResultBlob.CheckResult  -ForegroundColor Yellow  
                }
            }

            Write-Host "Message:     " -ForegroundColor Gray -NoNewline
            Write-Host "$($ResultBlob.CheckResultMessage)`r`n" -ForegroundColor White
        
        }
       
       default {
         switch($Result){

            { ($_ -in ( "Passed", "1") )} {
                $ResultBlob | Write-Host -ForegroundColor Green
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
          if ( ($null -eq $LogName) -or ($LogName -eq "")) { Write-Error "Please set variable `$global`:LogName." }
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
        param($message)

        Write-Output "`r`n$line`r`n" 
        Write-Output $message 
        Write-Output ""

        New-LogEntry $message 1
 }


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

function Get-NDESHelp {

    Write-StatusMessage @'
    Verifies if the NDES server meets all the required configuration.
     
    The NDES server role is required as back-end infrastructure for Intune for delivering VPN and Wi-Fi certificates via the SCEP protocol to mobile devices and desktop clients.

    See https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure.
'@

    
} 

function Confirm-Variables {
    param (
        [string]$NDESServiceAccount,
        [string]$IssuingCAServerFQDN,
        [string]$SCEPUserCertTemplate
    )

    $line = "." * 60

    if ($PSCmdlet.ParameterSetName -eq "Unattended") {
        $MscepRaEku = '1.3.6.1.4.1.311.20.2.1' # CEP Encryption
        # Get cert authority from the Certificate Request Agent cert.
        $IssuingCAServerFQDN = Get-Item 'Cert:\LocalMachine\My\*' | Where-Object { ($_.EnhancedKeyUsageList  -match $MscepRaEku) -and ($_.Extensions.Format(1)[0].split('(')[0] -replace "template="  -match "CEPEncryption" ) }
        $SCEPUserCertTemplate = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP).EncryptionTemplate
        $confirmation = "y"
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
    }

    if ($confirmation -eq 'y') {
 
         Write-StatusMessage  @"
            Initializing log file $($TempDirPath)\Validate-NDESConfig.log
            NDESServiceAccount=$($NDESServiceAccount)
            IssuingCAServer=$($IssuingCAServerFQDN)
            SCEPCertificateTemplate=$($SCEPUserCertTemplate)
"@
    }
}

function Set-ServiceAccountisLocalSystem {
Param(
    [parameter(Mandatory=$true)]
    [bool]$isSvcAcctLclSystem
    )

    $Script:SvcAcctIsComputer = $isSvcAcctLclSystem
    New-LogEntry  "Service account is local system (computer) account = $isSvcAcctLclSystem" -Severity 1
    }
 
function Get-NDESServiceAcct {
    
    if (  ($null -eq $NDESServiceAccount) -or ($NDESServiceAccount -eq "")  ) {
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
            Write-Error "No certificate found in $CARegPath. Please resolve this issue and run the script again."
            New-LogEntry "No certificate found in $CARegPath. Please resolve this issue and run the script again."  -Severity 3

            break
        }
    }
    New-LogEntry  "Service Account detected = $NDESServiceAccount" -Severity 1
    $NDESServiceAccount

}

if ($help){
    Get-NDESHelp
    break
}

if ($usage){
    Show-Usage
    break
}

function Test-IsNDESInstalled {
        if (-not (Get-Service PFXCertificateConnectorSvc) ){    
        Write-Error "Error: NDES Not installed" 
        Write-Error "Exiting....................."
        New-LogEntry  "NDES Not installed" -Severity 3
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

    Write-Output "RSAT-AD-Tools-Feature is not installed. This Windows Feature is required to continue. This is a requirement for AD tests. Install now? [y/n]"
    New-LogEntry  "Prompt: RSAT-AD-Tools-Feature is not installed. This Windows Feature is required to continue. This is a requirement for AD tests. Install now?" 2
    $response = Read-Host -Prompt "[y/n]"
    New-LogEntry "User entered $response"

    if ( ($response).ToLower() -eq "y" ) {
        Install-WindowsFeature RSAT-AD-Tools-Feature | Out-Null
    }
    else { 
        break
    }
}
    
function Test-IsAADModuleInstalled {

    if (Get-Module ActiveDirectory -ListAvailable) {
        New-LogEntry "ActiveDirectory module is installed." 1
    }
    else {
        New-LogEntry "ActiveDirectory module is not installed. Please run this command to install it and re-run the script:`r`nInstall-Module ActiveDirectory" -Severity 3
        Write-Error "ActiveDirectory module is not installed. Please run this command to install it and re-run the script:`r`nInstall-Module ActiveDirectory"
        break
    }

}
function Test-IsIISInstalled {
    if (-not (Get-WindowsFeature Web-WebServer).Installed){

        $script:IISNotInstalled = $true
        Write-Warning "IIS is not installed. Some tests will not run as we're unable to import the WebAdministration module"
        Write-Output ""
        New-LogEntry  "IIS is not installed. Some tests will not run as we're unable to import the WebAdministration module"  -Severity 2
    
    }

    else {
        Import-Module WebAdministration | Out-Null
    }
}

function Test-OSVersion {
    Write-StatusMessage    "Checking Windows OS version..." 
  
    New-LogEntry  "Checking OS Version"  1

    $OSVersion = (Get-CimInstance -class Win32_OperatingSystem).Version
    $MinOSVersion = "6.3"

        if ([version]$OSVersion -lt [version]$MinOSVersion){
        
            Write-Output "Error: Unsupported OS Version. NDES requires Windows Server 2012 R2 and above." 
            New-LogEntry  "Unsupported OS Version. NDES requires Windows Server 2012 R2 and above." -Severity 3
            
            } 
        
        else {
        
            Write-Output "Success: " 
            Write-Output "OS Version: $OSVersion is supported."
            New-LogEntry  "Server is version $($OSVersion)" -Severity 1
        
        }
}

function Test-IEEnhancedSecurityMode {
    #   Checking if IE Enhanced Security Configuration is Deactivated
    Write-StatusMessage "Checking Internet Explorer Enhanced Security Configuration settings"  
 

    # Check for the current state of Enhanced  Security Configuration; 0 = not configured
    $escState = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
 
    if ($escState.IsInstalled -eq 0) {
        Write-Output "Enhanced Security Configuration is not configured."  
        New-LogEntry "Enhanced Security Configuration is not configured." 1
    } else {
        Write-Error "Enhanced Security Configuration is configured."  
        New-LogEntry "Enhanced Security Configuration is configured."  3
    }
}

function Test-PFXCertificateConnector {
    Write-Output "Checking the `"Log on As`" for PFX Certificate Connector for Intune"  
    $service = Get-Service -Name "PFXCertificateConnectorSvc"

    if ($service) {
        # Get the service's process
        $serviceProcess = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $service.Name }

        # Check if the service is running as Local System or as a specific user
        if ($serviceProcess.StartName -eq "LocalSystem") {
            Write-Output "$($service.Name) is running as Local System"  
        } else {
            Write-Output "$($service.Name) is running as $($serviceProcess.StartName)"  
        }
    } else {
        Write-Error "PFXCertificateConnectorSvc service not found"  
    }
}

function Test-Connectivity {
    param(
        # parameters here
    )
    # function code here
}

function Test-Variables {
    if ($PSCmdlet.ParameterSetName -eq "Unattended") {
        $MscepRaEku = '1.3.6.1.4.1.311.20.2.1' # CEP Encryption
        # Get cert authority from the Certificate Request Agent cert.
        $IssuingCAServerFQDN = Get-Item 'Cert:\LocalMachine\My\*' | Where-Object { ($_.EnhancedKeyUsageList  -match $MscepRaEku) -and ($_.Extensions.Format(1)[0].split('(')[0] -replace "template="  -match "CEPEncryption" ) }
         
        $SCEPUserCertTemplate = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP).EncryptionTemplate
        $confirmation = "y"
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
    }
}

function Initialize-LogFile {
    Write-Output ""
    Write-Output $line
    New-LogEntry  "Initializing log file $($TempDirPath)\Validate-NDESConfig.log"  -Severity 1
    New-LogEntry  "Proceeding with variables=YES"  -Severity 1
    New-LogEntry  "NDESServiceAccount=$($NDESServiceAccount)" -Severity 1
    New-LogEntry  "IssuingCAServer=$($IssuingCAServerFQDN)" -Severity 1
    New-LogEntry  "SCEPCertificateTemplate=$($SCEPUserCertTemplate)" -Severity 1
}

function Test-InstallRSATTools {
    Test-IsNDESInstalled

    if ( -not ( Test-IsRSATADInstalled) ){
        Install-RSATAD
    }

    Test-IsAADModuleInstalled
    Test-IsIISInstalled
    Test-OSVersion
    Test-IEEnhancedSecurityMode
    Test-NDESServiceAccountProperties -NDESServiceAccount $NDESServiceAccount
    Get-EventLogData
}

function Test-WindowsFeaturesInstalled {
    param (
        [string]$LogFilePath
    )

    Write-StatusMessage "Checking Windows Features are installed..." 
    New-LogEntry "Checking Windows Features are installed..." -Severity 1  

    $WindowsFeatures = @("Web-Filtering","Web-Net-Ext45","NET-Framework-45-Core","NET-WCF-HTTP-Activation45","Web-Metabase","Web-WMI")

    foreach($WindowsFeature in $WindowsFeatures){
        $Feature = Get-WindowsFeature $WindowsFeature
        $FeatureDisplayName = $Feature.displayName

        if($Feature.installed){
            Write-Output "Success:" 
            Write-Output "$FeatureDisplayName Feature Installed"
            New-LogEntry "$($FeatureDisplayName) Feature Installed" -Severity 1  
        }
        else {
            Write-Output "Error: $FeatureDisplayName Feature not installed!"  
            New-LogEntry "$($FeatureDisplayName) Feature not installed!" -Severity 3  
        }
    }
} 

function Test-IISApplicationPoolHealth {
    Write-StatusMessage "Checking IIS Application Pool health..."  
    New-LogEntry  "Checking IIS Application Pool health" -Severity 1
    
        if (-not ($IISNotInstalled -eq $true)){
    
            # If SCEP AppPool Exists    
            if (Test-Path 'IIS:\AppPools\SCEP'){
    
            $IISSCEPAppPoolAccount = Get-Item 'IIS:\AppPools\SCEP' | Select-Object -expandproperty processmodel | Select-Object -Expand username
                
                if ((Get-WebAppPoolState "SCEP").value -match "Started"){            
                    $SCEPAppPoolRunning = $true            
                }
            }
    
            else {
    
                Write-Output "Error: SCEP Application Pool missing!"  
                Write-Output 'Please review "Step 3.1 - Configure prerequisites on the NDES server"'. 
                Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure" 
                New-LogEntry  "SCEP Application Pool missing"  -Severity 3
            
            }
        
            if ($SvcAcctIsComputer) {
                Write-Output ""
                Write-Output $line
                Write-Output ""
                Write-Output "Skipping application pool account check since local system is used as the service account..." 
                Write-Output ""
                New-LogEntry  "Skipping application pool account check since local system is used as the service account" -Severity 1 
            }
            else {
                if ($IISSCEPAppPoolAccount -contains "$NDESServiceAccount"){
                
                Write-Output "Success: " 
                Write-Output "Application Pool is configured to use "
                Write-Output "$($IISSCEPAppPoolAccount)"
                New-LogEntry  "Application Pool is configured to use $($IISSCEPAppPoolAccount)"  -Severity 1
                
                }
                
                else {
    
                Write-Output "Error: Application Pool is not configured to use the NDES Service Account"  
                Write-Output 'Please review "Step 4.1 - Configure NDES for use with Intune".' 
                Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure" 
                New-LogEntry  "Application Pool is not configured to use the NDES Service Account"  -Severity 3
                
                }
            }
                    
            if ($SCEPAppPoolRunning){
                    
                Write-Output "Success: " 
                Write-Output "SCEP Application Pool is Started "
                New-LogEntry  "SCEP Application Pool is Started"  -Severity 1
                    
            }
                    
            else {
    
                Write-Output "Error: SCEP Application Pool is stopped!"  
                Write-Output "Please start the SCEP Application Pool via IIS Management Console. You should also review the Application Event log output for errors"
                New-LogEntry  "SCEP Application Pool is stopped"  -Severity 3
                    
            }
    
        }
    
        else {
    
            Write-Output "IIS is not installed." 
            New-LogEntry  "IIS is not installed"  -Severity 3 
    
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

        Write-StatusMessage "Success:`r`nCorrect CSP used in install parameters"
         
        Write-Output $InstallParams.Message
        New-LogEntry "Correct CSP used in install parameters:" -Severity 1
        New-LogEntry "$($InstallParams.Message)" NDES_Eventvwr 1

    }
    else {

        Write-StatusMessage "Error: Incorrect CSP selected during install. NDES only supports the CryptoAPI CSP."          
        Write-Output $InstallParams.Message

        New-LogEntry "Error: Incorrect CSP selected during install. NDES only supports the CryptoAPI CSP" -Severity 3 
        New-LogEntry "$($InstallParams.Message)" NDES_Eventvwr 3
    }

    $ErrorActionPreference = "Continue"
}

function Test-HTTPParamsRegKeys {
    param ()

    Write-StatusMessage "Checking registry HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters has been set to allow long URLs..."
    New-LogEntry "Checking registry (HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters) has been set to allow long URLs" -Severity 1

    if (-not ($IISNotInstalled -eq $true)) {
        $MaxFieldLength = (Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxFieldLength).MaxfieldLength
        $MaxRequestBytes = (Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxRequestBytes).MaxRequestBytes

        if ($MaxFieldLength -notmatch "65534") {
            Write-Output "Error: MaxFieldLength not set to 65534 in the registry!"
            Write-Output ""
            Write-Output 'Please review "Step 4.3 - Configure NDES for use with Intune".'
            Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            New-LogEntry "MaxFieldLength not set to 65534 in the registry" -Severity 3
        } else {
            Write-Output "Success: "
            Write-Output "MaxFieldLength set correctly"
            New-LogEntry "MaxFieldLength set correctly" -Severity 1
        }

        if ($MaxRequestBytes -notmatch "65534") {
            Write-Output "MaxRequestBytes not set to 65534 in the registry!"
            Write-Output ""
            Write-Output 'Please review "Step 4.3 - Configure NDES for use with Intune".'
            Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure'"
            New-LogEntry "MaxRequestBytes not set to 65534 in the registry" -Severity 3
        } else {
            Write-Output "Success: "
            Write-Output "MaxRequestBytes set correctly"
            New-LogEntry "MaxRequestBytes set correctly" -Severity 1
        }
    } else {
        Write-Error "IIS is not installed."
        New-LogEntry "IIS is not installed." -Severity 3
    }
}
 
function Test-SPN {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ADAccount
    )

    Write-StatusMessage "Checking SPN has been set..." 
    New-LogEntry "Checking SPN has been set" -Severity 1

    $hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname

    $spn = setspn.exe -L $ADAccount

    if ($spn -match $hostname){
        Write-Output "Success: " 
        Write-Output "Correct SPN set for the NDES service account:"
        Write-Output ""
        Write-Output $spn 
        New-LogEntry "Correct SPN set for the NDES service account: $($spn)" -Severity 1
    }
    else {
        Write-Output "Error: Missing or Incorrect SPN set for the NDES Service Account!"  
        Write-Output 'Please review "Step 3.1c - Configure prerequisites on the NDES server".'
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        New-LogEntry "Missing or Incorrect SPN set for the NDES Service Account" -Severity 3 
    }
}
 
function Test-IntermediateCerts {
    param ()

    Write-StatusMessage "Checking there are no intermediate certs are in the Trusted Root store..."  
    New-LogEntry "Checking there are no intermediate certs are in the Trusted Root store" -Severity 1

    $IntermediateCertCheck = Get-Childitem cert:\LocalMachine\root -Recurse | Where-Object {$_.Issuer -ne $_.Subject}

    if ($IntermediateCertCheck){
        Write-Output "Error: Intermediate certificate found in the Trusted Root store. This can cause undesired effects and should be removed."  
        Write-Output "Certificates:"
        Write-Output ""
        Write-Output $IntermediateCertCheck
        New-LogEntry "Intermediate certificate found in the Trusted Root store: $($IntermediateCertCheck)" -Severity 3
    }
    else {
        Write-Output "Success: " 
        Write-Output "Trusted Root store does not contain any Intermediate certificates."
        New-LogEntry "Trusted Root store does not contain any Intermediate certificates." -Severity 1
    }
} 

function Test-Certificates {
    param ()

    # Set ErrorActionPreference to SilentlyContinue
    $ErrorActionPreference = "Silentlycontinue"

    Write-StatusMessage "Checking the EnrollmentAgentOffline and CEPEncryption are present..."  
    New-LogEntry "Checking the EnrollmentAgentOffline and CEPEncryption are present" -Severity 1

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
        Write-Output "Success: EnrollmentAgentOffline certificate is present"
        New-LogEntry "EnrollmentAgentOffline certificate is present" -Severity 1
    }
    else {
        Write-Output "Error: EnrollmentAgentOffline certificate is not present!"
        Write-Output "This can occur when an account without Enterprise Admin permissions installs NDES. You may need to remove the NDES role and reinstall with the correct permissions." 
        Write-Output 'Please review "Step 3.1 - Configure prerequisites on the NDES server".' 
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        New-LogEntry "EnrollmentAgentOffline certificate is not present" -Severity 3 
    }
    
    # Check if CEPEncryption certificate is present
    if ($CEPEncryption) {
        Write-Output "Success: CEPEncryption certificate is present"
        New-LogEntry "CEPEncryption certificate is present" -Severity 1
    }
    else {
        Write-Output "Error: CEPEncryption certificate is not present!"
        Write-Output "This can occur when an account without Enterprise Admin permissions installs NDES. You may need to remove the NDES role and reinstall with the correct permissions." 
        Write-Output 'Please review "Step 3.1 - Configure prerequisites on the NDES server".' 
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        New-LogEntry "CEPEncryption certificate is not present" -Severity 3
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
        Write-Output "Error: Registry key does not exist. This can occur if the NDES role has been installed but not configured."
        Write-Output 'Please review "Step 3 - Configure prerequisites on the NDES server".'
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        New-LogEntry "MSCEP Registry key does not exist." -Severity 3
    }
    else {
        $SignatureTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name SignatureTemplate).SignatureTemplate
        $EncryptionTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name EncryptionTemplate).EncryptionTemplate
        $GeneralPurposeTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name GeneralPurposeTemplate).GeneralPurposeTemplate
        $DefaultUsageTemplate = "IPSECIntermediateOffline"

        if ($SignatureTemplate -match $DefaultUsageTemplate -and $EncryptionTemplate -match $DefaultUsageTemplate -and $GeneralPurposeTemplate -match $DefaultUsageTemplate) {
            Write-Output "Error: Registry has not been configured with the SCEP Certificate template name. Default values have _not_ been changed."
            Write-Output 'Please review "Step 3.1 - Configure prerequisites on the NDES server".'
            Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            Write-Output ""
            New-LogEntry "Registry has not been configured with the SCEP Certificate template name. Default values have _not_ been changed." -Severity 3
        }
        else {
            Write-Output "One or more default values have been changed."
            Write-Output ""
            Write-Output "Checking SignatureTemplate key..."
            Write-Output ""
            if ($SignatureTemplate -match $SCEPUserCertTemplate) {
                Write-Output "Success: "
                Write-Output "SCEP certificate template '$($SCEPUserCertTemplate)' has been written to the registry under the _SignatureTemplate_ key. Ensure this aligns with the usage specified on the SCEP template."
                Write-Output ""
                New-LogEntry "SCEP certificate template $($SCEPUserCertTemplate)' has been written to the registry under the _SignatureTemplate_ key" -Severity 1
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
                New-LogEntry "SignatureTemplate key does not match the SCEP certificate template name.Registry value=$($SignatureTemplate)|SCEP certificate template value=$($SCEPUserCertTemplate)" -Severity 2
            }

            Write-StatusMessage "Checking EncryptionTemplate key..."
            if ($EncryptionTemplate -match $SCEPUserCertTemplate) {
                Write-Output "Success: "
                Write-Output "SCEP certificate template '$($SCEPUserCertTemplate)' has been written to the registry under the _EncryptionTemplate_ key. Ensure this aligns with the usage specified on the SCEP template."
                Write-Output ""
                New-LogEntry "SCEP certificate template $($SCEPUserCertTemplate) has been written to the registry under the _EncryptionTemplate_ key" -Severity 1
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
                New-LogEntry "EncryptionTemplate key does not match the SCEP certificate template name.Registry value=$($EncryptionTemplate)|SCEP certificate template value=$($SCEPUserCertTemplate)" -Severity 2
            }

            Write-Output $line
            Write-Output ""
            Write-Output "Checking GeneralPurposeTemplate key..."
            Write-Output ""
            if ($GeneralPurposeTemplate -match $SCEPUserCertTemplate) {
                Write-Output "Success: "
                Write-Output "SCEP certificate template '$($SCEPUserCertTemplate)' has been written to the registry under the _GeneralPurposeTemplate_ key. Ensure this aligns with the usage specified on the SCEP template"
                New-LogEntry "SCEP certificate template $($SCEPUserCertTemplate) has been written to the registry under the _GeneralPurposeTemplate_ key" -Severity 1
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
                New-LogEntry "GeneralPurposeTemplate key does not match the SCEP certificate template name.Registry value=$($GeneralPurposeTemplate)|SCEP certificate template value=$($SCEPUserCertTemplate)" -Severity 2
            }
        }
    }

    $ErrorActionPreference = "Continue"
}

function Test-ServerCertificate {
    Write-StatusMessage "Checking IIS SSL certificate is valid for use..."
    New-LogEntry "Checking IIS SSL certificate is valid for use" -Severity 1

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
        New-LogEntry "Certificate bound in IIS is valid. Subject:$($ServerCertObject.Subject)|Thumbprint:$($ServerCertObject.Thumbprint)|ValidUntil:$($ServerCertObject.NotAfter)|Internal and ExternalHostnames:$($DNSNameList)" -Severity 1
    } else {
        Write-Output "Error: The certificate bound in IIS is not valid for use. Reason:"
        Write-Output ""

        if ($ServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU) {
            $EKUValid = $true
        } else {
            $EKUValid = $false

            Write-Output "Correct EKU: "
            Write-Output "$($EKUValid)"
            Write-Output ""
        }

        if ($ServerCertObject.Subject -match $hostname) {
            $SubjectValid = $true
        } else {
            $SubjectValid = $false

            Write-Output "Correct Subject: "
            Write-Output "$($SubjectValid)"
            Write-Output ""
        }

        if ($SelfSigned -eq $false) {
            Out-Null
        } else {
            Write-Output "Is Self-Signed: "
            Write-Output "$($SelfSigned)"
            Write-Output ""
        }

        Write-Output 'Please review "Step 4 - Configure NDES for use with Intune>To Install and bind certificates on the NDES Server".'
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        New-LogEntry "The certificate bound in IIS is not valid for use. CorrectEKU=$($EKUValid)|CorrectSubject=$($SubjectValid)|IsSelfSigned=$($SelfSigned)" -Severity 3
    }
}

function Test-ClientCertificate {
    Write-Output ""
    Write-Output $line
    Write-Output ""
    Write-Output "Checking encrypting certificate is valid for use..." 
    Write-Output ""
    New-LogEntry "Checking encrypting certificate is valid for use..." -Severity 1

    $hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
    $clientAuthEku = "1.3.6.1.5.5.7.3.2" # Client Authentication
    $NDESCertThumbprint = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector -Name EncryptionCertThumbprint).EncryptionCertThumbprint
    $ClientCertObject = Get-ChildItem Cert:\LocalMachine\My\$NDESCertThumbprint

    if ($ClientCertObject.Issuer -match $ClientCertObject.Subject) {
        $ClientCertSelfSigned = $true
    } else {
        $ClientCertSelfSigned = $false
    }

    if ($ClientCertObject.EnhancedKeyUsageList -match $clientAuthEku -and $ClientCertObject.Issuer -notmatch $ClientCertObject.Subject) {
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
        New-LogEntry "Client certificate bound to NDES Connector is valid. Subject:$($ClientCertObject.Subject)|Thumbprint:$($ClientCertObject.Thumbprint)|ValidUntil:$($ClientCertObject.NotAfter)" -Severity 1
    } else {
        Write-Error "Error: The certificate bound to the NDES Connector is not valid for use. Reason:"  
        
        if ($ClientCertObject.EnhancedKeyUsageList -match $clientAuthEku) {                
            $ClientCertEKUValid = $true
        } else {                
            $ClientCertEKUValid = $false

            Write-Output "Correct EKU: "
            Write-Output "$($ClientCertEKUValid)" 
            Write-Output ""
        }

        if ($ClientCertSelfSigned -eq $false) {               
            New-LogEntry "ClientCertSelfSigned = $ClientCertSelfSigned" -Severity 3              
        } else {
            Write-Output "Is Self-Signed: "
            Write-Output "$($ClientCertSelfSigned)" 
            Write-Output ""
        }

        Write-Output 'Please review "Step 4 - Configure NDES for use with Intune>To Install and bind certificates on the NDES Server".'
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        New-LogEntry "The certificate bound to the NDES Connector is not valid for use. CorrectEKU=$ClientCertEKUValid IsSelfSigned=$ClientCertSelfSigned" -Severity 3
    }
}
 
function Test-InternalNdesUrl {
    Write-Output ""
    Write-Output $line
    $hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
    Write-Output ""
    Write-Output "Checking behaviour of internal NDES URL: " 
    Write-Output "https://$hostname/certsrv/mscep/mscep.dll" 
    Write-Output ""
    New-LogEntry "Checking behaviour of internal NDES URL" -Severity 1
    New-LogEntry "Https://$hostname/certsrv/mscep/mscep.dll" -Severity 1

    $Statuscode = try {
        (Invoke-WebRequest -Uri "https://$hostname/certsrv/mscep/mscep.dll").StatusCode
    } catch {
        $_.Exception.Response.StatusCode.Value__
    }

    if ($statuscode -eq "200") {
        Write-Output "Error: https://$hostname/certsrv/mscep/mscep.dll returns 200 OK. This usually signifies an error with the Intune Connector registering itself or not being installed." 
        New-LogEntry "https://$hostname/certsrv/mscep/mscep.dll returns 200 OK. This usually signifies an error with the Intune Connector registering itself or the service is not installed" -Severity 3
    } elseif ($statuscode -eq "403") {
        Write-Output "Trying to retrieve CA Capabilities..." 
        Write-Output ""
        try {
            $Newstatuscode = (Invoke-WebRequest -Uri "https://$hostname/certsrv/mscep/mscep.dll?operation=GetCACaps`&message=test").StatusCode
        } catch {
            $_.Exception.Response.StatusCode.Value__
        }

        if ($Newstatuscode -eq "200") {
            $CACaps = (Invoke-WebRequest -Uri "https://$hostname/certsrv/mscep?operation=GetCACaps`&message=test").Content
        }

        if ($CACaps) {
            Write-Output "Success: " 
            Write-Output "CA Capabilities retrieved:"
            Write-Output ""
            Write-Output $CACaps
            New-LogEntry "CA Capabilities retrieved:$CACaps" -Severity 1
        }
    } else {
        Write-Output "Error: Unexpected Error code! This usually signifies an error with the Intune Connector registering itself or not being installed" 
        Write-Output "Expected value is a 403. We received a $($Statuscode). This could be down to a missing reboot post policy module install. Verify last boot time and module install time further down the validation."
        New-LogEntry  "Unexpected Error code. Expected: 403 | Received: $Statuscode"  -Severity 3
    }
   }
        
#endregion

function Test-LastBootTime {
    Write-Output ""
    Write-Output $line
    Write-Output ""
    Write-Output "Checking Server's last boot time..." 
    Write-Output ""
    New-LogEntry "Checking last boot time of the server" -Severity 1

    $LastBoot = (Get-WmiObject win32_operatingsystem | Select-Object csname, @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}).lastbootuptime

    Write-StatusMessage @"
Server last rebooted: $LastBoot
Please ensure a reboot has taken place _after_ all registry changes and installing the NDES Connector. IISRESET is _not_ sufficient.
"@  

    New-LogEntry "LastBootTime: $LastBoot" -Severity 1
}

function Test-IntuneConnectorInstall {
    Write-StatusMessage "Checking if Intune Connector is installed..."
    New-LogEntry "Checking Intune Connector is installed" -Severity 1

    if ($IntuneConnector = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object {$_.DisplayName -eq "Certificate Connector for Microsoft Intune"}) {
        $installDate = [datetime]::ParseExact($IntuneConnector.InstallDate, 'yyyymmdd', $null).ToString('dd-mm-yyyy')
        Write-Output "Success: $($IntuneConnector.DisplayName) was installed on $installDate and is version $($IntuneConnector.DisplayVersion)"
        Write-Output ""
        New-LogEntry "ConnectorVersion: $IntuneConnector" -Severity 1
    } else {
        Write-Output "Error: Intune Connector not installed"
        Write-Output 'Please review "Step 5 - Enable, install, and configure the Intune certificate connector".'
        Write-Output "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Write-Output ""
        New-LogEntry "ConnectorNotInstalled" -Severity 3
    }
}

function Test-IntuneConnectorRegKeys {
    Write-Output ""
    Write-Output $line
    Write-Output ""
    Write-Output "Checking Intune Connector registry keys are intact" 
    Write-Output ""
    New-LogEntry "Checking Intune Connector registry keys are intact" -Severity 1
    $ErrorActionPreference = "SilentlyContinue"

    $KeyRecoveryAgentCertificate = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\KeyRecoveryAgentCertificate"
    $PfxSigningCertificate = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\PfxSigningCertificate"
    $SigningCertificate = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\SigningCertificate"

    if (-not (Test-Path $KeyRecoveryAgentCertificate)) {
        Write-Output "Error: KeyRecoveryAgentCertificate Registry key does not exist." 
        Write-Output ""
        New-LogEntry "KeyRecoveryAgentCertificate Registry key does not exist." -Severity 3 
    }
    else {
        $KeyRecoveryAgentCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name KeyRecoveryAgentCertificate).KeyRecoveryAgentCertificate

        if (-not ($KeyRecoveryAgentCertificatePresent)) {
            Write-Warning "KeyRecoveryAgentCertificate registry key exists but has no value"
            New-LogEntry "KeyRecoveryAgentCertificate missing value" -Severity 2
        }
        else {
            Write-Output "Success: " 
            Write-Output "KeyRecoveryAgentCertificate registry key exists"
            New-LogEntry "KeyRecoveryAgentCertificate registry key exists" -Severity 1
        }
    }

    if (-not (Test-Path $PfxSigningCertificate)) {
        Write-Output "Error: PfxSigningCertificate Registry key does not exist." 
        Write-Output ""
        New-LogEntry "PfxSigningCertificate Registry key does not exist." -Severity 3 
    }
    else {
        $PfxSigningCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name PfxSigningCertificate).PfxSigningCertificate

        if (-not ($PfxSigningCertificatePresent)) {
            Write-Warning "PfxSigningCertificate registry key exists but has no value"
            New-LogEntry "PfxSigningCertificate missing Value" -Severity 2
        }
        else {
            Write-Output "Success: " 
            Write-Output "PfxSigningCertificate registry keys exists"
            New-LogEntry "PfxSigningCertificate registry key exists" -Severity 1
        }
    }

    if (-not (Test-Path $SigningCertificate)) {
        Write-Output "Error: SigningCertificate Registry key does not exist." 
        Write-Output ""
        New-LogEntry "SigningCertificate Registry key does not exist" -Severity 3  
    }
    else {
        $SigningCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name SigningCertificate).SigningCertificate

        if (-not ($SigningCertificatePresent)) {
            Write-Warning "SigningCertificate registry key exists but has no value"
            New-LogEntry "SigningCertificate registry key exists but has no value" -Severity 2
        }
        else {
            Write-Output "Success: " 
            Write-Output "SigningCertificate registry key exists"
            New-LogEntry "SigningCertificate registry key exists" -Severity 1
        }
    }

    $ErrorActionPreference = "Continue"
}

function Get-EventLogData {
    param (
        [int]$EventLogCollDays = 5
    )

    $ErrorActionPreference = "SilentlyContinue"

    Write-Output ""
    Write-Output $line
    Write-Output ""
    Write-Output "Checking Event logs for pertinent errors..." 
    Write-Output ""
    New-LogEntry "Checking Event logs for pertinent errors" -Severity 1

    if (-not (Get-EventLog -LogName "Microsoft Intune Connector" -EntryType Error -After (Get-Date).AddDays(-$EventLogCollDays) -ErrorAction SilentlyContinue)) {
        Write-Output "Success: " 
        Write-Output "No errors found in the Microsoft Intune Connector"
        Write-Output ""
        New-LogEntry "No errors found in the Microsoft Intune Connector" -Severity 1
    }
    else {
        Write-Warning "Errors found in the Microsoft Intune Connector Event log. Please see below for the most recent 5, and investigate further in Event Viewer."
        Write-Output ""
        $EventsCol1 = Get-EventLog -LogName "Microsoft Intune Connector" -EntryType Error -After (Get-Date).AddDays(-$EventLogCollDays) -Newest 5 | Select-Object TimeGenerated, Source, Message
        $EventsCol1 | Format-List
        New-LogEntry "Errors found in the Microsoft Intune Connector Event log" NDES_Eventvwr 3
        $i = 0
        $count = @($EventsCol1).Count

        foreach ($item in $EventsCol1) {
            New-LogEntry "$($EventsCol1[$i].TimeGenerated);$($EventsCol1[$i].Message);$($EventsCol1[$i].Source)" NDES_Eventvwr 3
            $i++
        }
    }

    if (-not (Get-EventLog -LogName "Application" -EntryType Error -Source NDESConnector, Microsoft-Windows-NetworkDeviceEnrollmentService -After (Get-Date).AddDays(-$EventLogCollDays) -ErrorAction SilentlyContinue)) {
        Write-Output "Success: " 
        Write-Output "No errors found in the Application log from source NetworkDeviceEnrollmentService or NDESConnector"
        New-LogEntry "No errors found in the Application log from source NetworkDeviceEnrollmentService or NDESConnector" -Severity 1
    }
    else {
        Write-Warning "Errors found in the Application Event log for source NetworkDeviceEnrollmentService or NDESConnector. Please see below for the most recent 5, and investigate further in Event Viewer."
        Write-Output ""
        $EventsCol2 = Get-EventLog -LogName "Application" -EntryType Error -Source NDESConnector, Microsoft-Windows-NetworkDeviceEnrollmentService -After (Get-Date).AddDays(-$EventLogCollDays) -Newest 5 | Select-Object TimeGenerated, Source, Message
        $EventsCol2 | Format-List
        $i = 0
        $count = @($EventsCol2).Count

        foreach ($item in $EventsCol2) {
            New-LogEntry "$($EventsCol2[$i].TimeGenerated);$($EventsCol2[$i].Message);$($EventsCol2[$i].Source)" NDES_Eventvwr 3
            $i++
        }
    }

    $ErrorActionPreference = "Continue"
}

function Test-Connectivity {
    param(
        [string]$uniqueURL = "autoupdate.msappproxy.net",
        [int]$port = 443
    )

    Write-StatusMessage "Checking Connectivity to $uniqueURL" 

    try {
        $error.Clear()
        $connectionTest = $false

        $connection = New-Object System.Net.Sockets.TCPClient
        $connection.ReceiveTimeout = 500
        $connection.SendTimeout = 500 
        $result = $connection.BeginConnect($uniqueURL, $port, $null, $null)
        $wait = $result.AsyncWaitHandle.WaitOne(5000, $false)

        if ($wait -and !$connection.Client.Connected) {
            $connection.Close()
            $connectionTest = $false
        } elseif (!$wait) {
            $connection.Close()
            $connectionTest = $false
        } else {
            $connection.EndConnect($result) | Out-Null
            $connectionTest = $connection.Connected
        }
        
        if ($connectionTest) {
            Write-Output "Connection to $uniqueURL on port $port is successful."  
        } else {
            Write-Error "Connection to $uniqueURL on port $port failed."  
        }
    }
    catch {
        Write-Error "Error connecting to $uniqueURL. Please test that the service account has internet access."
        New-LogEntry "Unable to connect to $uniqueURL."
    }
} 

function Test-NDESServiceAccountProperties {
    param (
        [string]$NDESServiceAccount
    )

    Write-StatusMessage "Checking NDES Service Account properties in Active Directory..." 
    New-LogEntry "Checking NDES Service Account properties in Active Directory" -Severity 1

    $ADAccount = $NDESServiceAccount.split("\")[1]
    if ($SvcAcctIsComputer) {
        $ADAccountProps = Get-ADComputer $ADAccount -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut
    }
    else {
        $ADAccountProps = Get-ADUser $ADAccount -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut
    }

    if ($ADAccountProps.enabled -ne $true -OR $ADAccountProps.PasswordExpired -ne $false -OR $ADAccountProps.LockedOut -eq $true) {
        Write-StatusMessage "Error: Problem with the AD account. Please see output below to determine the issue"       
        New-LogEntry "Problem with the AD account. Please see output below to determine the issue" -Severity 3
    }
    else {
        Write-StatusMessage "Success:`r`nNDES Service Account seems to be in working order:"
        New-LogEntry "NDES Service Account seems to be in working order" -Severity 1
    }

    $msg = $ADAccountProps | Format-List SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut
    $msg
    New-LogEntry "$msg" -Severity 1
} 

function Test-NDESServiceAccountLocalPermissions {
    Write-StatusMessage "Checking NDES Service Account local permissions..." 
    New-LogEntry "Checking NDES Service Account local permissions" -Severity 1 

    if ($SvcAcctIsComputer) { 
        Write-StatusMessage "Skipping NDES Service Account local permissions since local system is used as the service account..." 
        New-LogEntry "Skipping NDES Service Account local permissions since local system is used as the service account" -Severity 1 
    }
    else {
        if ((net localgroup) -match "Administrators"){
            $LocalAdminsMember = ((net localgroup Administrators))

            if ($LocalAdminsMember -like "*$NDESServiceAccount*"){
                Write-Warning "NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use the IIS_IUSERS local group instead."
                New-LogEntry "NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use IIS_IUSERS instead." -Severity 2
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

    Write-StatusMessage "Checking Connectivity to $uniqueURL" 

    try {
        $error.Clear()
        $connectionTest = $false

        $connection = New-Object System.Net.Sockets.TCPClient
        $connection.ReceiveTimeout = 500
        $connection.SendTimeout = 500 
        $result = $connection.BeginConnect($uniqueURL, $port, $null, $null)
        $wait = $result.AsyncWaitHandle.WaitOne(5000, $false)

        if ($wait -and !$connection.Client.Connected) {
            $connection.Close()
            $connectionTest = $false
        } elseif (!$wait) {
            $connection.Close()
            $connectionTest = $false
        } else {
            $connection.EndConnect($result) | Out-Null
            $connectionTest = $connection.Connected
        }
        
        if ($connectionTest) {
            Write-Output "Connection to $uniqueURL on port $port is successful."  
        } else {
            Write-Error "Connection to $uniqueURL on port $port failed."  
        }
    }
    catch {
        Write-Error "Error connecting to $uniqueURL. Please test that the service account has internet access."
        New-LogEntry "Unable to connect to $uniqueURL."
    }
} 

function Test-NDESServiceAccountProperties {
    param (
        [string]$NDESServiceAccount
    )

    Write-StatusMessage "Checking NDES Service Account properties in Active Directory..." 
    New-LogEntry "Checking NDES Service Account properties in Active Directory" -Severity 1

    $ADAccount = $NDESServiceAccount.split("\")[1]
    if ($SvcAcctIsComputer) {
        $ADAccountProps = Get-ADComputer $ADAccount -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut
    }
    else {
        $ADAccountProps = Get-ADUser $ADAccount -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut
    }

    if ($ADAccountProps.enabled -ne $true -OR $ADAccountProps.PasswordExpired -ne $false -OR $ADAccountProps.LockedOut -eq $true) {
        Write-StatusMessage "Error: Problem with the AD account. Please see output below to determine the issue"       
        New-LogEntry "Problem with the AD account. Please see output below to determine the issue" -Severity 3
    }
    else {
        Write-StatusMessage "Success:`r`nNDES Service Account seems to be in working order:"
        New-LogEntry "NDES Service Account seems to be in working order" -Severity 1
    }

    $msg = $ADAccountProps | Format-List SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut
    $msg
    New-LogEntry "$msg" -Severity 1
} 
function Test-Connectivity {
    param(
        [string]$uniqueURL = "autoupdate.msappproxy.net",
        [int]$port = 443
    )

    Write-StatusMessage "Checking Connectivity to $uniqueURL" 

    try {
        $error.Clear()
        $connectionTest = $false

        $connection = New-Object System.Net.Sockets.TCPClient
        $connection.ReceiveTimeout = 500
        $connection.SendTimeout = 500 
        $result = $connection.BeginConnect($uniqueURL, $port, $null, $null)
        $wait = $result.AsyncWaitHandle.WaitOne(5000, $false)

        if ($wait -and !$connection.Client.Connected) {
            $connection.Close()
            $connectionTest = $false
        } elseif (!$wait) {
            $connection.Close()
            $connectionTest = $false
        } else {
            $connection.EndConnect($result) | Out-Null
            $connectionTest = $connection.Connected
        }
        
        if ($connectionTest) {
            Write-Output "Connection to $uniqueURL on port $port is successful."  
        } else {
            Write-Error "Connection to $uniqueURL on port $port failed."  
        }
    }
    catch {
        Write-Error "Error connecting to $uniqueURL. Please test that the service account has internet access."
        New-LogEntry "Unable to connect to $uniqueURL."
    }
} 

function Test-NDESServiceAccountProperties {
    param (
        [string]$NDESServiceAccount
    )

    Write-StatusMessage "Checking NDES Service Account properties in Active Directory..." 
    New-LogEntry "Checking NDES Service Account properties in Active Directory" -Severity 1

    $ADAccount = $NDESServiceAccount.split("\")[1]
    if ($SvcAcctIsComputer) {
        $ADAccountProps = Get-ADComputer $ADAccount -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut
    }
    else {
        $ADAccountProps = Get-ADUser $ADAccount -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut
    }

    if ($ADAccountProps.enabled -ne $true -OR $ADAccountProps.PasswordExpired -ne $false -OR $ADAccountProps.LockedOut -eq $true) {
        Write-StatusMessage "Error: Problem with the AD account. Please see output below to determine the issue"       
        New-LogEntry "Problem with the AD account. Please see output below to determine the issue" -Severity 3
    }
    else {
        Write-StatusMessage "Success:`r`nNDES Service Account seems to be in working order:"
        New-LogEntry "NDES Service Account seems to be in working order" -Severity 1
    }

    $msg = $ADAccountProps | Format-List SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut
    $msg
    New-LogEntry "$msg" -Severity 1
}

function Test-NDESServiceAccountLocalPermissions {
    Write-StatusMessage "Checking NDES Service Account local permissions..." 
    New-LogEntry  "Checking NDES Service Account local permissions" -Severity 1 
    if ($SvcAcctIsComputer) { 
        Write-StatusMessage "Skipping NDES Service Account local permissions since local system is used as the service account..." 
        New-LogEntry  "Skipping NDES Service Account local permissions since local system is used as the service account" -Severity 1 
    }
    else {
        if ((net localgroup) -match "Administrators"){

            $LocalAdminsMember = ((net localgroup Administrators))

            if ($LocalAdminsMember -like "*$NDESServiceAccount*"){

                Write-Warning "NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use the IIS_IUSERS local group instead."
                New-LogEntry  "NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use IIS_IUSERS instead."  -Severity 2

            }

            else {

                Write-StatusMessage "Success:`r`nNDES Service account is not a member of the local Administrators group"
                New-LogEntry  "NDES Service account is not a member of the local Administrators group"  -Severity 1    
            }
        }
           else {

        Write-Warning "No local Administrators group exists, likely due to this being a Domain Controller or renaming the group. It is not recommended to run NDES on a Domain Controller."
        New-LogEntry  "No local Administrators group exists, likely due to this being a Domain Controller or renaming the group. It is not recommended to run NDES on a Domain Controller." -Severity 2
    
        }

    }
} 
 
Function Test-IIS_IUSR_Membership {
    Write-StatusMessage "Checking NDES Service account is a member of the IIS_IUSR group..." 
    if ((net localgroup) -match "IIS_IUSRS"){

        $IIS_IUSRMembers = ((net localgroup IIS_IUSRS))

        if ($IIS_IUSRMembers -like "*$NDESServiceAccount*"){

            Write-StatusMessage "Success:`r`nNDES service account is a member of the local IIS_IUSR group"
            New-LogEntry  "NDES service account is a member of the local IIS_IUSR group" -Severity 1    
        }

        else {

            Write-Output "Error: NDES Service Account is not a member of the local IIS_IUSR group" 
            New-LogEntry  "NDES Service Account is not a member of the local IIS_IUSR group"  -Severity 3 

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

                if ($LocalSecPolResults -match "SeInteractiveLogonRight" -and $LocalSecPolResults -match "SeBatchLogonRight" -and $LocalSecPolResults -match "SeServiceLogonRight"){
            
                    Write-Output "Success: " 
                    Write-Output "NDES Service Account has been assigned the Logon Locally, Logon as a Service and Logon as a batch job rights explicitly."
                    New-LogEntry  "NDES Service Account has been assigned the Logon Locally, Logon as a Service and Logon as a batch job rights explicitly." -Severity 1
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
                    New-LogEntry  "NDES Service Account has _NOT_ been assigned the Logon Locally, Logon as a Service or Logon as a batch job rights _explicitly_." -Severity 3
            
                }

        }

    }

    else {

        Write-Output "Error: No IIS_IUSRS group exists. Ensure IIS is installed."  
        Write-Output 'Please review "Step 3.1 - Configure prerequisites on the NDES server".' 
        Write-Output "https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        New-LogEntry  "No IIS_IUSRS group exists. Ensure IIS is installed." -Severity 3

    }

}
 
Function Test-PFXCertificateConnectorService {
    Write-Output "Checking the `"Log on As`" for PFX Certificate Connector for Intune"  
    $service = Get-Service -Name "PFXCertificateConnectorSvc"

    if ($service) {
        # Get the service's process
        $serviceProcess = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $service.Name }

        # Check if the service is running as Local System or as a specific user
        if ($serviceProcess.StartName -eq "LocalSystem") {
            Write-Output "$($service.Name) is running as Local System"  
        }
        else {
            Write-Output "$($service.Name) is running as $($serviceProcess.StartName)"  
        }
    } 
    else {
        Write-Error "PFXCertificateConnectorSvc service not found"  
    }

}

function Compress-LogFiles {
    param ()

    Write-StatusMessage "Gathering log files..."
    
    if ($PSCmdlet.ParameterSetName -eq "Unattended") {
        Write-Output "Automatically gathering files."
        $LogFileCollectionConfirmation = "y"
    }
    else {
        Write-Output "Do you want to gather troubleshooting files? This includes IIS, NDES Connector, NDES Plugin, CRP, and MSCEP log files, in addition to the SCEP template configuration.  [Y]es, [N]o:"
        $LogFileCollectionConfirmation = Read-Host
    }
    
    if ($LogFileCollectionConfirmation -eq "y") {
        $IISLogPath = (Get-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name logfile.directory).Value + "\W3SVC1" -replace "%SystemDrive%",$env:SystemDrive
        $IISLogs = Get-ChildItem $IISLogPath | Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
        $NDESConnectorLogs = Get-ChildItem "$env:SystemRoot\System32\Winevt\Logs\Microsoft-Intune-CertificateConnectors*"

        foreach ($IISLog in $IISLogs) {
            Copy-Item -Path $IISLog.FullName -Destination $TempDirPath
        }

        foreach ($NDESConnectorLog in $NDESConnectorLogs) {
            Copy-Item -Path $NDESConnectorLog.FullName -Destination $TempDirPath
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

        $SCEPUserCertTemplateOutputFilePath = "$($TempDirPath)\SCEPUserCertTemplate.txt"
        certutil -v -template $SCEPUserCertTemplate > $SCEPUserCertTemplateOutputFilePath

        New-LogEntry "Collecting server logs" -Severity 1

        Add-Type -assembly "system.io.compression.filesystem"
        $Currentlocation = $env:temp
        $date = Get-Date -Format ddMMyyhhmmss
        Copy-Item $LogFilePath .
        [io.compression.zipfile]::CreateFromDirectory($Script:TempDirPath, "$($Currentlocation)\$($date)-CertConnectorLogs-$($hostname).zip")

        Write-Output ""
        Write-Output "Success: " 
        Write-Output "Log files copied to $($Currentlocation)\$($date)-CertConnectorLogs-$($hostname).zip"
        Write-Output ""
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

# Script Variables
$parent = [System.IO.Path]::GetTempPath()
[string] $name = [System.Guid]::NewGuid()
New-Item -ItemType Directory -Path (Join-Path $parent $name) | Out-Null
$Script:TempDirPath = "$parent$name"
$Script:LogFilePath = "$($Script:TempDirPath)\Validate-NDESConfig.log"

# Flag to query computer vs user properties from AD
[bool]$SvcAcctIsComputer = $false
$NDESServiceAccount = Get-NDESServiceAcct
$line = "." * 60

Write-StatusMessage "Starting logging to $logfilepath"
 
Confirm-Variables -NDESServiceAccount $NDESServiceAccount -IssuingCAServerFQDN $IssuingCAServerFQDN -SCEPUserCertTemplate $SCEPUserCertTemplate

if ( -not ( Test-IsRSATADInstalled) ){
    Install-RSATAD
} 

Initialize-LogFile
Test-Variables
Test-IsNDESInstalled
Test-IsAADModuleInstalled
Test-IsIISInstalled
Test-OSVersion
Test-IEEnhancedSecurityMode
Test-NDESServiceAccountProperties -NDESServiceAccount $NDESServiceAccount
Get-EventLogData
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
Format-Log
Compress-LogFiles

#endregion 




#region Ending script
 
Write-StatusMessage  "End of NDES configuration validation" 
 
if ($WriteLogOutputPath) {

        Write-Output "Log file copied to $($LogFilePath)"
        Write-Output ""
        # for ODC
        $copyPath = "$env:temp\CollectedData\Intune\Files\NDES"
        if ($PSCmdlet.ParameterSetName -eq "Unattended"  ){
            if ( -not (Test-Path $copyPath) ) { mkdir $copyPath -Force }
            Copy-Item $Script:LogFilePath $copyPath
            }

            
        Write-Output "Ending script..." 
        Write-Output ""

    }  
 else { 
    New-LogEntry "Skipping log copy based on command line switches" 1
 }

#endregion