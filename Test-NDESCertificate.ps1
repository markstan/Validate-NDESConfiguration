# Prompt user for subject name
$subjectName = Read-Host -Prompt 'Enter subject name (e.g., CN=yoursubjectname)'
$altname = Read-Host -Prompt 'Enter SubjectAlternativename (e.g., upn=user1@contoso.com)'

# Create content for INF file
$infContent = @"
[Version]
Signature=`"$Windows NT$`"
[NewRequest]
Subject = "CN=$subjectName"
KeyLength = 2048
ProviderName = `"Microsoft RSA SChannel Cryptographic Provider`"
ProviderType = 12
RequestType = PKCS10
[Extensions]

2.5.29.17 = "{text}"
_continue_ = "UPN=$altname"
"@

# Get the script's running location
$scriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Specify the INF file path
$infFilePath = Join-Path -Path $scriptLocation -ChildPath 'certificate_request.inf'

# Write content to INF file
$infContent | Out-File -FilePath $infFilePath -Encoding ASCII

Write-Host "INF file created successfully at: $infFilePath"

# Run certreq to create CSR
$csrFileName = "test.csr"
$infFileLocation = $infFilePath  # Assuming $infFilePath contains the path to the INF file

# Run certreq command to generate CSR
certreq -new $infFileLocation $csrFileName

# Define the registry path
$registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP"

# Define the names of the properties/values you want to retrieve
$propertyName1 = "EncryptionTemplate"
$propertyName2 = "GeneralPurposeTemplate"
$propertyName3 = "SignatureTemplate"

# Check if the registry path exists
if (Test-Path $registryPath) {
    # Attempt to get the first property value
    try {
        # Use Get-ItemProperty to fetch the first property's value
        $value1 = (Get-ItemProperty -Path $registryPath -Name $propertyName1).$propertyName1

        # Check if the value was successfully retrieved
        if ($null -ne $value1) {
            Write-Output "Template Configured for $propertyName1 is: $value1"
        }
        else {
            Write-Output "No template Configuration for'$propertyName1'"
        }
    }
    catch {
        Write-Output "An error occurred while retrieving the property '$propertyName1': $_"
    }

    # Attempt to get the second property value
    try {
        # Use Get-ItemProperty to fetch the second property's value
        $value2 = (Get-ItemProperty -Path $registryPath -Name $propertyName2).$propertyName2

        # Check if the value was successfully retrieved
        if ($null -ne $value2) {
            Write-Output "Template configured for $propertyName2 is: $value2"
        }
        else {
            Write-Output "No template Configuration for'$propertyName2'"
        }
    }
    catch {
        Write-Output "An error occurred while retrieving the property '$propertyName2': $_"
    }
    
    # Attempt to get the third property value
    try {
        # Use Get-ItemProperty to fetch the third property's value
        $value3 = (Get-ItemProperty -Path $registryPath -Name $propertyName3).$propertyName3

        # Check if the value was successfully retrieved
        if ($null -ne $value3) {
            Write-Output "Template configured for $propertyName3 is: $value3"
        }
        else {
            Write-Output "No template Configuration for'$propertyName3'"
        }
    }
    catch {
        Write-Output "An error occurred while retrieving the property '$propertyName3': $_"
    }
}
else {
    Write-Output "The registry path '$registryPath' does not exist."
}

# Submit CSR for certificate issuance
$csrFilePath = Join-Path -Path $scriptLocation -ChildPath $csrFileName
$certificateTemplate = $value1

# Fetching the CAInfo from Registry

$CAConfiguration = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\CAInfo" -Name Configuration
$cainfo = $CAConfiguration.Configuration

Write-Output "CAinfo is $cainfo"

# Sumitting the certreq
certreq.exe -submit -config "$cainfo"-attrib "CertificateTemplate:$certificateTemplate"  $csrFilePath

# Remove the CSR file
Remove-Item -Path $csrFilePath

# Remove the INF file
Remove-Item -Path $infFilePath
