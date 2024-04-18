# Prompt user for subject name
$subjectName = Read-Host -Prompt 'Enter subject name (e.g., CN=yoursubjectname)'
$altname = Read-Host -Prompt 'Enter SubjectAlternativename (e.g., upn=user1@contoso.com)'

Create-CertificateRequest

function Create-CertificateRequest {
    param (
        [string]$subjectName,
        [string]$altname
    )

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
    $scriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path


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
}
