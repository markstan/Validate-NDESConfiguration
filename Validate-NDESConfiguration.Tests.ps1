 Describe "CheckInternalNDESURL" {
    It "Should return an error if the internal NDES URL returns 200 OK" {
        # BEGIN: CheckInternalNDESURL - Test Case 1
        $hostname = "example.com"
        $statuscode = "200"

        $result = CheckInternalNDESURL

        $result | Should -Contain "Error: https://$hostname/certsrv/mscep/mscep.dll returns 200 OK."
        $result | Should -Contain "This usually signifies an error with the Intune Connector registering itself or not being installed."
        # END: CheckInternalNDESURL - Test Case 1
    }

    It "Should retrieve CA capabilities if the internal NDES URL returns 403" {
        # BEGIN: CheckInternalNDESURL - Test Case 2
        $hostname = "example.com"
        $statuscode = "403"
        $Newstatuscode = "200"
        $CACaps = "Test CA Capabilities"

        $result = CheckInternalNDESURL

        $result | Should -Contain "Success: CA Capabilities retrieved:"
        $result | Should -Contain $CACaps
        # END: CheckInternalNDESURL - Test Case 2
    }

    It "Should return an error for unexpected error codes" {
        # BEGIN: CheckInternalNDESURL - Test Case 3
        $hostname = "example.com"
        $statuscode = "500"

        $result = CheckInternalNDESURL

        $result | Should -Contain "Error: Unexpected Error code!"
        $result | Should -Contain "Expected value is a 403."
        $result | Should -Contain "We received a $($statuscode)."
        $result | Should -Contain "This could be down to a missing reboot post policy module install."
        # END: CheckInternalNDESURL - Test Case 3
    }
}

Describe "CheckLastBootTime" {
    It "Should check the server's last boot time" {
        # BEGIN: CheckLastBootTime - Test Case 1
        $LastBoot = "2022-01-01 00:00:00"

        $result = CheckLastBootTime

        $result | Should -Contain "Server last rebooted: $LastBoot"
        $result | Should -Contain "Please ensure a reboot has taken place _after_ all registry changes and installing the NDES Connector."
        $result | Should -Contain "IISRESET is _not_ sufficient."
        # END: CheckLastBootTime - Test Case 1
    }
}

Describe "CheckIntuneConnectorInstallation" {
    It "Should check if the Intune Connector is installed" {
        # BEGIN: CheckIntuneConnectorInstallation - Test Case 1
        $IntuneConnector = @{
            DisplayName = "Certificate Connector for Microsoft Intune"
            DisplayVersion = "1.0"
            Publisher = "Microsoft"
            InstallDate = "20220101"
        }

        $result = CheckIntuneConnectorInstallation

        $result | Should -Contain "Success: $($IntuneConnector.DisplayName) was installed on $($IntuneConnector.InstallDate) and is version $($IntuneConnector.DisplayVersion)"
        # END: CheckIntuneConnectorInstallation - Test Case 1
    }

    It "Should return an error if the Intune Connector is not installed" {
        # BEGIN: CheckIntuneConnectorInstallation - Test Case 2
        $IntuneConnector = $null

        $result = CheckIntuneConnectorInstallation

        $result | Should -Contain "Error: Intune Connector not installed"
        $result | Should -Contain 'Please review "Step 5 - Enable, install, and configure the Intune certificate connector".'
        $result | Should -Contain "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        # END: CheckIntuneConnectorInstallation - Test Case 2
    }
}

Describe "CheckIntuneConnectorRegistryKeys" {
    It "Should check if the Intune Connector registry keys are intact" {
        # BEGIN: CheckIntuneConnectorRegistryKeys - Test Case 1
        $KeyRecoveryAgentCertificatePresent = "Test KeyRecoveryAgentCertificate"
        $PfxSigningCertificatePresent = "Test PfxSigningCertificate"
        $SigningCertificatePresent = "Test SigningCertificate"

        $result = CheckIntuneConnectorRegistryKeys

        $result | Should -Contain "Success: KeyRecoveryAgentCertificate registry key exists"
        $result | Should -Contain "Success: PfxSigningCertificate registry keys exists"
        $result | Should -Contain "Success: SigningCertificate registry key exists"
        # END: CheckIntuneConnectorRegistryKeys - Test Case 1
    }

    It "Should return an error if any of the Intune Connector registry keys are missing" {
        # BEGIN: CheckIntuneConnectorRegistryKeys - Test Case 2
        $KeyRecoveryAgentCertificatePresent = $null
        $PfxSigningCertificatePresent = $null
        $SigningCertificatePresent = $null

        $result = CheckIntuneConnectorRegistryKeys

        $result | Should -Contain "Error: KeyRecoveryAgentCertificate Registry key does not exist."
        $result | Should -Contain "Error: PfxSigningCertificate Registry key does not exist."
        $result | Should -Contain "Error: SigningCertificate Registry key does not exist."
        # END: CheckIntuneConnectorRegistryKeys - Test Case 2
    }
}