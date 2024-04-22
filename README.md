# Validate-NDESConfiguration

Validate-NDES Configuration is a support script to validate the on-premises Network Device Enrolment Service (NDES) configuration. The script also collects logs, registry data for MSCEP and Microsoft Intune Connector, recent IIS logs and eventvwr. Once the data is gathered, the script will open an Explorer window in the folder where the ODC contents are located. The default file name is DATEANDTIME-CertConnectorLogs.zip.

To run this tool, open an elevated PowerShell window (right-click, "Run as administrator..."), create a temporary folder, then run these three commands:

         wget https://aka.ms/NDESValidatorPS1  -outfile NDESValidator.ps1
         PowerShell -ExecutionPolicy Bypass -File .\NDESValidator.ps1

(Hint: You can copy and paste the commands from this page and paste them directly in to the PowerShell window.

The first line downloads the NDESValidator Powershell Script. The second line runs the script.

If you have any problems downloading the files using the commands above (usually due to network or firewall restrictions), you can also click on the green 'Code' button above and choose Download ZIP to save the contents of this project.

![image](https://github.com/PremNRajan/Pren-Validate-NDESConfiguration/assets/145558878/ddd015f6-06f9-4c4e-a802-c5e071b85857)

Please contact [markstan@microsoft.com](mailto:markstan@microsoft.com) for any bug reports or feature requests.

