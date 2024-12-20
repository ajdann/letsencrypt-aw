#######################################################################################
# Script that renews a Let's Encrypt certificate for an Azure Application Gateway
# Pre-requirements:
#      - Have a storage account in which the folder path has been created: 
#        '/.well-known/acme-challenge/', to put here the Let's Encrypt DNS check files

#      - Add "Path-based" rule in the Application Gateway with this configuration: 
#           - Path: '/.well-known/acme-challenge/*'
#           - Check the configure redirection option
#           - Choose redirection type: permanent
#           - Choose redirection target: External site
#           - Target URL: <Blob public path of the previously created storage account>
#                - Example: 'https://test.blob.core.windows.net/public'
#      - For execution on Azure Automation: Import 'AzureRM.profile', 'AzureRM.Network' 
#        and 'ACMESharp' modules in Azure
#
#      UPDATE 2019-11-27
#      - Due to deprecation of ACMEv1, a new script is required to use ACMEv2.
#        The module to use is called ACME-PS.
#
#      UPDATE 2020-09-03
#      - Migrated to Az modules.
#        Following modules are needed now: Az.Accounts, Az.Network, Az.Storage
#
#######################################################################################

Param(
    [string]$domain,
    [string]$EmailAddress,
    [string]$STResourceGroupName,
    [string]$storageName,
    [string]$AGResourceGroupName,
    [string]$AGName,
    [string]$AGOldCertName,
    [string]$containerName
)

Import-Module ACME-PS

try {
    Write-Output "Logging in as azure managed identity"
    Disable-AzContextAutosave # Ensures that no login info is saved after the runbook is done
    $azureContext = (Connect-AzAccount -Identity).context
    $azureContext = Set-AzContext -SubscriptionName $azureContext.Subscription -DefaultProfile $azureContext
    Write-Output "Logged in as " + $azureContext
    Write-Output "========================="

    Write-Output "Registering with ACME service"
    $state = New-ACMEState -Path $env:TEMP
    $serviceName = 'LetsEncrypt'
    Get-ACMEServiceDirectory $state -ServiceName $serviceName -PassThru;
    New-ACMENonce $state;
    New-ACMEAccountKey $state -PassThru;
    New-ACMEAccount $state -EmailAddresses $EmailAddress -AcceptTOS; # Register the account key with the acme service. The account key will automatically be read from the state
    Write-Output "========================="

    Write-Output "Creating ACME Challenge"
    $state = Get-ACMEState -Path $env:TEMP;
    New-ACMENonce $state -PassThru; 
    $identifier = New-ACMEIdentifier $domain;
    $order = New-ACMEOrder $state -Identifiers $identifier;
    $authZ = Get-ACMEAuthorization -State $state -Order $order;
    $challenge = Get-ACMEChallenge $state $authZ "http-01";
    Write-Output "Challenge data is " + $challenge.Data;
    Write-Output "========================="

    Write-Output "Creating file requested by ACME Challenge"
    $fileName = $env:TMP + '\' + $challenge.Token;
    Write-Output "File name is " + $fileName;
    Set-Content -Path $fileName -Value $challenge.Data.Content -NoNewline;
    $blobName = ".well-known/acme-challenge/" + $challenge.Token
    $storageContext = New-AzStorageContext -StorageAccountName $storageName
    Set-AzStorageBlobContent -File $fileName -Container $containerName -Context $storageContext -Blob $blobName -Properties @{"ContentType" = "text/plain"}
    Write-Output "========================="

    Write-Output "Notifying ACME service that challenge file is ready"
    $challenge | Complete-ACMEChallenge $state;
    Write-Output "========================="

    Write-Output "Waiting for ACME order"
    while($order.Status -notin ("ready","invalid")) {
        Start-Sleep -Seconds 10;
        $order | Update-ACMEOrder $state -PassThru;
        Write-Output "Continuing to poll for ACME order"
    }
    Write-Output "========================="
# Check for invalid order status and get authorization error details
    if($order.Status -ieq "invalid") {  
        Write-Output "Showing details of invalid order"
        $order | Get-ACMEAuthorizationError -State $state;
        throw "Order was invalid";
    }
    Write-Output "Issuing certificate signing request"
    $certKey = New-ACMECertificateKey -Path "$env:TEMP\$domain.key.xml";
    Complete-ACMEOrder $state -Order $order -CertificateKey $certKey;
    Write-Output "========================="

    Write-Output "Waiting for certificate"
    while(-not $order.CertificateUrl) {
        Start-Sleep -Seconds 15
        $order | Update-ACMEOrder $state -PassThru
        Write-Output "Continuing to poll for certificate"
    }
    $password = ConvertTo-SecureString -String "Passw@rd123***" -Force -AsPlainText
    Export-ACMECertificate $state -Order $order -CertificateKey $certKey -Path "$env:TEMP\$domain.pfx" -Password $password;
    Write-Output "========================="

    Write-Output "Cleaning up storage"
    Remove-AzStorageBlob -Container $containerName -Context $storageContext -Blob $blobName
    Write-Output "========================="

    Write-Output "Renewing application gateway certificate with new certificate"
    $appgw = Get-AzApplicationGateway -ResourceGroupName $AGResourceGroupName -Name $AGName
    Set-AzApplicationGatewaySSLCertificate -Name $AGOldCertName -ApplicationGateway $appgw -CertificateFile "$env:TEMP\$domain.pfx" -Password $password
    Set-AzApplicationGateway -ApplicationGateway $appgw
    Write-Output "========================="

    Write-Output "Finished renewing certificate"
}
catch 
{
    Write-Error $_
    throw "Failed to renew certificate"

}