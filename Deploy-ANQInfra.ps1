<# Variables:
{
    "ANQAdminEmail": {
        "Description": "ANQ Administrator Email Address",
        "IsRequired": true
    },
    "ANQAdminPassword": {
        "Description": "ANQ Administrator Password",
        "IsRequired": true
    },
    "ANQClusterName": {
        "Description": "ANQ Cluster Name - must be less than 16 characters.",
        "IsRequired": true
    },
    "ANQStorageSKU": {
        "Description": "ANQ Storage SKU [hot or cold]",
        "IsRequired": true,
        "DefaultValue": "Hot"
    },
    "ANQInitialCapacity": {
        "Description": "ANQ Initial Capacity in TB",
        "IsRequired": true,
        "DefaultValue": 50
    },
    "ANQInternalTenantID": {
        "Description": "ANQ Internal Tenant ID",
        "IsRequired": false,
        "DefaultValue": 1
    },
    "ANQProfileShareName": {
        "Description": "ANQ Profile Share Name",
        "IsRequired": true
    },
    "ANQFsPath": {
        "Description": "ANQ File System Path",
        "IsRequired": true
    },
    "ANQShareDescription": {
        "Description": "ANQ Share Description",
        "IsRequired": false
    },
    "ANQGrantReadAccess": {
        "Description": "ANQ Grant Read Access",
        "IsRequired": false
    },
    "ANQGrantReadWriteAccess": {
        "Description": "ANQ Grant Read Write Access",
        "IsRequired": false
    },
    "ANQGrantAllAccess": {
        "Description": "ANQ Grant All Access",
        "IsRequired": false
    }
}
#>

$ANQVirtualNetwork= $SecureVars.ANQVirtualNetwork
$ANQClusterZone= $SecureVars.ANQClusterZone
$ANQSubnet= $SecureVars.ANQSubnet
$ANQOfferId= $SecureVars.ANQOfferId
$ANQPublisherId= $SecureVars.ANQPublisherId
$ANQPlanID= $SecureVars.ANQPlanID
$AzureRegionName= $SecureVars.ANQRegionName 
$AzureResourceGroupName= $SecureVars.ANQResourceGroupName
$AzureSubscriptionId= $AzureSubscriptionId
$NerdioTenantID= $SecureVars.NerdioTenantID
$ANQADDomainName= $SecureVars.ANQADDomainName
$ANQADUsername= $SecureVars.ANQADUsername
$ANQADPassword= $SecureVars.ANQADPassword
$NerdioClientID= $SecureVars.NerdioClientID
$NerdioAPIScope= $SecureVars.NerdioAPIScope
$NerdioClientSecret= $SecureVars.NerdioClientSecret
$NerdioNMEURI= $SecureVars.NerdioNMEURI


# Formats JSON in a nicer format than the built-in ConvertTo-Json does.
function Format-Json([Parameter(Mandatory, ValueFromPipeline)][String] $json) {
    $indent = 0;
    ($json -Split '\n' |
    % {
        if ($_ -match '[\}\]]') {
        # This line contains  ] or }, decrement the indentation level
        $indent--
        }
        $line = (' ' * $indent * 2) + $_.TrimStart().Replace(':  ', ': ')
        if ($_ -match '[\{\[]') {
        # This line contains [ or {, increment the indentation level
        $indent++
        }
        $line
    }) -Join "`n"
}

function Login-ANQCluster {
    param(
        [string]$ANQAdminIPAddress,
        [int]$ANQPortNumber,
        [string]$ANQAdminUsername,
        [string]$ANQAdminPassword
        )
    
    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Login to the ANQ cluster $($ANQAdminIPAddress)"

    if (!$BearerToken) {
        # API Request Body
        $Body = @{
            'username' = $ANQAdminUsername
            'password' = $ANQAdminPassword
        }

        # API url definition
        $Url = "/v1/session/login"

        # API call run	
        try {
            # Adjusting for compatibility with older PowerShell versions
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                $response = Invoke-RestMethod -Method 'POST' -Uri "https://$($ANQAdminIPAddress):$($ANQPortNumber)$($Url)" -Body ($Body | ConvertTo-Json -Depth 10) -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

            }
            else{
                if ($SkipCertificateCheck -eq 'true') {
                    $PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
                    $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://$($ANQAdminIPAddress):$($ANQPortNumber)$($Url)" -Body ($Body | ConvertTo-Json -Depth 10) -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
                }
            }
            
            # Outputs
            $BearerToken = $response.bearer_token

            # Credentials will be required for other function operations. 	
            $global:Credentials = @{
                ANQAdminIPAddress = $ANQAdminIPAddress
                ANQPortNumber = $ANQPortNumber
                BearerToken = $BearerToken
            }
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Logged in successfully to the ANQ Cluster - $($ANQAdminIPAddress)"
            return
        }
        catch {
            Write-Error "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Failed to login. Error: $($_.Exception.Message)"
        }
    }
}

function Modify-ANQNetwork {
    param(
        [int16]$NetworkID=1,
        [array]$DnsServers,
        [array]$DnsSearchDomains,
        [int16]$TenantID=1,
        [string]$ANQAdminIPAddress,
        [int]$ANQPortNumber=8000,
        [string]$ANQAdminUsername,
        [string]$ANQAdminPassword
    )

    if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
    }

    try {
        # Existing BearerToken check
        if (!$global:Credentials) {
            Login-ANQCluster -ANQAdminIPAddress $ANQAdminIPAddress -ANQPortNumber $ANQPortNumber -ANQAdminUsername $ANQAdminUsername -ANQAdminPassword $ANQAdminPassword
        }
        else {
            if (!$global:Credentials.BearerToken){
                Login-ANQCluster -ANQAdminIPAddress $ANQAdminIPAddress -ANQPortNumber $ANQPortNumber -ANQAdminUsername $ANQAdminUsername -ANQAdminPassword $ANQAdminPassword
            }
            else{
                if (!$global:Credentials.BearerToken.StartsWith("session-v1")) {
                    Login-ANQCluster -ANQAdminIPAddress $ANQAdminIPAddress -ANQPortNumber $ANQPortNumber -ANQAdminUsername $ANQAdminUsername -ANQAdminPassword $ANQAdminPassword
                }
            }
        }

        $bearerToken = $global:Credentials.BearerToken

        $TokenHeader = @{
            Authorization = "Bearer $bearerToken"
        }

        # API Request Body
        $body = @{
            "id" = $networkID
            "dns_servers" = $DnsServers
            "dns_search_domains" = $DnsSearchDomains
            "tenant_id" = $TenantID 
        }

        Write-Output ($body | ConvertTo-Json -Depth 10)

        # API url definition
        $url = "/v2/network/interfaces/1/networks/$NetworkID"

        # API call run	
        try {
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                $response = Invoke-RestMethod -Method 'PATCH' -Uri "https://$($ANQAdminIPAddress):$($ANQPortNumber)$($Url)" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

            }
            else{
                if ($SkipCertificateCheck -eq 'true') {
                    $PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
                    $response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri "https://$($ANQAdminIPAddress):$($ANQPortNumber)$($Url)" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
                }
            }
        }
        catch {
            Write-Error "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $($_.Exception.Message)"
            Write-Output "Failed to define DNS servers and search domains $_"
            exit 1
        }
    }
    catch {
        Write-Error "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $($_.Exception.Message)"
        Write-Output "Failed to define DNS servers and search domains $_"
        exit 1
    }
}



function Create-ANQCluster {
    param (
        [string]$AzureSubscriptionId,
        [string]$AzureRegionName,
        [string]$AzureResourceGroupName,
        [string]$ANQClusterName,
        [string]$ANQAdminEmail,
        [string]$ANQClusterZone,
        [string]$ANQVirtualNetwork,
        [string]$ANQSubnet,
        [string]$ANQAdminPassword,
        [string]$ANQOfferId,
        [string]$ANQPublisherId,
        [string]$ANQPlanID,
        [string]$ANQStorageSKU,
        [int]$ANQInitialCapacity,
        [string]$NerdioClientID,
        [string]$NerdioClientSecret,
        [string]$NerdioTenantID
    )

    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ANQ cluster deployment has started..."
    
        # Write-Output "AzureSubscriptionId" $AzureSubscriptionId
        # Write-Output "AzureRegionName" $AzureRegionName
        # Write-Output "AzureResourceGroupName" $AzureResourceGroupName
        # Write-Output "ANQClusterName" $ANQClusterName
        # Write-Output "ANQAdminEmail" $ANQAdminEmail
        # Write-Output "ANQClusterZone" $ANQClusterZone
        # Write-Output "ANQVirtualNetwork" $ANQVirtualNetwork
        # Write-Output "ANQSubnet" $ANQSubnet
        # Write-Output "ANQAdminPassword" $ANQAdminPassword
        # Write-Output "ANQOfferId" $ANQOfferId
        # Write-Output "ANQPublisherId" $ANQPublisherId
        # Write-Output "ANQPlanID" $ANQPlanID
        # Write-Output "ANQStorageSKU" $ANQStorageSKU
        # Write-Output "ANQInitialCapacity" $ANQInitialCapacity
        # Write-Output "NerdioClientID" $NerdioClientID
        # Write-Output "NerdioClientSecret" $NerdioClientSecret
        # Write-Output "NerdioTenantID" $NerdioTenantID

    # Define the body of the request
    $Body = @{
        properties = @{
            marketplaceDetails = @{
                planId = $ANQPlanID
                offerId = $ANQOfferId
                publisherId = $ANQPublisherId
            }
            userDetails = @{ email = $ANQAdminEmail }
            delegatedSubnetId = "/subscriptions/$AzureSubscriptionId/resourceGroups/$AzureResourceGroupName/providers/Microsoft.Network/virtualNetworks/$ANQVirtualNetwork/subnets/$ANQSubnet"
            storageSku = $ANQStorageSKU
            adminPassword = $ANQAdminPassword
            initialCapacity = $ANQInitialCapacity
            availabilityZone = $ANQClusterZone
        }
        location = $AzureRegionName
    }

    # Convert the hashtable to a JSON string
    $BodyJson = $Body | ConvertTo-Json -Depth 10

    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ANQ cluster parameters are ready"

    # Obtain an access token
    $tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$NerdioTenantID/oauth2/token" -Body @{
        grant_type    = "client_credentials"
        client_id     = $NerdioClientID
        client_secret = $NerdioClientSecret
        resource      = "https://management.azure.com/"
    }

    $accessToken = $tokenResponse.access_token

    # Include the access token in the 'Authorization' header of your API request
    $headers = @{
        'Authorization' = "Bearer $accessToken"
        'Content-Type'  = "application/json"
    }

    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Access token obtained."

    # Set the API version for the Azure REST API call
    $ApiVersion = '2024-01-30-preview'

    # Construct the REST API endpoint URL
    $url = "https://management.azure.com/subscriptions/$($AzureSubscriptionId)/resourceGroups/$($AzureResourceGroupName)/providers/Qumulo.Storage/fileSystems/$($ANQClusterName)?api-version=$($ApiVersion)"
    
    # Execute the Azure CLI command to create the cluster. Note: This action requires already logged in with az login if using Cloud Shell
    try {
        $createResponse = Invoke-RestMethod -Method Put -Uri $url -Body $BodyJson -Headers $headers
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Cluster create request submitted. Waiting for cluster to be provisioned. It will take 10-15 minutes."
        do {
            Start-Sleep -Seconds 15
            $viewStatusResponse = Invoke-RestMethod -Method Get -Uri $url -Headers $headers
            $provisioningState = $viewStatusResponse.properties.provisioningState
            if ($provisioningState -ne "Succeeded") {
                Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Cluster provisioning state: $provisioningState. Please wait for cluster provisioning"
            }
            else{
                Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  Cluster provisioning state: $provisioningState. Your ANQ cluster is ready."
                Write-Output "Cluster details: "
                Write-Output "Login URL: $($viewStatusResponse.properties.clusterLoginUrl)"
                Write-Output "Private IPs: $($viewStatusResponse.properties.privateIPs)"
                Write-Output "Capacity: $($viewStatusResponse.properties.InitialCapacity)"
                Write-Output "Storage SKU: $($viewStatusResponse.properties.storageSku)"                
            }
        } while ($provisioningState -ne "Succeeded")
        $global:AdminIPAddress = $viewStatusResponse.properties.privateIPs[0]
    
    } catch {
        Write-Error "Failed to create cluster: $_"
    }

    

}

function Join-ANQADDomain {
    param(
        [string]$ANQADDomainName,
        [string]$ANQADUsername,
        [string]$ANQADPassword,
        [string]$ANQADNetbios,
        [string]$ANQADOU,
        [bool]$ANQADPosixAttributes = $False,
        [string]$ANQADBaseDn,
        [string]$ANQAdminIPAddress,
        [int]$ANQPortNumber,
        [string]$ANQAdminUsername,
        [string]$ANQAdminPassword
    )

    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Joining the $($ANQADNetbios) domain"

    try {
        # Existing BearerToken check
        if (!$global:Credentials) {
            Login-ANQCluster -ANQAdminIPAddress $ANQAdminIPAddress -ANQPortNumber $ANQPortNumber -ANQAdminUsername $ANQAdminUsername -ANQAdminPassword $ANQAdminPassword
        }
        else {
            if (!$global:Credentials.BearerToken){
                Login-ANQCluster -ANQAdminIPAddress $ANQAdminIPAddress -ANQPortNumber $ANQPortNumber -ANQAdminUsername $ANQAdminUsername -ANQAdminPassword $ANQAdminPassword
            }
            else{
                if (!$global:Credentials.BearerToken.StartsWith("session-v1")) {
                    Login-ANQCluster -ANQAdminIPAddress $ANQAdminIPAddress -ANQPortNumber $ANQPortNumber -ANQAdminUsername $ANQAdminUsername -ANQAdminPassword $ANQAdminPassword
                }
            }
        }

        $bearerToken = $global:Credentials.BearerToken

        $TokenHeader = @{
            Authorization = "Bearer $bearerToken"
        }

        # API Request Body
        $Body = @{
            'user' = $ANQADUsername
            'password' = $ANQADPassword
            'domain' = $ANQADDomainName
            'domain_netbios' = $ANQADNetbios
            'ou' = $ANQADOU
            'use_ad_posix_attributes' = $ANQADPosixAttributes
            'base_dn' = $ANQADBaseDn
        }

        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Sending a request to join the domain"


        # API url definition
        $url = "/v1/ad/join"

        # API call run
        try {
            # Adjusting for compatibility with older PowerShell versions
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                $response = Invoke-RestMethod -Method 'POST' -Uri "https://$($ANQAdminIPAddress):$($ANQPortNumber)$($Url)" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
            }
            else{
                if ($SkipCertificateCheck -eq 'true') {
                    $PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
                    $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://$($ANQAdminIPAddress):$($ANQPortNumber)$($Url)" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
                }
            }
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Domain joined successfully."
            return $response
        }
        catch {
            Write-Error "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $($_.Exception.Message)"
        }
    }
    catch {
        Write-Error "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $($_.Exception.Message)"
    }
}

function Add-ANQSMBShare {
    param(
        [string]$ANQProfileShareName,
        [int]$ANQInternalTenantID = 1,
        [string]$ANQFsPath,
        [bool]$ANQCreateFSPath = $True,
        [string]$ANQDefaultFileCreateMode = "0644",
        [string]$ANQDefaultDirCreateMode = "0755",
        [bool]$AccessBasedEnumaration = $False,
        [bool]$ANQRequireEncryption = $False,
        [switch]$ANQNoAccess,
        [switch]$ANQDenyAllHosts,
        [switch]$ANQReadOnly,
        [switch]$ANQAllAccess,
        [array]$ANQGrantReadAccess,
        [array]$ANQGrantReadWriteAccess,
        [array]$ANQGrantAllAccess,
        [array]$ANQDenyAccess,
        [array]$ANQReadOnlyHosts,
        [array]$ANQDenyHosts,
        [array]$ANQFullControlHosts,
        [string]$ANQAdminIPAddress,
        [int]$ANQPortNumber = 8000,
        [string]$ANQAdminUsername,
        [string]$ANQAdminPassword
    )
    
    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Creating the $($ANQProfileShareName) SMB share on the $($clusterName) ANQ cluster"
    
    try {
        # Existing BearerToken check
        if (!$global:Credentials) {
            Login-ANQCluster -ANQAdminIPAddress $ANQAdminIPAddress -ANQPortNumber $ANQPortNumber -ANQAdminUsername $ANQAdminUsername -ANQAdminPassword $ANQAdminPassword
        }
        else {
            if (!$global:Credentials.BearerToken){
                Login-ANQCluster -ANQAdminIPAddress $ANQAdminIPAddress -ANQPortNumber $ANQPortNumber -ANQAdminUsername $ANQAdminUsername -ANQAdminPassword $ANQAdminPassword
            }
            else{
                if (!$global:Credentials.BearerToken.StartsWith("session-v1")) {
                    Login-ANQCluster -ANQAdminIPAddress $ANQAdminIPAddress -ANQPortNumber $ANQPortNumber -ANQAdminUsername $ANQAdminUsername -ANQAdminPassword $ANQAdminPassword
                }
            }
        }

        $bearerToken = $global:Credentials.BearerToken
        $ANQAdminIPAddress = $global:Credentials.ANQAdminIPAddress
        $ANQPortNumber = $global:Credentials.ANQPortNumber

        $TokenHeader = @{
            Authorization = "Bearer $bearerToken"
        }

        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') SMB share parameters are being prepared"

        # API url definition
        
        $url = "/v3/smb/shares/?allow-fs-path-create=true"
        

        # Trustee (User & Group) Share Permissions
        if ($ANQNoAccess) {
            $permissions = @()
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') No SMB share user permissions defined"
        }
        else {
            $permissions = @()
            if ($ANQReadOnly) {
                $trusteeHash = @{ name = "Everyone" }
                $permissions += (
                    @{
                        type = "ALLOWED"
                        trustee = $trusteeHash
                        rights = @(
                            "READ"
                        )
                    }
                )
            }

            if ($ANQAllAccess) {
                $trusteeHash = @{ name = "Everyone" }
                $permissions += (
                    @{
                        type = "ALLOWED"
                        trustee = $trusteeHash
                        rights = @(
                            "ALL"
                        )
                    }
                )
            }
            if ($ANQGrantReadAccess) {
                foreach ($trustee in $ANQGrantReadAccess) {
                    if ($trustee.Contains(':'))
                    {
                        $trusteeArray = $trustee.Split(":")
                        $trusteeHash = @{ $trusteeArray[0] = $trusteeArray[1] }
                    }
                    else {
                        $trusteeHash = @{ name = $trustee }
                    }
                    $permissions += (
                        @{
                            type = "ALLOWED"
                            trustee = $trusteeHash
                            rights = @(
                                "READ"
                            )
                        }
                    )
                }
            }
            if ($ANQGrantReadWriteAccess) {
                foreach ($trustee in $ANQGrantReadWriteAccess) {
                    if ($trustee.Contains(':'))
                    {
                        $trusteeArray = $trustee.Split(":")
                        $trusteeHash = @{ $trusteeArray[0] = $trusteeArray[1] }
                    }
                    else {
                        $trusteeHash = @{ name = $trustee }
                    }
                    $permissions += (
                        @{
                            type = "ALLOWED"
                            trustee = $trusteeHash
                            rights = @(
                                "READ",
                                "WRITE"
                            )
                        }
                    )
                }
            }
            if ($ANQGrantAllAccess) {
                foreach ($trustee in $ANQGrantAllAccess) {
                    if ($trustee.Contains(':'))
                    {
                        $trusteeArray = $trustee.Split(":")
                        $trusteeHash = @{ $trusteeArray[0] = $trusteeArray[1] }
                    }
                    else {
                        $trusteeHash = @{ name = $trustee }
                    }
                    $permissions += (
                        @{
                            type = "ALLOWED"
                            trustee = $trusteeHash
                            rights = @(
                                "ALL"
                            )
                        }
                    )
                }
            }
            if ($ANQDenyAccess) {
                foreach ($trustee in $ANQDenyAccess) {
                    if ($trustee.Contains(':'))
                    {
                        $trusteeArray = $trustee.Split(":")
                        $trusteeHash = @{ $trusteeArray[0] = $trusteeArray[1] }
                    }
                    else {
                        $trusteeHash = @{ name = $trustee }
                    }
                    $permissions += (
                        @{
                            type = "DENIED"
                            trustee = $trusteeHash
                            rights = @(
                                "ALL"
                            )
                        }
                    )
                }
            }

            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') SMB share user permissions are ready"
        }

        # Host Restriction Permissions
        if (!$ANQReadOnlyHosts -or !$ANQDenyHosts -or !$ANQFullControlHosts -or !$ANQDenyAllHosts)
        {
            $networkPermissions = @(
                @{
                    type = "ALLOWED"
                    address_ranges = @()
                    rights = @(
                        "READ",
                        "WRITE",
                        "CHANGE_PERMISSIONS"
                    )
                }
            )

            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') No SMB share host permissions defined"

        }
        else {
            $networkPermissions = @()
            if ($ANQReadOnlyHosts) {
                $networkPermissions += (
                    @{
                        type = "DENIED"
                        address_ranges = $ANQReadOnlyHosts
                        rights = @(
                            "WRITE",
                            "CHANGE_PERMISSIONS"
                        )
                    },
                    @{
                        type = "ALLOWED"
                        address_ranges = $ANQReadOnlyHosts
                        rights = @(
                            "READ"
                        )
                    }
                )
            }
            if ($ANQDenyHosts) {
                $networkPermissions += (
                    @{
                        type = "DENIED"
                        address_ranges = $ANQDenyHosts
                        rights = @(
                            "ALL"
                        )
                    }
                )
            }
            if ($ANQFullControlHosts) {
                $networkPermissions += (
                    @{
                        type = "ALLOWED"
                        address_ranges = $ANQFullControlHosts
                        rights = @(
                            "ALL"
                        )
                    }
                )
            }
            if ($ANQDenyAllHosts) {
                $networkPermissions += (
                    @{
                        type = "DENIED"
                        address_ranges = $ANQDenyAllHosts
                        rights = @(
                            "ALL"
                        )
                    }
                )
            }

            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') SMB share host permissions are ready"
        }

        # API Request body
        $body = @{
            "share_name" = $ANQProfileShareName
            "tenant_id" = $ANQInternalTenantID
            "fs_path" = $ANQFsPath
            "description" = $ANQShareDescription
            "permissions" = $Permissions
            "network_permissions" = $networkPermissions
            "access_based_enumeration_enabled" = $AccessBasedEnumaration
            "default_file_create_mode" = $ANQDefaultFileCreateMode
            "default_directory_create_mode" = $ANQDefaultDirCreateMode
            "require_encryption" = $ANQRequireEncryption
        }

        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Share settings are going to be applied now"

        # API call run
        try {
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                $response = Invoke-RestMethod -Method 'POST' -Uri "https://$($ANQAdminIPAddress):$($ANQPortNumber)$($Url)" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
            
            }
            else{
                if ($SkipCertificateCheck -eq 'true') {
                    $PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
                }
                $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://$($ANQAdminIPAddress):$($ANQPortNumber)$($Url)" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
            }
                Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') SMB share details:"
                Write-Output ($response|ConvertTo-Json -Depth 10 | Format-Json)
                return
        }
        catch {
            Write-Error "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $($_.Exception.Message)"
            Write-Output "Failed to create SMB share: $_"
            exit 1
        }
    }
    catch {
        Write-Error "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') failed to login. Error: $($_.Exception.Message)"
        Write-Output "Failed to create SMB share: $_"
        exit 1
    }
}


# Define a hashtable to hold command parameters
$CreateANQCmdParameters = @{
    AzureSubscriptionId = $AzureSubscriptionId
    AzureRegionName = $AzureRegionName
    AzureResourceGroupName = $AzureResourceGroupName
    ANQClusterName = $ANQClusterName
    ANQAdminEmail = $ANQAdminEmail
    ANQClusterZone = $ANQClusterZone
    ANQVirtualNetwork = $ANQVirtualNetwork
    ANQSubnet = $ANQSubnet
    ANQAdminPassword = $ANQAdminPassword
    ANQOfferId = $ANQOfferId
    ANQPublisherId = $ANQPublisherId
    ANQPlanID = $ANQPlanID
    ANQStorageSKU = $ANQStorageSKU
    ANQInitialCapacity = $ANQInitialCapacity
    NerdioClientID = $NerdioClientID
    NerdioClientSecret = $NerdioClientSecret
    NerdioTenantID = $NerdioTenantID
}



# Use splatting to pass parameters to the function

Create-ANQCluster @CreateANQCmdParameters

$ANQAdminIPAddress = $global:AdminIPAddress
$ANQPortNumber = 8000
$ANQAdminUsername = "admin"

Start-Sleep -Seconds 10

$NetworkCmdParameters = @{
    NetworkID=1
    DnsServers = $ANQDnsServers
    DnsSearchDomains = $ANQSearchDomains
    TenantID=1
    ANQAdminIPAddress = $ANQAdminIPAddress
    ANQPortNumber = $ANQPortNumber
    ANQAdminUsername = $ANQAdminUsername
    ANQAdminPassword = $ANQAdminPassword
}

# Modify-ANQNetwork @NetworkCmdParameters

# Start-Sleep -Seconds 10

# Define a hashtable to hold command parameters
$JoinADCmdParameters = @{
    ANQADDomainName = $ANQADDomainName
    ANQADUsername = $ANQADUsername
    ANQADPassword = $ANQADPassword
    ANQAdminIPAddress = $ANQAdminIPAddress
    ANQPortNumber = $ANQPortNumber
    ANQAdminUsername = $ANQAdminUsername
    ANQAdminPassword = $ANQAdminPassword
}

# Conditionally add parameters to the hashtable
if ($ANQADNetbios) {
    $JoinADCmdParameters['ANQADNetbios'] = $ANQADNetbios
}

if ($ANQADOU) {
    $JoinADCmdParameters['ANQADOU'] = $ANQADOU
}

if ($ANQADPosixAttributes) {
    $JoinADCmdParameters['ANQADPosixAttributes'] = $ANQADPosixAttributes
}

if ($ANQADBaseDn) {
    $JoinADCmdParameters['ANQADBaseDn'] = $ANQADBaseDn
}

Join-ANQADDomain @JoinADCmdParameters

Write-Output "SMB share creation operations will start in 3 minutes..."
Start-Sleep -Seconds 60
Write-Output "SMB share creation operations will start in 2 minutes..."
Start-Sleep -Seconds 60
Write-Output "SMB share creation operations will start in 1 minute..."
Start-Sleep -Seconds 60

# Define a hashtable to hold command parameters
$CmdParameters = @{
    ANQProfileShareName = $ANQProfileShareName
    ANQFsPath = $ANQFsPath
    ANQCreateFSPath = $True
    ANQAdminIPAddress = $ANQAdminIPAddress
    ANQPortNumber = $ANQPortNumber
    ANQAdminUsername = $ANQAdminUsername
    ANQAdminPassword = $ANQAdminPassword
}

# Conditionally add parameters to the hashtable
if ($ANQInternalTenantID) {
    $CmdParameters['ANQInternalTenantID'] = $ANQInternalTenantID
}

if ($ANQAccessBasedEnumeration) {
    $CmdParameters['ANQAccessBasedEnumeration'] = $ANQAccessBasedEnumeration
}

if ($ANQRequireEncryption) {
    $CmdParameters['ANQRequireEncryption'] = $ANQRequireEncryption
}

if ($ANQShareDescription) {
    $CmdParameters['ANQShareDescription'] = $ANQShareDescription
}

if ($ANQGrantAllAccess) {
    $CmdParameters['ANQGrantAllAccess'] = $ANQGrantAllAccess
}

if ($ANQGrantReadWriteAccess) {
    $CmdParameters['ANQGrantReadWriteAccess'] = $ANQGrantReadWriteAccess
}

if ($ANQNoAccess) {
    $CmdParameters['ANQNoAccess'] = $ANQNoAccess
}

if ($ANQDenyAllHosts) {
    $CmdParameters['ANQDenyAllHosts'] = $ANQDenyAllHosts
}

if ($ANQReadOnly) {
    $CmdParameters['ANQReadOnly'] = $ANQReadOnly
}

if ($ANQAllAccess) {
    $CmdParameters['ANQAllAccess'] = $ANQAllAccess
}

if ($ANQGrantReadAccess) {
    $CmdParameters['ANQGrantReadAccess'] = $ANQGrantReadAccess
}

if ($ANQDenyAccess) {
    $CmdParameters['ANQDenyAccess'] = $ANQDenyAccess
}

if ($ANQReadOnlyHosts) {
    $CmdParameters['ANQReadOnlyHosts'] = $ANQReadOnlyHosts
}

if ($ANQDenyHosts) {
    $CmdParameters['ANQDenyHosts'] = $ANQDenyHosts
}

if ($ANQFullControlHosts) {
    $CmdParameters['ANQFullControlHosts'] = $ANQFullControlHosts
}


Add-ANQSMBShare @CmdParameters
