# Azure Native Qumulo File Services (ANQ) Deployment on Nerdio Manager
<p align="center" width="100%">
    <img width="50%" src="/images/anqnerdio.png">
</p>

##  1. Purpose
The benefits and functionalities of integrating Azure Native Qumulo (ANQ) with Nerdio, focusing on streamlining business operations and eliminating performance issues. This integration simplifies operations and reduces complexity, enhancing resource allocation efficiency and leading to significant cost reductions. By providing an easy-to-maintain, comprehensive end-to-end solution, it enables quick setup and rapid deployment within minutes. 

ANQ revolutionizes cloud file storage, offering an elegant solution for demanding file-based workloads, while the seamless integration with Nerdio showcases unparalleled simplicity and a straightforward setup process within Azure Virtual Desktop. 

Additionally, the simple and predictable cost structure ensures no hidden surprises, and the outstanding performance capabilities are demonstrated through anonymized workload examples and benchmarking.

## 2. Prerequisites for ANQ
### 2.1. Creating a Dedicated Subnet for ANQ
The ANQ instance connects to your Azure subscription by using  _VNet injection_, an Azure-specific networking technology that establishes an automatic, direct connection between your resources and service resources without complicated manual configuration or  VNet peering.

VNet injection lets you:
-   Apply routing and security policies to your ANQ service endpoints by using the Azure Portal, CLI, and API.
-   Create endpoints that allow access to ANQ by inserting special network interfaces into your subnet. This process binds these network interfaces directly to the compute resources of your ANQ instance.

The service requires an owner or contributor role with access to your Azure subscription.
If you use a custom role which must have write permissions to the resource groups in which you create your  delegated subnet and service.

The ANQ service requires a dedicated subnet.

> [!NOTE]
> -   Your subnet address range should be at least  `/24`  (it should contain at least 256 IP addresses, including 251 free IP addresses and 5 IP addresses reserved for Azure.)
> -   Your subnet must be in the same region as the ANQ file system.

To apply a specific subnet configuration, you can first create a subnet and then select it when you create your ANQ instance.

1.  Identify the region in which you want to subscribe to ANQ.
    
2.  In the region, create a new virtual network or select an existing virtual network.
    
3.  In your virtual network, create a new subnet.
    
    Use the default configuration or update the subnet network configuration based on your network policy.
    
4.  Delegate the newly created subnet to  `Qumulo.Storage/fileSystems`.

### 2.2. Configuring Network Security Groups For ANQ

**Network security groups**  let administrators enforce networking traffic rules. You can assign network security groups to individual network interfaces or to entire subnets.

Because it is possible to create or remove network interfaces from an ANQ instance, we recommend assigning security groups to a delegated subnet.

To ensure that your configuration doesn’t block a specific protocol, follow the guidance in  [Required Networking Ports for Qumulo Core](https://docs.qumulo.com/azure-administrator-guide/network-configuration/required-ports.html).

### 2.3. Load-Balancing ANQ Endpoints
Qumulo provisions multiple endpoints to allow access to ANQ. Every endpoint appears in the Azure Portal as a network interface with an IP address.

To avoid the bandwidth limits of individual endpoints, use **round-robin DNS** to distribute your workload traffic across your endpoints.

There are many options for customers to manage DNS in Azure: Azure DNS, Azure Private DNS, DNS appliances such as Infoblox or BlueCat, Windows Server (traditional AD), and even BIND. Regardless of the method, Qumulo requires a Fully Qualified Domain Name (FQDN) Round Robin record resolvable by the clients to distribute them for balanced connectivity.

To ensure that client connections to your cluster are balanced evenly, you must provide a single namespace for your cluster. To do this, configure your DNS server to send a different IP address for each DNS request for your ANQ.

For example, you can set the TTL for each record to  `0`, or `1` to allow each DNS lookup for your ANQ to yield one of the configured IP addresses on ANQ.

### 2.4. Active Directory (or Entra) Account with Permissions to Join The Domain
To join an Active Directory (AD) domain, an account needs the following permissions:
-   Create computer objects in the AD domain.
-   Delete computer objects in the AD domain (if re-joining an existing computer account).
-   Reset computer accounts in the AD domain (if re-joining an existing computer account).

Typically, these permissions are granted to accounts in the "Domain Admins" or "Administrators" groups by default. However, non-administrative users can be delegated the specific permissions needed to join a computer to the domain.

### 2.5. Global Secure Variables

Nerdio Manager allows you to manage Global Secure Variables. These secure variables can be passed to scripted actions. The variables are stored securely in the Azure Key Vault and can be passed to scripted actions using the  **`$SecureVars.Variable_Name`**  variable name.

**Tip:**  This feature is especially helpful if you want to pass sensitive information to a scripted action without passing it via clear text.

To manage global secure variables:

1.  Navigate to  **Settings** > **Nerdio environment**.
    
2.  In the  **Secure variables for scripted actions**  tile, select the **Add**.
    
3.  To add a global secure variable, enter the following information:
    
    -   **Name:** Type the name of the variable. The variable name must be between 1 and 20 alphanumeric characters.
        
    -   **Value:** Type the variable's value.
        
    -   **Pass variable to specified scripted actions only**: Optionally, select this option to only pass this variable to the scripted action(s) specified. When unselected, it is passed to all scripted actions.
        
        -   **Scripted actions:** From the drop-down list, select the ANQ Deployment script.
            
> [!NOTE]
> The variable is listed in the  Secure Variables  column of each selected scripted action in the  Azure runbooks window.
            
4.  When you have entered the desired information, select  **OK**.

#### 2.5.1. Required Global Secure Variables
##### 2.5.1.1. Azure Environment Details:
|Secure Variable|Description|
|--|--|
|**ANQAzureSubsID**| Azure Subscription ID |
|**ANQAzureSubsID**|Azure Subscription ID|
|**ANQResourceGroupName** | Azure Resource Group Name |
|**ANQResourceGroupName**|Azure Resource Group Name|
|**ANQRegionName**|Azure Region Name|
|**ANQClusterZone**|Availability Zone to deploy ANQ Cluster in|
|**ANQVirtualNetwork**|Azure Virtual Network for ANQ|
|**ANQSubnet**|ANQ Subnet delegated to ANQ|

##### 2.5.1.2. ANQ Cluster Details:
|Secure Variable|Description|Details|
|--|--|--|
|**ANQAdminEmail**| ANQ Administrator Email Address |
|**ANQAdminPassword**|ANQ Administrator Password|Password must be 8-128 characters long, including at least 3 of the following: lowercase letter, uppercase letter, number, and one special character.|
|**ANQClusterName** |ANQ Cluster Name|Must be less than 16 characters|


##### 2.5.1.3. ANQ DNS Details (Required for Non-Entra Environments):
|Secure Variable|Description|
|--|--|
|**ANQDNSServerIPs**|ANQ DNS Servers if it is different than the default ones|
|**ANQDNSSearchDomains**|ANQ Search Domains|

> [!NOTE]
> The ANQ cluster needs to know how to resolve the Domain Controller names/IP addresses. Depending on the Identity topology chosen, you may need to manually update this entry. If using integrated Microsoft Entra Domain Services this is done for you.
 
 ##### 2.5.1.4. Domain Details
| Secure Variable | Description |
|--|--|
|**ANQADDomainName**| ANQ Active Directory Domain Name |
|**ANQADUsername**|ANQ Active Directory Username for AD join without the Domain Name|
|**ANQADPassword**|ANQ Active Directory password for AD join|


##### 2.5.1.5. Nerdio Details:
|Secure Variable|Description|
|--|--|
|**NerdioNMEURI**|The URI of the Nerdio Management Engine|
|**NerdioClientID**|The API scope of the Nerdio API application|
|**NerdioClientSecret**|The client secret of the Nerdio API application|

How to create a new Client Secret:
1.  Navigate to [Microsoft Entra](https://entra.microsoft.com/)
2.  Click **Applications**
3.  Click **App registrations**
4. Click **All applications**
5. Find **nerdio-nmw-app** and copy **Application (client) ID**
6. Click **nerdio-nmw-app**
7. Click **Certificates & secrets**
8. Click **New client secret**
9. Define a **Description** and set expire duration
10. Click **Add**
11. Copy the **Client Secret**

|Secure Variable|Description|
|--|--|
|**NerdioTenantID**|Nerdio Tenant ID|
|**NerdioAPIScope**|Nerdio API Scope|

How to see:
1. In Nerdio Manager, navigate to  **Settings**  > **Integrations**.
2. In the  **REST API**  tile, click  **show**  to see the credentials.
    

##### 2.5.1.6. Standard ANQ Definitions (validated on May 20, 2024):
|Secure Variable|Value|
|--|--|
|**ANQOfferID**|qumulo-saas-mpp|
|**ANQPlanID**|azure-native-qumulo-hot-cold-iops-live|
|**ANQPublisherId**|qumulo1584033880660|


## 3. Getting Started with Nerdio REST API Integration

> [!IMPORTANT]
> This feature is only available in the Nerdio Manager Premium edition.

To enable API for your Nerdio Manager installation:

1.  In Nerdio Manager, navigate to  **Settings**  > **Integrations**.
    
2.  In the  **REST API**  tile, select  **Disabled**  to **enable** it.
    
> [!NOTE]
> The process of enabling API is a multi-step process. Follow the steps below in the pop-up window once you select  Disable.
    
3.  In **Step #1**, select  **Run**.
    
    This creates a new Azure application under the  nerdio-nmw-app  app registration that currently exists in your Azure tenant.
    
4.  In **Step #2**, select  **Grant**  to navigate to your Azure portal and grant Admin consent and assign permissions to the application.
    
5.  In the Azure portal, select  **Grant admin consent for Nerdio**.
    
6.  Navigate back to **Nerdio Manager**, and select the **refresh** icon to confirm that the permissions were granted correctly.
 
7.  In **Step #3**, select  **Generate**  to generate the client secret and other details you need to make API calls.


## 4. Preparing a Hybrid Worker Group

In the current implementation of Private Link, Automation account cloud jobs cannot access Azure resources that are secured using private endpoint. For example, Azure Key Vault, Azure SQL, Azure Storage account, etc.

The user Hybrid Runbook Worker feature of Azure Automation enables you to run runbooks directly on the Azure machine. From the machine that's hosting the role, you can run runbooks directly on it and against resources in the environment to manage those local resources.

To deploy an ANQ service, you need to use a  [Hybrid Runbook Worker](https://learn.microsoft.com/en-us/azure/automation/automation-hybrid-runbook-worker)  due to that reason. 

Azure Automation provides native integration of the Hybrid Runbook Worker role through the Azure virtual machine (VM) extension framework. 

### 4.1. Deploying an Azure VM

You need to deploy an Azure VM with the below requirements before creating hybrid worker group.

##### Machine minimum requirements

-   Two cores
-   4 GB of RAM

##### Supported operating systems

- Windows Server 2022 (including Server Core)  
- Windows Server 2019 (including Server Core)  
- Windows Server 2016, version 1709, and 1803 (excluding Server Core)  

##### Other Requirements

- Windows PowerShell 5.1 (download WMF 5.1). PowerShell Core isn't supported.
- .NET Framework 4.6.2 or later.

### Create hybrid worker group

To create a hybrid worker group in the Azure portal, follow these steps:

1.  Sign in to the  [Azure portal](https://portal.azure.com/).
    
2.  Go to your Automation account which starts with *nmw-app-scripted-actions-*.
    
3.  Under  **Process Automation**, select  **Hybrid worker groups**.
    
4.  Select  **+ Create hybrid worker group**.
    
5.  From the **Basics** tab, in the  **Name**  text box, enter a name for your Hybrid worker group.
    
6.  For the  **Use Hybrid Worker Credentials**  option:
    -   If you select  **Default**, the hybrid extension will be installed using the local system account.
   
7.  Select  **Next**  to advance to the  **Hybrid workers**  tab. 
    
8.  Select  **Add machines**  to go to the  **Add machines as hybrid worker**  page. Find the VM that you deployed before.
    
9.  Select the checkbox next to the machine you want to deployed for the hybrid worker group. 
    
10.  Select  **Add**.
    
11.  Select  **Next**  to advance to the  **Review + Create**  tab.
    
12.  Select  **Create**.
    
The hybrid worker extension installs on the machine and the hybrid worker gets registered to the hybrid worker group. Adding a hybrid worker to the group happens immediately, while installation of the extension might take a few minutes. Select  **Refresh**  to see the new group. Select the group name to view the hybrid worker details.

### 4.2. Installing the Run As account certificate on the hybrid worker:

1.  Find the Azure Key vault associated with the Nerdio installation. It begins with  **nmw-app-kv-**.
    
2.  In the  **Key Vault**, select  **Certificates**.
    
3.  Select the certificate called  **nmw-scripted-action-cert**.
    
4.  Select **Download in  PFX/PEM format**.
    
> [!NOTE]
> In order to download the certificate, your user account needs permission to list/get certificates AND secrets from the key vault. See this Microsoft  [article](https://learn.microsoft.com/en-us/azure/key-vault/general/assign-access-policy?tabs=azure-portal)  for more information.
    
5.  Install the downloaded certificate on the hybrid worker VM. 
> [!NOTE]
> You can leave the password empty.

## 5. Creating an Azure Runbook

Scripted Actions are PowerShell scripts that can be used to extend and customize the functionality of Nerdio Manager. These scripts can be created and customized by the Nerdio Manager administrators. They can be applied at various stages of the Nerdio Manager automation. 
    
### 5.1. Configuring the Azure runbooks settings:

1.  Navigate to  **Settings**  >  **Nerdio environment**.
    
2.  In the  **Azure runbooks scripted actions**  tile, select  **Enabled**.
    
3.  Enter the following information:
    
    -   **Use Azure Automation Runbooks?**: Toggle this option **on**.
        
        -   ***On:*** *You can select an Azure region where an Automation Account is created to run this Runbook.*
            
    -   **Automation Account Name:** This is a unique name and is only used to run these Azure Runbooks.
        
    -   **Hybrid Worker Group:** From the drop-down list, select the hybrid worker group that you created.
        
4.  Once you have entered the desired information, select  **OK**.

### 5.2. Creating a New Scripted Action

To create a new scripted action:

1.  Navigate to  **Scripted Actions**.
    
2.  Select  **Azure runbooks**.
    
3.  Select  **Add scripted action**.
    
4.  Enter the following information:
    
    -   **Name:** Type the name of the script. This name is displayed when you select this action from the list of available scripted actions.
        
    -   **Description:** Type the script's description.
        
    -   **Tags:** From the drop-down list, select optional tags for the script. These tags are used for searching and organization.
        
    -   **Script Execution Mode:** From the drop-down list, select **Combined** execution mode.
     
        ***Combined:** Marks the script as one that can be combined safely with other scripts. For example, a script that adds a registry value.*

            
    -   **Script:** Download the PowerShell script for ANQ deployment from the [Qumulo GitHub](https://github.com/Qumulo/NerdioRunbooks/) repo.
        
> [!NOTE]
> Nerdio Manager allows you to integrate variables into the Azure runbooks scripted actions. The ANQ deployment script has the required variables and secure variables.
        
5.  Once you have entered all the desired information, select  **Save & close**.

## 6. Running the Azure Runbook

To create a new scripted action:

1.  Navigate to  **Scripted Actions**.
    
2.  Select  **Azure runbooks**.
    
3.  Find the **ANQ - Deploy Infrastructure** runbook.
4. Select **Run / schedule** on the **Edit** menu.
5. Select your **Azure Subscription**
6. Define the below Variables.

##### Cluster Definitions
|Variable|Value|Details|
|--|--|--|
|ANQAdminEmail|ANQ Administrator Email Address|
|ANQAdminPassword|ANQ Administrator Password|You can define a SecureVariable and select here or you can define here.
|ANQClusterName|ANQ Cluster Name|Must be less than 16 characters|
|ANQStorageSKU|ANQ Storage SKU| Hot or Cold|
|ANQInitialCapacity|ANQ Initial Capacity in TB||

##### SMB Share Definitions
|Variable|Value|
|--|--|
|ANQInternalTenantID|ANQ Internal Tenant ID for the SMB share|
|ANQProfileShareName|ANQ Profile share name (SMB share)|
|ANQFSPath|ANQ File System Path|
|ANQShareDescription|ANQ Share Description|

##### SMB Share Permissions
|Variable|Value|
|--|--|
|ANQGrantReadAccess|ANQ Grant Read Access|
|ANQGrantReadWriteAccess|ANQ Grant Read Write Access|
|ANQGrantAllAccess|ANQ Grant All Access|

> [!NOTE]
> Don't use the domain name

## 6. Troubleshooting

### 6.1. Troubleshooting The Azure Runbook
Azure runbooks have enhanced logs that help you troubleshoot issues with scripted actions.

To view the Azure runbook logs:

1.  Navigate to  **Scripted Actions**  > **Azure runbooks**.
    
2.  At the bottom of the window, in the  **Scripted Actions Tasks**  section, locate the task with an  **Error** in the  **Status** column.
    
3.  Select  **Details**.
    
4.  Locate the entry in the log with an error.
    
5.  In the  **Output** section, select any of the following:
    
    -   **Show:** Select  Show  to display the standard Azure automation account runbook output.
        
    -   **Exception:** Select  Exception  to display the exception's details.

### 6.2. Troubleshooting FSLogix With frxtray Application

The FSLogix **frxtray** application is a system tray tool designed to provide visibility and troubleshooting capabilities for FSLogix profiles and can be vital in troubleshooting FSLogix UNC connection related issues.

The **frxtray** tool is vital for managing FSLogix profiles, providing essential monitoring and troubleshooting capabilities to ensure smooth operation and quick resolution of any issues that arise.

#### Features and benefits of frxtray:

**1.  Status Monitoring:**
-   The **frxtray** tool uses a traffic light system to display the status of FSLogix profiles. A green light indicates an active profile, while a yellow light indicates an inactive profile, which can help quickly identify issues such as when a local profile exists instead of an FSLogix profile​.

**2.  Access to Logs:**
-   By double-clicking the **frxtray** icon in the system tray, you can access the profile logs, which provide detailed information about the profile status and any errors encountered. This is particularly useful for diagnosing issues with profile loading and connectivity​.

**3. Advanced View:**
-   The tool includes an advanced view option, allowing deeper inspection of the profile configuration and status. This can be helpful for IT administrators needing to troubleshoot more complex issues​.

#### Location and Setup:
-   The **frxtray** application is typically installed at *C:\Program Files\FSLogix\Apps\frxtray.exe* if the default installation path is used. It's part of the standard FSLogix client installation and can be set up to start automatically for all users by placing it in the startup folder​.


## References

 - [Reference Architecture – Multi-Region Azure Native Qumulo and Azure Virtual Desktop](https://qumulo.com/resources/reference-architecture-multi-region-azure-native-qumulo-and-azure-virtual-desktop/)
 -   [Microsoft Configuration Setting Reference](https://learn.microsoft.com/en-us/fslogix/reference-configuration-settings?tabs=profiles)
-   [Nerdio's FSLogix Settings and Configuration](https://nmw.zendesk.com/hc/en-us/articles/4731655270167-FSLogix-Settings-and-Configuration)
-   [Connecting Azure Native Qumulo to Microsoft Entra Domain Services](https://docs.qumulo.com/azure-administrator-guide/getting-started/connecting-azure-native-qumulo-to-microsoft-entra-domain-services.html)
-   [Azure Native Qumulo Administrator Guide](https://docs.qumulo.com/azure-administrator-guide/)

## Additional Documents
- [What is Azure Native Qumulo Scalable File Service?](https://learn.microsoft.com/en-us/azure/partner-solutions/qumulo/qumulo-overview)
- [Azure Native Qumulo Scalable File Service (Marketplace)](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/qumulo1584033880660.qumulo-saas-mpp?exp=ubp8&tab=Overview)
- [Azure Native Qumulo Pricing](https://qumulo.com/product/azure/pricing/)
- [Azure Native Qumulo - Pricing and Performance Calculator](https://azure.qumulo.com/calculator)

## Help

To post feedback, submit feature ideas, or report bugs, use the [Issues](https://github.com/Qumulo/NerdioRunbooks/issues) section of this GitHub repo.

## Copyright

Copyright © 2024 [Qumulo, Inc.](https://qumulo.com)

## License

[![License](https://img.shields.io/badge/license-MIT-green)](https://opensource.org/licenses/MIT)

See [LICENSE](LICENSE) for full details

    MIT License
    
    Copyright (c) 2022 Qumulo, Inc.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

## Trademarks

All other trademarks referenced herein are the property of their respective owners.

## Contributors
 - [Berat Ulualan](https://github.com/beratulualan)
 - [Kevin McDonald](https://github.com/qumulokmac)
