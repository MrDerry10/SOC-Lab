
# Mini Honeynet in Azure with Microsoft Sentinel
### Project Overview
This project demonstrates the creation of a mini honeynet within Microsoft Azure to detect, analyze, and respond to potential attacks. Logs from various resources were ingested into a Log Analytics Workspace, which was then utilized by Microsoft Sentinel for building attack maps, triggering alerts, and creating security incidents. The project involved a two-phase analysis of the environment—before and after applying security controls—and measured key security metrics to assess the effectiveness of these controls.

## Key Objectives
- Build and configure a honeynet in Microsoft Azure.
- Ingest logs into a Log Analytics Workspace for centralized monitoring.
- Use Microsoft Sentinel to detect malicious activity through alerts and incidents.
- Measure and compare security metrics in both insecure and secure states.

## Metrics Collected
- During the experiment, the following data points were gathered:
- **SecurityEvent:** Windows event logs.
- **Syslog:** Linux event logs.
- **SecurityAlert:** Alerts triggered within the Log Analytics Workspace.
- **SecurityIncident:** Incidents created by Microsoft Sentinel based on detected threats.
- **AzureNetworkAnalytics_CL:** Malicious network traffic and flows allowed into the honeynet.

## Architecture
The honeynet infrastructure was designed with the following components:
- **Virtual Network (VNet):** Isolated environment for hosting resources.
- **Network Security Group (NSG):** Controls incoming and outgoing traffic.
- **Virtual Machines:** Two Windows servers and one Linux server simulate typical targets.
- **Log Analytics Workspace:** Centralized platform for log ingestion and analysis.
- **Azure Key Vault:** Secure storage for sensitive data such as keys and secrets.
- **Azure Storage Account:** Stores logs and other data persistently.
- **Microsoft Sentinel:** Security Information and Event Management (SIEM) tool used for monitoring, alerting, and incident response.

## Project Phases
**1. Insecure Environment (Initial State)**

- The honeynet was first deployed without any hardening or security controls. Turning off the firewalls and removing network policies exposing it to the internet to attract attackers. 
- Logs were collected over a 24-hour period, measuring the amount of malicious activity, alerts, and incidents triggered.
- **Objective:** Understand the threats and vulnerabilities in an unsecured network.

  # Attack maps Before Hardening / security controls
![Screenshot 2024-10-09 191946](https://github.com/user-attachments/assets/1b555cf9-e12e-430b-a9fa-96e993165105)
![Screenshot 2024-10-09 231721](https://github.com/user-attachments/assets/d999bcbf-8366-45cb-9c5c-0e1051686a62)
![Screenshot 2024-10-09 192012](https://github.com/user-attachments/assets/1fd7fa29-aa47-455f-8aa0-dfdff712c236)


  

## Secured Environment (Post-Security Controls)

- After the initial data collection, security controls were implemented to harden the environment, including firewall rules and stricter access policies.
- Logs were collected for an additional 24 hours, and a significant reduction in security events and incidents was observed.
- **Objective:** Assess the effectiveness of the security controls by comparing pre- and post-control metrics.

![image](https://github.com/user-attachments/assets/accbabfd-28db-47e4-9755-5176f162d20a)
![Screenshot 2024-10-09 204152](https://github.com/user-attachments/assets/4b825a82-79db-458b-93e0-51a322b03964)
![Screenshot 2024-10-09 162324](https://github.com/user-attachments/assets/93aad209-f386-4501-9485-9addab449d66)

### Firewall Implementation for Secure Subnet and Policies

In this section, a firewall was implemented using Azure Firewall and Network Security Groups (NSGs) to control traffic, block malicious IP addresses, and secure the subnet. The following summarizes the key configuration steps and their effects:

| Step                                   | Description                                                       | Effect/Result                                                       |
|----------------------------------------|-------------------------------------------------------------------|---------------------------------------------------------------------|
| **Create Virtual Network and Subnet**  | Set up a secure VNet with a dedicated subnet for resources.        | Isolates resources for controlled access.                          |
| **Azure Firewall Setup**               | Deployed Azure Firewall with a public IP for traffic control.     | Filters inbound and outbound traffic to block malicious flows.     |
| **Firewall Rules (Allow HTTP/HTTPS)**  | Allowed only HTTP/HTTPS traffic to access the subnet.             | Only authorized web traffic is allowed into the environment.       |
| **Deny Malicious IPs**                 | Blocked specific known malicious IP ranges using firewall rules.  | Prevents unwanted or malicious connections from entering.          |
| **Network Security Group (NSG) Rules** | Applied inbound and outbound NSG rules to restrict access.       | Limits access to only authorized IPs, reducing exposure.          |
| **Logging and Monitoring**             | Enabled diagnostic logging for traffic analysis.                  | Provides visibility into network traffic, enabling proactive detection of threats. |

## Results
The implementation of security controls had a substantial impact on the security of the network:

- **Reduction in Malicious Activity:** Fewer SecurityEvents and Syslog alerts were generated after applying firewall rules and policies.
- **Fewer Incidents:** Microsoft Sentinel created fewer incidents, indicating that the environment became more secure.
- **Enhanced Visibility:** By ingesting logs from multiple sources, it was possible to track malicious flows and analyze how attacks were mitigated.

# Attack map after Hardening / security controls
![image](https://github.com/user-attachments/assets/c6213f14-74cf-4b53-9f6d-2053876913a0)

**All queries produced no results due to no instances of malicious activity for the 24 hours period after hardening**

# Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:

### Before and After Security Hardening

| Metric                                      | Before Count | 
|---------------------------------------------|--------------|
| **SecurityEvent (Windows VMs)**             | 8563       | 
| **Syslog (Linux VMs)**                      | 1025          | 
| **SecurityAlert (Microsoft Defender)**      | 15            |
| **SecurityIncident (Sentinel Incidents)**    | 134         | 
| **AzureNetworkAnalytics_CL (Malicious Flows)** | 985       | 
| **Failed Login Attempts (Windows VMs)**     | 320          | 
| **Suspicious Network Traffic (Linux VMs)**  | 115          | 
| **Malicious IP Addresses Blocked (Azure Firewall)** | 15   |
| **Unusual File Changes (Windows/Linux)**    | 90           | 
| **Brute Force Attack Attempts (Kali Linux)**| 250          | 


**Start Time:** 2024-04-13 13:53:48  
**Stop Time:** 2024-04-14 13:53:48


# Metrics after Hardening / security controls
The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
| Start Time 2024-04-15 11:50:28
| Stop Time 2024-04-16 11:50:28

### Metrics Collected

| Metric                                      | After Count | 
|---------------------------------------------|--------------|
| **SecurityEvent (Windows VMs)**             | 3894       | 
| **Syslog (Linux VMs)**                      | 6         | 
| **SecurityAlert (Microsoft Defender)**      | 0            |
| **SecurityIncident (Sentinel Incidents)**    | 0        | 
| **AzureNetworkAnalytics_CL (Malicious Flows)** | 0       | 
| **Failed Login Attempts (Windows VMs)**     | 50          | 
| **Suspicious Network Traffic (Linux VMs)**  | 8          | 
| **Malicious IP Addresses Blocked (Azure Firewall)** | 120   |
| **Unusual File Changes (Windows/Linux)**    | 20           | 
| **Brute Force Attack Attempts (Kali Linux)**| 15          | 


## Change

### Before and After Security Hardening

| Metric                                      | Before Count | After Count | Percentage Change |
|---------------------------------------------|--------------|-------------|--------------------|
| **SecurityEvent (Windows VMs)**             | 7671         | 3894        | -49.1%             |
| **Syslog (Linux VMs)**                      | 833          | 6           | -99.2%             |
| **SecurityAlert (Microsoft Defender)**      | 4            | 0           | -100%              |
| **SecurityIncident (Sentinel Incidents)**    | 59           | 0           | -100%              |
| **AzureNetworkAnalytics_CL (Malicious Flows)** | 620        | 0           | -100%              |
| **Failed Login Attempts (Windows VMs)**     | 320          | 50          | -84.4%             |
| **Suspicious Network Traffic (Linux VMs)**  | 115          | 8           | -93%               |
| **Malicious IP Addresses Blocked (Azure Firewall)** | 15    | 120         | +700%              |
| **Unusual File Changes (Windows/Linux)**    | 90           | 20          | -77.8%             |
| **Brute Force Attack Attempts (Kali Linux)**| 250          | 15          | -94%               |



**Note:** In a more heavily utilized production environment, additional security events and alerts could be generated, offering further insights into potential risks and defenses.

## Conclusion
This project highlights the importance of applying layered security measures to cloud environments. By comparing the metrics from an insecure to a secured state, the effectiveness of the implemented security controls was clearly demonstrated. Microsoft Sentinel proved to be a valuable tool in identifying, analyzing, and responding to potential threats in real-time.

### KQL Queries

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Start/Stop Time                              | range x from 1 to 1 step 1<br>\| project StartTime = ago(24h), StopTime = now()                                                                  |
| Security Events (Windows VMs)                | SecurityEvent<br>\| where TimeGenerated>= ago(24h)<br>\| count                                                                                   |
| Syslog (Linux VMs)                           | Syslog<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                                         |
| SecurityAlert (Microsoft Defender for Cloud) | Security Alert<br>\| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"<br>\| where TimeGenerated >= ago(24h)<br>\| count |
| Security Incident (Sentinel Incidents)       | SecurityIncident<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                               |
| NSG Inbound Malicious Flows Allowed          | AzureNetworkAnalytics_CL<br>\| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0<br>\| where TimeGenerated >= ago(24h)<br>\| count    |
