<img width="200" src="https://img.icons8.com/color/96/000000/spider.png" alt="Latrodectus Spider Malware"/>

# Threat Hunt Report: Latrodectus Stealthy Loader Campaign
- [Scenario Creation](link-to-scenario-creation-page)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Phishing email simulation platform
- Latrodectus malware loader (simulated)

## Scenario

Security analysts have detected suspicious email activity and potential malware infections targeting employees in North America. Intelligence reports indicate that the Lunar Spider threat group is conducting a campaign using Latrodectus, a sophisticated stealthy loader that deploys ransomware and infostealers through phishing emails. The malware employs advanced evasion techniques to avoid detection and establishes persistent command & control communications.

Recent email security alerts have flagged suspicious attachments and links, while network monitoring has identified unusual encrypted traffic patterns consistent with command & control communications. Additionally, there have been reports of system performance issues and unexpected network activity that could indicate active malware infections.

### High-Level Latrodectus Discovery Plan

- **Check `EmailEvents`** for any suspicious phishing emails with malicious attachments or links.
- **Check `DeviceFileEvents`** for any downloaded malicious payloads or loader components.
- **Check `DeviceProcessEvents`** for any signs of stealthy loader execution and payload deployment.
- **Check `DeviceNetworkEvents`** for any command & control communications or data exfiltration attempts.

---

## Steps Taken

### 1. Searched the `EmailEvents` Table for Phishing Campaign

Searched for suspicious email activity that could be part of the Latrodectus phishing campaign. Discovered that user "labuser" on device "abe-mde-est" received a malicious email at `2025-06-03T09:15:22.4567891Z` with the subject "Urgent: Invoice Payment Required" containing a weaponized attachment `invoice_details.zip` that served as the initial infection vector.

**Query used to locate events:**

```kql
EmailEvents
| where RecipientEmailAddress == "labuser@company.com"
| where Subject contains_any ("Invoice", "Payment", "Urgent", "Document", "Report")
| where AttachmentCount > 0
| where ThreatTypes has_any ("Malware", "Phish")
| project Timestamp, SenderFromAddress, Subject, AttachmentCount, AttachmentNames, ThreatTypes, DeliveryAction
| order by Timestamp desc
```

---

### 2. Searched the `DeviceFileEvents` Table for Loader Deployment

Searched for file creation events that could indicate Latrodectus loader deployment on the endpoint. Evidence was found at `2025-06-03T09:18:45.7891234Z` showing the creation of suspicious files including `svchost.exe` in an unusual location and `config.dat` which appeared to be loader configuration data, indicating successful initial compromise.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "abe-mde-est"
| where InitiatingProcessAccountName == "labuser"
| where FileName in ("svchost.exe", "config.dat", "loader.dll", "update.exe")
| where FolderPath !startswith "C:\\Windows\\System32\\"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
| order by Timestamp desc
```

---

### 3. Searched the `DeviceProcessEvents` Table for Stealthy Execution

Searched for process execution events that could reveal Latrodectus loader activity and payload deployment. The investigation uncovered suspicious process execution at `2025-06-03T09:20:15.1357924Z` where a fake `svchost.exe` process was launched from `C:\Users\labuser\AppData\Local\Temp\` with command line arguments indicating loader functionality and subsequent payload injection.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "abe-mde-est"
| where FileName in ("svchost.exe", "rundll32.exe", "regsvr32.exe", "powershell.exe")
| where FolderPath contains_any ("Temp", "AppData", "Downloads")
| where ProcessCommandLine contains_any ("inject", "load", "execute", "decode", "decrypt")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, ParentProcessName
| order by Timestamp desc
```

---

### 4. Searched the `DeviceNetworkEvents` Table for Command & Control Communications

Searched for network connections that could indicate Latrodectus command & control communications and data exfiltration. Evidence was discovered of encrypted communications to suspicious IP address `185.243.96.200` on port `443` beginning at `2025-06-03T09:25:30.2468135Z`, with regular beaconing patterns consistent with malware C2 traffic and potential credential exfiltration.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "abe-mde-est"
| where RemoteIP !startswith "10.0."
| where RemotePort in ("443", "80", "8080", "8443")
| where InitiatingProcessFileName in ("svchost.exe", "explorer.exe", "chrome.exe")
| where RemoteIP in ("185.243.96.200", "203.0.113.75", "198.51.100.42")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

---

### 5. Searched the `DeviceRegistryEvents` Table for Persistence Mechanisms

Searched for registry modifications that could indicate Latrodectus persistence establishment and system manipulation. Registry changes were detected at `2025-06-03T09:22:45.9753186Z` including new Run key entries and service installations designed to maintain persistence across system reboots and evade detection by security tools.

**Query used to locate events:**

```kql
DeviceRegistryEvents
| where DeviceName == "abe-mde-est"
| where RegistryKey contains_any ("Run", "Services", "Winlogon", "Policies")
| where RegistryValueName contains_any ("svchost", "update", "loader", "system")
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```

---

## Chronological Event Timeline

### 1. Initial Infection - Phishing Email Delivery
- **Timestamp:** `2025-06-03T09:15:22Z`
- **Event:** User "labuser" received malicious phishing email with subject "Urgent: Invoice Payment Required" containing weaponized attachment `invoice_details.zip` as part of Latrodectus campaign.
- **Action:** Phishing email delivery successful.
- **Attachment:** `invoice_details.zip` containing Latrodectus loader
- **Sender:** `accounting@legitimate-company.org` (spoofed domain)

### 2. User Interaction - Malicious Attachment Execution
- **Timestamp:** `2025-06-03T09:17:30Z`
- **Event:** User "labuser" on device "abe-mde-est" extracted and executed the malicious attachment, triggering initial Latrodectus loader deployment.
- **Action:** Malware execution initiated.
- **File Executed:** `invoice_details.exe` (disguised as document)
- **Execution Context:** User-initiated from Downloads folder

### 3. Loader Deployment - File System Manipulation
- **Timestamp:** `2025-06-03T09:18:45Z`
- **Event:** Latrodectus loader created multiple files on the system including fake `svchost.exe` in user directory and configuration files for persistence and payload management.
- **Action:** Malware installation detected.
- **Files Created:** `C:\Users\labuser\AppData\Local\Temp\svchost.exe`, `config.dat`, `loader.dll`
- **SHA256:** `a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456`

### 4. Process Injection - Stealthy Execution
- **Timestamp:** `2025-06-03T09:20:15Z`
- **Event:** Latrodectus loader executed process injection techniques, launching fake `svchost.exe` process with command line arguments indicating payload decryption and injection capabilities.
- **Action:** Process hollowing and injection detected.
- **Process:** `svchost.exe` (fake)
- **Command Line:** `svchost.exe -decode -inject explorer.exe`
- **Parent Process:** `explorer.exe`

### 5. Persistence Establishment - Registry Modification
- **Timestamp:** `2025-06-03T09:22:45Z`
- **Event:** Registry modifications detected on device "abe-mde-est" establishing persistence through Run key entries and service installations to survive system reboots.
- **Action:** Persistence mechanism installation.
- **Registry Key:** `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- **Value Name:** `SystemUpdate`
- **Value Data:** `C:\Users\labuser\AppData\Local\Temp\svchost.exe -silent`

### 6. Command & Control - Network Communications
- **Timestamp:** `2025-06-03T09:25:30Z`
- **Event:** Encrypted network connections established to external command & control server at IP `185.243.96.200` on port `443`, initiating regular beaconing pattern for remote control capabilities.
- **Action:** C2 communication established.
- **Remote IP:** `185.243.96.200`
- **Communication Pattern:** HTTPS beaconing every 5 minutes
- **Data Transfer:** Encrypted payload downloads and system information exfiltration

### 7. Payload Deployment - Infostealer Installation
- **Timestamp:** `2025-06-03T09:30:45Z`
- **Event:** Secondary payload deployment detected as Latrodectus loader downloaded and executed credential stealing components targeting browser data, cryptocurrency wallets, and stored passwords.
- **Action:** Infostealer deployment confirmed.
- **Payload Type:** Credential harvesting module
- **Target Data:** Browser cookies, saved passwords, cryptocurrency wallet files
- **Exfiltration Method:** HTTPS POST to C2 infrastructure

### 8. Anti-Analysis Evasion - Security Tool Bypass
- **Timestamp:** `2025-06-03T09:35:20Z`
- **Event:** Latrodectus implemented evasion techniques including sandbox detection, security tool enumeration, and process name masquerading to avoid detection by security solutions.
- **Action:** Evasion techniques activated.
- **Techniques:** Process hollowing, name masquerading, sandbox evasion
- **Target Processes:** Security tools, analysis environments, monitoring solutions

---

## Summary

The investigation on device "abe-mde-est" revealed a sophisticated Latrodectus stealthy loader campaign targeting user "labuser" through a well-crafted phishing email. The attack demonstrated advanced evasion techniques including process injection, registry persistence, and encrypted command & control communications. The malware successfully established persistence, deployed credential stealing payloads, and maintained covert communications with external infrastructure. Evidence suggests the attack was part of a larger campaign by the Lunar Spider threat group targeting North American organizations with multi-stage malware deployment.

---

## Response Taken

The device "abe-mde-est" was immediately isolated from the network to prevent further C2 communications and lateral movement. The malicious `svchost.exe` process was terminated and all related files quarantined. Registry persistence mechanisms were removed and the user account was secured. Command & control IP addresses were blocked at the network perimeter and threat intelligence was updated with campaign indicators.

---
