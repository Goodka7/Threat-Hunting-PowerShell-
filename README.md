<img width="300" src="https://github.com/user-attachments/assets/9c09c98f-0e0f-40f4-a921-696b5fd7e44e" alt="Red PowerShell logo"/>

# Threat Hunt Report: Suspicious PowerShell Activity
- [Scenario Creation](https://github.com/Goodka7/Threat-Hunting-PowerShell-/blob/main/resources/Threat-Hunt-Event(PowerShell).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell

##  Scenario

Management is concerned about potential misuse of PowerShell to execute malicious commands or disable security features. Recent security logs indicate irregular PowerShell execution patterns, including encoded commands and the disabling of security tools. The goal is to detect suspicious PowerShell usage, such as obfuscated scripts or unauthorized execution of system commands, and analyze any related security incidents. If any suspicious activity is identified, notify management for further investigation.

### High-Level PowerShell Discovery Plan

- **Check `DeviceProcessEvents`** for PowerShell processes executed in a suspicious manner (e.g., via`cmd.exe`, `rundll32.exe`).
- **Check `DeviceNetworkEvents`** for any network activity involving suspicious external requests (e.g., file download attempts using `Invoke-WebRequest`).
- **Check `DeviceFileEvents`** any new or suspicious file creations in temporary directories (e.g., `C:\Windows\Temp\FakeMalware`).
- **Check `DeviceRegistryEvents`** for unusual changes, particularly in execution policies or PowerShell-related settings.
---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

Searched for any process that had "cmd.exe", "rundll32.exe", "powershell_ise.exe" or "powershell.exe" in the command line. 

The dataset reveals 88 records of process activity on the device "hardmodevm", by user "labuser" predominantly involving powershell.exe (47 instances) and cmd.exe (22 instances as initiating processes). Frequent use of PowerShell commands includes flags like -NoProfile, -NonInteractive, and -ExecutionPolicy Bypass, often triggered via cmd.exe or gc_worker.exe, suggesting possible script automation or suspicious activity. Initiating processes such as WindowsAzureGuestAgent.exe and timestamps concentrated on Jan 25, 2025, further indicate repeated execution patterns. These observations suggest potentially unauthorized or automated operations warranting deeper investigation.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("cmd.exe", "rundll32.exe", "powershell_ise.exe", "powershell.exe")
| where DeviceName == "hardmodevm"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/e5e5fee9-fa90-403b-aed5-4553926bf119">

---

### 2. Searched the `DeviceNetworkEvents` Table

Searched for any connections that contained the commands "Invoke-WebRequest", "-Uri" and "http". 

The dataset reveals network activity originating from "hardmodevm", user "labuser", with notable connections initiated by powershell.exe using commands that include -ExecutionPolicy Bypass. External requests were made to URLs such as raw.githubusercontent.com, associated with IP addresses 185.199.108.133 and 185.199.111.133, both of which are commonly used to host scripts or files. These connections occurred over HTTPS (port 443) and were marked as successful (ConnectionSuccess). The combination of PowerShell usage with potentially suspicious URLs highlights activity that may involve downloading or executing external scripts, warranting further investigation.

**Query used to locate event:**

```kql
DeviceNetworkEvents
| where DeviceName == "hardmodevm"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
      or InitiatingProcessCommandLine contains "-Uri"
      or RemoteUrl has "http"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/926684fe-1507-4af8-abc5-3c8d466f3de2">

---

### 3. Searched the `DeviceFileEvents` Table

Searched for any new or suspicious file creations in temporary directories.

The dataset reveals evidence of the execution of `payload.ps1`, with several temporary files created in the directory `C:\Users\labuser\AppData\Local\Temp\`. Files such as `__PSScriptPolicyTest_xp01hqvv.wby.ps1` were generated during the execution of `powershell.exe` and `powershell_ise.exe`, both of which used the `-ExecutionPolicy Bypass` parameter. These actions are marked as `FileCreated`, confirming that the payload execution resulted in temporary script files being generated. This activity indicates successful script execution with potentially bypassed security policies, warranting further investigation into the impact of these temporary files.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "hardmodevm"
| where FolderPath startswith "C:\\Windows\\Temp\\" or FolderPath contains "\\Temp\\"
| where FileName endswith ".exe" or FileName endswith ".ps1"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/fc3c072b-e1e1-43c7-862c-6dce9f305d5c">

---

### 4. Searched the `DeviceRegistryEvents` Table

Searched for unusual changes, particularly in execution policies or PowerShell-related settings.

The data highlights changes on hardmodevm involving keys related to both PowerShell and general system configurations. Notably, registry keys such as HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates and HKEY_CURRENT_USER\S-1-5-21...WindowsPowerShell\v1.0\powershell.exe were altered, with actions including RegistryValueSet and RegistryKeyCreated. These changes were initiated by processes like svchost.exe and explorer.exe. 

While no direct link to altered execution policies was found, the involvement of PowerShell-related keys and potentially suspicious value modifications like Microsoft Corporation suggests configuration changes that might impact system behavior. These events warrant further review to determine their relationship with recent payload execution and possible security implications.

**Query used to locate events:**

```kql
DeviceRegistryEvents
| where DeviceName == "hardmodevm"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated", "RegistryKeyDeleted")
| where RegistryKey contains "PowerShell" 
      or RegistryKey contains "Microsoft"
      or RegistryKey contains "Policies"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueType, RegistryValueData, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/fbce844e-8ebd-40ad-96e0-49d0ddae1ce8">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Time:** `3:29:50 PM, January 20, 2025`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.4.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe`

### 2. Process Execution - TOR Browser Installation

- **Time:** `3:30:55 PM, January 20, 2025`
- **Event:** The user "labuser" executed the file `tor-browser-windows-x86_64-portable-14.0.4.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `cmd.exe /c powershell.exe -ExecutionPolicy Bypass -Command "Start-Process \"C:\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe\" -ArgumentList '/S' -NoNewWindow -Wait".`
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Time:** `3:42:26 PM to 3:42:49 PM, January 20, 2025`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Time:** `3:43:03 PM, January 20, 2025`
- **Event:** A network connection to IP `45.21.116.144` on port `9001` by user "labuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Time:** `3:43:36 PM, January 20, 2025` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Time:** `3:51 to 3:55 PM, January 20, 2025`
- **Event:** The user "labuser" created a folder named `tor-shopping-list` on the desktop, and created several files with names that are potentially related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list`

---

## Summary

The user "labuser" on the device "hardmodevm" installed and used the Tor Browser, taking actions that raised concerns. First, "labuser" silently initiated the installation of the Tor Browser through a PowerShell command. After the installation, they created the "tor.exe" file and executed it, which started the Tor service with specific configurations. Additionally, multiple instances of "firefox.exe" associated with the Tor Browser were launched, and the user successfully connected to the Tor network, accessing a remote IP and URL, suggesting the use of Tor for anonymous browsing. Furthermore, a folder (tor-shopping-list) containing several .txt and .json files was created, holding several files with names indicating potential illicit activity. These actions suggest that the user may have been engaging in suspicious or unauthorized activities using the Tor network.

---

## Response Taken

TOR usage was confirmed on the endpoint `hardmodevm` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
