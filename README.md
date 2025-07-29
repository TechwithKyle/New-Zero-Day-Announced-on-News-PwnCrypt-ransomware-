<img width="1000" height="450" alt="image" src="https://github.com/user-attachments/assets/e00a464d-d4c5-4934-98e7-8d6f0f02ea2a" />


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

A new ransomware strain named PwnCrypt has been reported in the news, leveraging a
PowerShell-based payload to encrypt files on infected systems. The payload, using AES-256
encryption, targets specific directories such as the C:\Users\Public\Desktop, encrypting files and
prepending a .pwncrypt extension to the original extension. For example, hello.txt becomes
hello.pwncrypt.txt after being targeted with the ransomware. The CISO is concerned with the
new ransomware strain being spread to the corporate network and wishes to investigate.

---

## Timeline Summary and Findings 

A search of DeviceFileEvents in Microsoft Defender for Endpoint (MDE) revealed multiple instances of files being renamed and recreated with a .pwncrypt extension prepended to the original file name (e.g., example.pwncrypt.csv). Additionally, a ransom note (decryption-instructions.txt) was discovered, indicating ransomware was executed and file encryption had occurred.

**Query used to locate events:**

```kql
let VMName = "kylesvm"; DeviceFileEvents
| where DeviceName == VMName
| order by Timestamp desc
```

<img width="1501" height="1131" alt="image" src="https://github.com/user-attachments/assets/cf7ba25d-3593-49fb-8d53-2d5f1bb58167" />


---

The ransomware was most likely executed via PowerShell scripts, triggered through a chain involving explorer.exe launching senseir.exe, which then invoked cmd.exe and powershell.exe with repeated use of the -ExecutionPolicy Bypass and AllSigned flags. This pattern is highly consistent with scripted ransomware delivery and execution.
Evidence suggests that the initial access vector was a manually launched executable, senseir.exe, named "OfflineSenseIR", indicating likely delivery via phishing or removable media.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "kylesvm"
| where Timestamp > ago(1d)
| where ProcessCommandLine contains "pwncrypt" or FileName in~ ("powershell.exe", "cmd.exe") | project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

<img width="1504" height="833" alt="image" src="https://github.com/user-attachments/assets/3b19311d-c718-4476-800c-70caf02b2fd7" />

---

During the threat hunt triggered by ransomware IOCs I investigated potential outbound communication with malicious infrastructure. Using MDE’s DeviceNetworkEvents and found that the infected device kylesvm initiated multiple outbound SSL connections over port 443. These IPs were contacted repeatedly using SSL-inspected sessions. This activity suggests possible command-and-control (C2) communication as part of the pwncrypt ransomware behavior.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "kylesvm"
| where Timestamp > ago(1d)
| where RemotePort == 443
| project Timestamp, RemoteIP, RemotePort, RemoteURL, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

<img width="756" height="380" alt="image" src="https://github.com/user-attachments/assets/30d7b7fb-7e8c-4812-b953-970c5498b3c7" />


---

## Response

● Immediately isolate kylesvm from the network.
    Prevents lateral movement
    Blocks ongoing exfiltration or communication with C2 servers
● Kill the parent process via Live Response
    Identifies malicious processes (e.g., Powershell or senseir.exe)
    Terminate the process that's actively encrypting files and downloading payloads
● Collect forensic artifacts (memory dump, process tree, script paths, and command history)
    This helps understand how the ransomware was delivered and executed
    Useful for post-incident analysis and possibly reversing the payload
    May contain keys and decryption methods in memory
● Restore affected files from backups (if available)
● Scan for persistence in Startup folders, ScheduledTasks, and Registry Run keys

---

## MITRE ATT&CK Framework and TTPs:

T1059.001 – Command and Scripting Interpreter: PowerShell
PowerShell was used extensively with -ExecutionPolicy Bypass -File, showing scripted execution of the ransomware payload.

T1059.003 – Command and Scripting Interpreter: CMD
Ransomware was launched via cmd.exe /c powershell.exe, a common pattern for chained execution from user-launched binaries or scripts.

T1204.002 – User Execution: Malicious File
The executable senseir.exe was manually launched by the user via explorer.exe, indicating likely delivery
through phishing or file drop.

T1027 – Obfuscated Files or Information
Use of PowerShell with execution policy bypass indicates an attempt to evade traditional script blocking and logging.

T1486 – Data Encrypted for Impact
Multiple files were renamed and recreated with .pwncrypt in the name, confirming encryption activity consistent with ransomware.

T1490 – Inhibit System Recovery
cmd.exe executed commands to delete contents from AppData folders using /q /c del /q, indicating an effort to disrupt recovery or forensic analysis.

T1071 – Application Layer Protocol (SSL):
The use of cmd.exe and powershell.exe to bypass execution policies is a tactic associated with execution and command-and-control over application-layer protocols.

