# Enumeration and privilege escalation on Windows

> In the previous chapter we covered aspects of enumeration of a Linux machine once we have access. We explored users, processes, the file system for the information and software it has on it and the computer itself. In this chapter we will look at a Windows environment. The enumeration principles are the same, however there are differences in the details of accounts, file systems and the way processes run. There are important differences also between machines that operate in a standalone fashion and those that are administered as part of a collection of computers in an Active Directory Domain.

## Windows Accounts and User Privileges

Windows has a number of different types of accounts. On a single machine where all of the accounts are local accounts, the types are Administrator, Standard and Guest. The difference between Administrator and a Standard user is in what files and folders they can access on the machine and what actions they can take, like installing software, stopping and starting services and other systems administrative tasks.

File permissions are controlled differently from the simple read, write, execute permissions of Linux. Windows sets permissions on folders and files that allow users, or the groups they belong to, modify, read and execute, list folder contents, and read and write data. There are some other permissions relating to controlling who can access attributes and permissions themselves.

What a user can do is controlled also by user rights. These are privileges that allow users to do specific tasks such as back up files and directories which is controlled by the SeBackupPrivilege or debug programs which is SeDebugPrivilege. We can list the privileges on an account in several ways. The command whoami /priv will list the privileges set on a user and whether they are disabled or enabled:

```bash
c:\Users\rin>whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name Description State
============================= =============================== ========
SeShutdownPrivilege           Shut down the system            Disabled
SeChangeNotifyPrivilege       Bypass traverse checking        Enabled
SeUndockPrivilege             Remove computer from docking... Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set  Disabled
SeTimeZonePrivilege           Change the time zone            Disabled
```

In addition to these rights that a user has, Windows groups also have their own rights and so belonging to a specific group can give you access to those rights not specifically granted through the user privileges. An example of this is Remote Desktop Users that allows members to remotely access the machine.

## Active Directory

Active Directory \(AD\) is often used to manage users in an organization because the users can be centrally managed and can have access to more than one computer in the AD domain. We won't be covering AD in detail here but just the basics about users and how users and their access privileges change when they are an AD account rather than a local account on a machine.

Generally, users rights in AD are the same as those that are assigned locally although there are some specific rights that apply only in an Active Directory environment. What does change are the built-in privileged accounts and groups of Active Directory. This includes Enterprise Admins, Domain Admins, Administrators and Schema Admins. Commonly, we are looking to get access to a user who is an enterprise or domain admin.

## Enumeration Checklist on Windows

As with Linux machines in the previous chapter, the aim of enumeration is to understand the system that you have access to in detail including the physical characteristics, network, and software that is running on it, including system software. As with remote access, we are looking for vulnerabilities related to software versions that we can exploit because we have local access. The same rules apply as before, depending on whether we actually have the user's password and are able to exploit authenticated vulnerabilities as well as unauthenticated ones. Whilst doing this, we are going to pay specific attention to potential misconfigurations that can be exploited such as execution paths that allow scripts and binaries to be run as part of the normal processing on the system. User privileges that allow execution of administrative commands, installing or running services to establish persistence and to create or alter users on the system.

With Windows, there is the added element of the enterprise environment which allows us to get ownership of an entire domain of computers and accounts if we get administrative privileges on that Active Directory domain or all of the domains of an enterprise.

At the same time, we are searching for information that might be accessible and useful, including but not limited to, usernames and passwords. This might be in documents, configuration files and databases.

To assist with this, there is a windows equivalent for LinPEAS called WinPEAS that does the same job at enumerating aspects of the machine. We will look at the individual areas that WinPEAS enumerates. Although we can look at individual commands that could be run independently, it is easier if you need to know what these commands are, to look at the WinPEAS script.

### System Info

With Windows, the important aspects are the version of Windows that we are dealing with, its particular build number and what hotfixes or patches \(dealing with specific KBs or Knowledge Base issues\). This will allow us to determine if there are any specific vulnerabilities that this configuration may have. We also need to know the architecture of the machine to know what versions of applications to run \(64 bit vs 32 bit\) although it is becoming rarer to see a 32 bit version of Windows running. WinPEAS provides the following information about the system:

```text
Hostname: DESKTOP-IRRKDNQ
ProductName: Windows 10 Education
EditionID: Education
ReleaseId: 1709
BuildBranch: rs3_release
CurrentMajorVersionNumber: 10
CurrentVersion: 6.3
Architecture: AMD64
ProcessorCount: 2
SystemLang: en-US
KeyboardLang: English (United States)
TimeZone: (UTC+08:00) Beijing, Chongqing, Hong Kong, Urumqi
IsVirtualMachine: True
Current Time: 1/4/2021 11:55:39 AM
HighIntegrity: True
PartOfDomain: False
Hotfixes: KB2693643, KB4519564, KB4134661, KB4295110, KB4462930, KB4486153, KB4489219, KB4516115, KB4523202, KB4525241,
```

### Vulnerabilities based on version

Using the version and build number, WinPEAS will use Watson to check what Knowledge Base updates \(KBs\) have been updated and then suggest privilege escalation vulnerabilities based on that. Alternatively, or in addition, you can use searchsploit and internet searches to look for exploits.

### Environment

Environment variables are set at a system \(machine\) level, user level and process level. On Windows, you can use PowerShell to list all environment variables using the command

```bash
Get-ChildItem env:
```

Individual variables can be printed using $env:SystemRoot and you can set variables using the same syntax $env:SystemRoot = c:\

The Path variable is important because it will be used by Windows to find an executable and so if you have control over a directory in a path, then you can potentially add your own executable file.

WinPEAS will list all environment variables on the machine for your user.

### Check protections

Although this will be the subject of its own chapter, Windows has a range of software and configurations that try and protect the machine against deliberate or accidental manipulation. We will go into some of these in more detail later, along with a discussion of how to evade these protections, but for the time being, WinPEAS will list what protections are enabled:

* auditing of various events such as logon, account management, privilege use, process tracking.
* Windows Event Forwarding \(WEF\) which forwards events for other systems to check for intrusions
* Local Administrator Password Solution \(LAPS\) which manages local administrator passwords in an AD environment,
* LSA Protection which is additional protection for the Local Security Authority,
* Credentials Guard which protects NTLM password hashes, Kerberos Ticket Granting Tickets and application credentials,
* Antivirus such as Windows Defender
* User Account Control \(UAC\) which checks whether software being run is authorized and whether the user running it is entitled to run it

### PowerShell

PowerShell version information can be obtained by using the variable $PSVersionTable and you can also check any logged history stored in the file:

```bash
c:\Users\rin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Another important policy that will determine what you can and can't do with PowerShell is its execution mode. PowerShell has the following execution modes:

* Restricted: which will not run scripts but just allow interactive commands
* ByPass: nothing is blocked and there are no warnings or prompt
* AllSigned: which will run scripts but they have to be signed by a publisher you trust although you can agree to trust a publisher
* Remote Signed: where local scripts can run unsigned but those run from remote sources need to be signed.
* Unrestricted: which will run all scripts.
* Undefined: the default is restricted for Windows clients and RemoteSigned for Windows servers.

These policies apply at the machine, user, process level and you can list them using the command:

```bash
PS C:\Users\rin\Desktop> Get-ExecutionPolicy -List
 Scope            ExecutionPolicy
 -----            ---------------
MachinePolicy           Undefined
UserPolicy              Undefined
Process                 Undefined
CurrentUser             Undefined
LocalMachine         Unrestricted
```

To change the execution policy, you can use Set-ExecutionPolicy Unrestricted but you need administrative access to do that.

### Users and Groups

Get information about the users and groups on the system and whether the current user has privileges that can be used to escalate further such as: SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege. This is covered in more detail below.

1. Check user access to home directories.
2. Check password policies
3. Check contents of clipboard

### Processes

1. Check for non-Microsoft processes that are running on the box, their versions and any known vulnerabilities
2. Check for non-Microsoft services that are running under elevated accounts. ​
3. Check whether the services can be modified by the user including stopping, starting and updating configuration including registry settings.

### Software

Enumerate software installed on the system in c:\Program Files and c:\Program Files \(x86\). Software can be installed in other locations and checking the registry for Uninstall information may reveal where.

1. Check for software configured to autorun.

### Device Drivers

Check for non-Microsoft device drivers that may be vulnerable through DLL hijacking, being able to write to folders inside the PATH.

### Windows Credentials

Check Windows Vault for stored credentials accessible to software that can use Credentials Manager and Windows Vault to automatically login on behalf of a user using the stored credentials. You can list what credentials are stored by using the cmdkey /list command:

```bash
c:\Users\rin
λ cmdkey /list
Currently stored credentials:
 Target: LegacyGeneric:target=git:https://github.com
 Type: Generic
 User: PersonalAccessToken
 Local machine persistence
 Target: LegacyGeneric:target=TERMSRV/172.16.5.66
 Type: Generic
 User: student
 Local machine persistence
```

Other places to look for credentials:

* Passwords of saved Wifi networks?
* Interesting info in saved RDP Connections?
* Passwords in recently run commands?
* ​Remote Desktop Credentials Manager passwords?

### Network Information

1. Check for network interfaces and known hosts.
2. Check for network shares
3. Check current listening ports
4. Check firewall rules
5. Check cached DNS

### File and Registry

As with the Linux enumeration, we are looking for any information that may be of value, but especially information relating to credentials. Windows is different from Linux in that it has the Windows Registry which is a in-memory database for storing configuration information. This search involves looking at specific well-known locations that may potentially yield credentials such as web.config files for the IIS web server, credentials stored with programs like OpenVPN, SSH, Internet browsers, and other applications.

Some examples of registry locations that can be queried using the application reg are:

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

































