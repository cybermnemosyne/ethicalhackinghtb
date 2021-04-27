# Exercise: Network Enumeration of the Archetype box

To practice using Nmap, let’s scan a machine on Hack The Box. Archetype is one of the site’s introductory tutorial machines, located in the Starting Point section of the site, under Labs in the left-hand menu \(Figure 2-2\). Unlike other machines on HackTheBox, the Starting Point machines are always running and so can be accessed directly using the machine's IP address.

To access any Hack The Box machine you need to connect to the network via a VPN. In the case of Archetype, there is a special VPN configuration file for the Starting Point machines. Download the file by clicking the VPN Connection link in the Dashboard page. To run the VPN, use openvpn:

┌─\[rin@parrot\]─\[~/access\]

└──╼ $sudo openvpn rin-startingpoint.ovpn

In this exercise, we’ll use Nmap to enumerate all open ports on the machine. Then we’ll walk through an example of what you can do with the services you discover: after finding open ports related to the Windows file sharing technology SMB we’ll use three different approaches to enumerating SMB file shares and their contents. We will then mount an SMB share to make it accessible on our Parrot box and go through its contents to look for credentials.



![A screenshot of a computer

Description automatically generated with medium confidence](../.gitbook/assets/3%20%287%29.png)

Starting Point machines on HackTheBox

Running Nmap

To run a full TCP port scan, which scans all 65,5535 ports, use the following Nmap command:

sudo nmap -v -sC -sV --min-rate=1000 -T4  -p- archetype.htb -oN nmap/tcp-full 

This command attempts to perform a full TCP SYN scan as fast as possible. We need to use sudo to allow Nmap to do a SYN scan. The argument -p- tells Nmap to scan all ports. Because we specified no option for the type of scan to do, Nmap does a SYN scan of TCP ports by default. The argument –min-rate=1000 tells Nmap to send probes at a rate of at least 1,000 per second. The -T4 argument tells Nmap to do an aggressive timing scan \(the default is T3\) which essentially makes the scan faster. The -v makes the output verbose, printing out the discovered ports and their status as the command executes.

Next, we run some scripts. Nmap can run scripts written in the Lua programming language with its Nmap Scripting Engine \(NSE\). The -sC flag tells Nmap to run all of its default scripts, which will do things like find vulnerabilities, look for default attributes and behaviors in software, and a range of other things. The script http-favicon.nse for example, will retrieve the favorites icon \(favicon\) from a website and compare it against known favicons from specific products, printing the product name if it is a match. This is just another way of finding out what product we are dealing with.

The -sV flag tells Nmap to try to get version information for all software that it finds. Finally, the -o flag is the output and -oN saves all output from Nmap in Nmap format \(normal format\). This format saves information that is normally printed to the terminal but without any warnings and other runtime output.

When you run this command on Archetype, you should receive output like the following:

┌─\[✗\]─\[rin@parrot\]─\[~/boxes/StartingPoint/Archetype\]

└──╼ $ sudo nmap -v -sC -sV --min-rate=1000 -T4  -p- archetype.htb -oN nmap/tcp-full 

&lt;SNIP&gt;

 PORT STATE SERVICE VERSION

 135/tcp open msrpc Microsoft Windows RPC

u 139/tcp open netbios-ssn Microsoft Windows netbios-ssn

v 445/tcp open microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds

w 1433/tcp open ms-sql-s Microsoft SQL Server 2017 14.00.1000.00; RTM

\| ms-sql-ntlm-info:

\| Target\_Name: ARCHETYPE

\| NetBIOS\_Domain\_Name: ARCHETYPE

\| NetBIOS\_Computer\_Name: ARCHETYPE

\| DNS\_Domain\_Name: Archetype

\| DNS\_Computer\_Name: Archetype

\|\_ Product\_Version: 10.0.17763

\| ssl-cert: Subject: commonName=SSL\_Self\_Signed\_Fallback

\| Issuer: commonName=SSL\_Self\_Signed\_Fallback

\| Public Key type: rsa

\| Public Key bits: 2048

\| Signature Algorithm: sha256WithRSAEncryption

\| Not valid before: 2020-10-01T12:43:48

\| Not valid after: 2050-10-01T12:43:48

\| MD5: b89e 499d adf4 9f0b 35f3 03ca 682e 7a8d

\|\_SHA-1: d6e4 4a18 723d 6e1c 286a c963 4370 b663 934a 5317

\|\_ssl-date: 2020-10-08T13:33:45+00:00; +15m45s from scanner time.

5985/tcp open http Microsoft HTTPAPI httpd 2.0 \(SSDP/UPnP\)

\|\_http-server-header: Microsoft-HTTPAPI/2.0

\|\_http-title: Not Found

47001/tcp open http Microsoft HTTPAPI httpd 2.0 \(SSDP/UPnP\)

\|\_http-server-header: Microsoft-HTTPAPI/2.0

\|\_http-title: Not Found

49664/tcp open msrpc Microsoft Windows RPC

49665/tcp open msrpc Microsoft Windows RPC

49666/tcp open msrpc Microsoft Windows RPC

49667/tcp open msrpc Microsoft Windows RPC

49668/tcp open msrpc Microsoft Windows RPC

49669/tcp open msrpc Microsoft Windows RPC

Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

x Host script results:

\|\_clock-skew: mean: 2h56m12s, deviation: 3h34m42s, median: 1h20m10s

\| ms-sql-info:

\| 10.10.10.27:1433:

\| Version:

\| name: Microsoft SQL Server 2017 RTM

\| number: 14.00.1000.00

\| Product: Microsoft SQL Server 2017

\| Service pack level: RTM

\| Post-SP patches applied: false

\|\_ TCP port: 1433

\| smb-os-discovery:

\| y OS: Windows Server 2019 Standard 17763 \(Windows Server 2019 Standard 6.3\)

\| Computer name: Archetype

\| NetBIOS computer name: ARCHETYPE\x00

\| Workgroup: WORKGROUP\x00

\|\_ System time: 2021-02-03T21:06:58-08:00

\| z smb-security-mode:

\| account\_used: guest

\| authentication\_level: user

\| challenge\_response: supported

\|\_ message\_signing: disabled \(dangerous, but default\)

\| smb2-security-mode:

\| 2.02:

\|\_ Message signing enabled but not required

\| smb2-time:

\| date: 2021-02-04T05:06:54

\|\_ start\_date: N/A

Notice that Nmap has identified the operating system as Windows Server 2019 Standard 17763 y. Also, you can see that file sharing is enabled because ports 139 u and 445 v are open. These ports are used for the Server Message Block \(SMB\), a protocol we'll dive deeper into shortly. These ports are always worth exploring to see if the machine is sharing folders that anonymous and unauthenticated users can accessible. Next, notice that port 1433 is running Microsoft SQL Server 2017 14.00.1000.00 w. When you discover any software like this, you can use information about the service and its version to look for known vulnerabilities in it.

You’ve asked Nmap to run all relevant scripts, and the results from those is detailed in the output x. As you can see, these scripts tell us more about the MSSQL and SMB services running on this box. Let’s see what we can do with this information. For MSSQL, you’re told that there have been no patches installed, so this service is considered to be a vanilla RTM \(Release to Manufacturing\) install.

Maybe we’ll be able to find credentials to it in the SMB shares. As you can see, there are details of the security implemented for versions 1 and 2 of SMB, and from this information, it looks like you will be able to use SMB version 1 without any credentials; Nmap shows that the ports involved with SMB are open and that guest access was allowed z.

Exploring SMB Shares

Once you’ve discovered open ports on a system, you can explore the services running on those systems to figure out whether they’re vulnerable. One useful service you’ll commonly discover is Server Message Block \(SMB\), a messaging protocol that provides access to shared files, printers, and serial ports.

The most famous exploit of SMB, EternalBlue \(CVE-2017-0144\), uses specially crafted SMB packets against SMB v1 implementations to allow unauthenticated attackers to execute code on the system remotely. Originally developed by the US National Security Agency, the exploit was leaked to the world by a hacker group called the Shadow Brokers in 2017 and became the main vector for the WannaCry and NotPetya ransomware attacks.

The key vulnerability you’ll find in SMB are misconfigurations that grant overly permissive access, especially unauthenticated access to file shares or printers. And as you learned from the Nmap script, you might be able to access Archetype’s file shares without credentials.

Enumerating Shares

Let’s try to enumerate file shares on the system so we can see any of them are accessible. We can use a number of tools to do this. The first is Nmap itself, using the script smb-enum-shares.nse:

```bash
$ nmap -sV --script=/usr/share/Nmap/scripts/smb-enum-shares.nse -p 445 -Pn archetype.htb
Starting Nmap 7.80 ( https://Nmap.org ) at 2020-10-08 21:21 AWST
Nmap scan report for 10.10.10.27
Host is up (0.40s latency).
PORT STATE SERVICE VERSION
445/tcp open microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
Service Info: OS: Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
Host script results:
| smb-enum-shares:
| account_used: guest
| \\10.10.10.27\ADMIN$:
| Type: STYPE_DISKTREE_HIDDEN
| Comment: Remote Admin
| Anonymous access: <none>
| Current user access: <none>
| \\10.10.10.27\C$:
| Type: STYPE_DISKTREE_HIDDEN
| Comment: Default share
| Anonymous access: <none>
| Current user access: <none>
| \\10.10.10.27\IPC$:
| Type: STYPE_IPC_HIDDEN
| Comment: Remote IPC
| Anonymous access: READ/WRITE
| Current user access: READ/WRITE
| \\10.10.10.27\backups:
| Type: STYPE_DISKTREE
| Comment:
| Anonymous access: READ
|_ Current user access: READ
```

Here, we use -Pn to tell Nmap not to ping the host, which it would normally do to check if it is online, because we already know that the host is online. We’re only scanning the one port on which SMB is running \(-p 445\), passing the name of the script we want it to run. The script shows the file shares that are available, whether they allow anonymous access, and what the read and write permissions are for an authenticated user and an anonymous user.

Another tool we can use is smbclient which comes pre-installed on Parrot OS. Like Nmap's SMB share enumeration script, it will say whether it has found any shares visible from the machine. However, it doesn't say whether any of those shares are accessible by an anonymous access:

```bash
$ smbclient -N -L archetype.htb
 Sharename    Type     Comment
 ---------    ----     -------
 ADMIN$       Disk     Remote Admin
 backups      Disk
 C$           Disk     Default share
 IPC$         IPC      Remote IPC
SMB1 disabled -- no workgroup available
```

A third tool that is found on Parrot OS is smbmap, which again will do what the other two tools have done. Like Nmap, will give access for the permissions on the shares:

```bash
$ smbmap -u 'guest' -p '' -H archetype.htb
[+] IP: 10.10.10.27:445 Name: 10.10.10.27
 Disk      Permissions      Comment
 ----      -----------      -------
 ADMIN$    NO ACCESS        Remote Admin
 backups   READ ONLY
 C$        NO ACCESS        Default share
 IPC$      READ ONLY        Remote IPC
```

Finally, there’s crackmapexec, which gives the following output:

```bash
$ crackmapexec smb archetype.htb --shares -u 'guest' -p ''
SMB 10.10.10.27 445 ARCHETYPE [*] Windows Server 2019 Standard 17763 (name:ARCHETYPE) (domain:Archetype) (signing:False) (SMBv1:True)
SMB 10.10.10.27 445 ARCHETYPE [+] Archetype\guest:
SMB 10.10.10.27 445 ARCHETYPE [+] Enumerated shares
SMB 10.10.10.27 445 ARCHETYPE Share   Permissions   Remark
SMB 10.10.10.27 445 ARCHETYPE -----   -----------   ------
SMB 10.10.10.27 445 ARCHETYPE ADMIN$  Remote Admin
SMB 10.10.10.27 445 ARCHETYPE backups READ
SMB 10.10.10.27 445 ARCHETYPE C$ Default share
SMB 10.10.10.27 445 ARCHETYPE IPC$ Remote IPC
```

{% hint style="info" %}
Crackmapexec can be installed using the apt command:

`sudo apt install crackmapexec`
{% endhint %}

Of these approaches, smbclient does not reveal permissions information, which makes the other tools more informative in this case. For smbmap and crackmapexec, you have to specify a username explicitly. In this case, it doesn’t matter what username you choose; it just can’t be an empty string.

Mounting and Exploring a Shared Folder

From all of the tools you ran, you can see that the “guest” user has unauthenticated read access to the folder called backups. To explore this shared folder, you can mount the share directly using the command mount. Mounting means that you map the share to a local drive and then can access it as if it were local:

sudo mkdir /mnt/cifs 

sudo mount -t cifs -o username=guest //archetype.htb/backups /mnt/cifs

If you mount the share, you can unmount it with the command:

sudo umount /mnt/cifs

The other way to explore the share is with the smbclient tool. This command is similar to FTP; it provides a prompt from which files and directories within the share can be accessed:

┌─\[✗\]─\[oztechmuse@parrot\]─\[~/boxes/StartingPoint/Archetype\]

└──╼ $**smbclient -N \\\\10.10.10.27\\backups**

Try "help" to get a list of possible commands.

smb: \&gt; dir

 . D 0 Mon Jan 20 20:20:57 2020

 .. D 0 Mon Jan 20 20:20:57 2020

 prod.dtsConfig AR 609 Mon Jan 20 20:23:02 2020

 10328063 blocks of size 4096. 8257280 blocks available

smb: \&gt;

On the Archetype machine, in the backups folder, notice that there is an MS SQL server integration service dtsconfig file, which is used to configure packages that are integrated with MS SQL server. The dtsconfig file is called prod.dtsConfig. Let’s look at its contents:

&lt;DTSConfiguration&gt;

 &lt;DTSConfigurationHeading&gt;

 &lt;DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/&gt;

 &lt;/DTSConfigurationHeading&gt;

 &lt;Configuration ConfiguredType="Property" Path="\Package.Connections\[Destination\].Properties\[ConnectionString\]" ValueType="String"&gt;

u &lt;ConfiguredValue&gt;Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql\_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;&lt;/ConfiguredValue&gt;

 &lt;/Configuration&gt;

&lt;/DTSConfiguration&gt;

Inside, the file contains a username and password that can be used to access MS SQL server on the machine u. This means you could log into the database using an interactive command line tool and, in this case, execute shell commands. We will come back to the exploitation of MS SQL in Chapter XX.

