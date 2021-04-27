# Remote Desktop Protocol

Remote Desktop Protocol \(RDP\) allows user to access their desktop from another machine over a network using the RDP client. The RDP server listens on TCP and UDP port 3389 by default. Users are permitted to use RDP are those in the Remote Desktop Users group. RDP access is one way hackers will gain initial access to a machine if they have a user's credentials. It can also be used to establish persistence, i.e. an easy way to regain access at some later point. In this case, a new user can be created and added to the relevant groups to allow remote desktop access.

RDP is also susceptible to man-in-the-middle attacks. Using software such as Seth[\[3\]](remote-desktop-protocol.md). When Remote Desktop Connection connects through to a machine, it will throw up an error if there is a problem with the TLS certificate. However, it does this with the default self-signed certificate and users are normally used to just ignoring the warning and clicking through. Another issue with man-in-the-middle is if RDP is configured to use Network Level Authentication which Seth is not able to handle. In this scenario, Seth will still be able to capture the plaintext password that was entered into the login screen for the RDP connection, but the connection will then die.

There have been a number of exploits of RDP with the most significant recent exploit being BlueKeep \(CVE-2019-0708\) which allowed remote code execution through RDP on Windows 7 and Windows Server 2008 machines.

RDP does not feature in Hack The Box machines, mainly because in the past, it would have been hard to support the many users accessing RDP all at the same time on a VM. However, this is an important technique in an attacker's arsenal and so MITRE for example lists numerous malicious hacker groups as using it to gain access and for lateral movement [\[4\]](remote-desktop-protocol.md).

