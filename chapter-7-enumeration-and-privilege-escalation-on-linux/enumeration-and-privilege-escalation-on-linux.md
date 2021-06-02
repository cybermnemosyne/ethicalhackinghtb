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

We have seen an example of the use of suid files in the Hack The Box machine Ellingson \(REF XXX\) where a buffer overflow of an application, owned by root and with the suid permission set allowed us to run a shell as root. Having a file with suid set and owned by a more privileged user is only part of the equation. We also need to find a way for that running that program will allow us to perform an action such as run a local or reverse shell or read or write to a file. Fortunately, there are a large number of Linux applications that will allow us to do exactly that. A list of them is available on GTFOBins \([https://gtfobins.github.io/\#+suid\](https://gtfobins.github.io/#+suid\)\). As an example, we can take the application find. Here we are going to create a local copy of the find command and set the suid bit on it and then execute to drop to a shell as root.

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

One of the easiest things to do to enumerate a system after gaining access is to run a script file like PEAS \(Privilege Escalation Awesome Scripts\) \([https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite\](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite\)\). This checks for an extensive, but not necessarily exhaustive, list of potential vulnerabilities. It produces a great deal of output that is colour coded and references explanations of its findings on the GitHub site HackTricks \([https://book.hacktricks.xyz/linux-unix/privilege-escalation\#path\](https://book.hacktricks.xyz/linux-unix/privilege-escalation#path\)\).

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

**/** is the root directory and only the user root has access to write in this directory. The user root's home directory is /root.

**/bin** contains user binary executables like ps, ls, ping, grep etc. it is a symbolic link to **/usr/bin**

**/sbin** contains system binaries like iptables, reboot, fdisk, ifconfig, etc.

**/etc** contains configuration files and scripts for services running on the system. Configuration files for the Apache 2 web server are in /etc/apache2 for example. Also contains the passwd and shadow files that contain user and password information.

**/dev** contains device files that are the interface with physical devices on, or attached to, the system such as tty devices /dev/tty1. /dev/shm is a directory that is commonly used as a way of passing information between applications through shared memory. This is a virtual directory and anything written to it is stored in memory and not actually written to disk. Consequently, even though /tmp and /dev/shm get wiped on reboot of the machine, files in /tmp could potentially be restored forensically even after being wiped.

**/proc** contains files that store information about system processes like uptime for example.

**/var** contains files like logs \(/var/logs\), backups \(/var/backups\), mail \(/var/mail\) and spool \(printing; /var/spool\). There is also a /var/tmp directory that can be used to run programs out of. This directory does survive reboots however. The directory /var/www/html is often used as the root directory of the web server.

**/tmp** contains temporary files as mentioned previously. Files get deleted on reboot.

**/usr** contains user binaries, libraries, documentation and source code

**/usr/local** contains users programs that you install from source.

**/home** contains user home directories

**/boot** contains boot loader files

**/lib** contains system libraries

**/opt** contains optional add-on applications

**/mnt** is a location for mounting temporary filesystems

**/media** is a location for mounting removable media devices like CDs

**/srv** contains specific service related data

## Enumerating the file system

When enumerating the file system, the /home directory is a good place to start, especially if you have access to any of the users on the system.

Home directories on Linux usually contain a number of files and directories that are hidden because they start with a ".". To list them, you need to use the ls -la flag. Some of these files are resource script files like .bashrc \(if you are running bash\) that configure the bash environment. Things like configuring the amount of history that is kept which is normally viewable by typing history or by listing the .bash\_history file. Other programs such as browsers and email clients keep hidden directories and files in the user's home directory and so these are a good place to look for potentially sensitive information.

Other locations that can be checked are:

_**/var/backups**_ which is a potential location for backups of sensitive files that may be accessible.

_**/var/log**_ is normally only accessible by root but if your user is part of the adm group, it may be able to read some of the system log files and log files belonging to web and database servers.

_**/etc**_ for configuration information for web servers and databases. The /etc/passwd file is readable by all users and will reveal information about the users on the system, which ones can login and where their home directories are located.

**/opt** can contain additional software that has been installed by a user and so is a good place to look for things that are non-standard on the system.

**/usr/local** is another location of applications and libraries that have been installed from source.

_**/bin**_, _**/sbin**_, _**/usr/local/bin**_ we have already seen that searching for binaries that have the suid of guid bit set is often an easy exploitable vulnerability and that we can search for these generally on the system or specifically in these directories.

Another way of exploring what applications have been installed on a system is through the specific package manager tool for the Linux distribution of the machine. One of the most common tools for this is APT but there are a raft of others lime RPM or YUM for RedHat systems. Using apt, you can investigate what packages have been installed on the system with the command

```bash
apt --list
```

If we want to see what files a package has installed, we can use dpkg-query as follows:

```bash
┌─[rin@parrot]─[~]
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
<SNIP>
```

We can also find out what package a specific file was installed from using the dpkg command:

```bash
┌─[rin@parrot]─[~]
└──╼ $dpkg -S /usr/bin/nvim
neovim: /usr/bin/nvim
```

## Enumerating processes

As a starting point, we can list the running processes on a machine using the ps command:

```bash
echo "$(ps aux)"
```

Which will produce output of the type

```bash
root 738 0.7 4.7 868380 285788 tty7 Ssl+ 2020 20:09 /usr/lib/xorg/Xorg :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tc
p vt7 -novtswitch
root 739 0.0 0.0 2672 1616 tty1 Ss+ 2020 0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
redis 744 0.5 0.8 199724 50820 ? Ssl 2020 14:21 /usr/bin/redis-server 127.0.0.1:0
postgres 769 0.0 0.4 212832 24896 ? Ss 2020 0:24 /usr/lib/postgresql/13/bin/postgres -D /var/lib/postgresql/13/main -c config_
file=/etc/postgresql/13/main/postgresql.conf
postgres 770 0.0 0.4 211568 25044 ? Ss 2020 0:09 /usr/lib/postgresql/12/bin/postgres -D /var/lib/postgresql/12/main -c config_
file=/etc/postgresql/12/main/postgresql.conf
postgres 793 0.0 0.1 212936 6120 ? Ss 2020 0:00 postgres: 13/main: checkpointer
```

We are looking for any unusual programs running and who they are being run by. This gives us a static view of the processes however and doesn't necessarily show processes that are run periodically and then terminate after a short period. To look at this sort of behaviour, we can use a program called pspy64 \([https://github.com/DominicBreuker/pspy\](https://github.com/DominicBreuker/pspy\)\) which will monitor processes and highlight when new processes run.

Services are usually long running processes, often run by specific accounts or root that provide functionality such as communication, transportation, databases, web servers, etc. You can list the services running on.a machine using

```bash
service --status-all
```

For each individual service, you can get additional information using the systemctl application and then specific client applications that may communicate with the service.

```bash
┌─[✗]─[rin@parrot]─[~]
└──╼ $systemctl status ufw
ufw.service - Uncomplicated firewall
Loaded: loaded (/lib/systemd/system/ufw.service; enabled; vendor preset: enabled)
Active: active (exited) since Tue 2020-12-15 10:27:41 AWST; 2 weeks 3 days ago
Docs: man:ufw(8)
Main PID: 370 (code=exited, status=0/SUCCESS)
Tasks: 0 (limit: 7009)
Memory: 0B
CGroup: /system.slice/ufw.service
```

Cron is a job scheduler that runs a process periodically. It is configured using a client application crontab but you may have access to list cron jobs that are configured in a number of different locations:

```text
/etc/crontab.hourly
/etc/crontab.daily
/etc/crontab.weekly
/etc/crontab.d
```

and in the file /etc/crontab. You can also list cron jobs for the current user using

```bash
crontab -l
```

**LinPEAS** will do all of the above and we will cover a few specific examples of enumeration using LinPEAS. It is important to remember however that this doesn't substitute for manual enumeration. LinPEAS, even in its "Stealth" mode will be very noisy because it will likely flag unusual behavior for the user for any anomalous behavior detection software.

