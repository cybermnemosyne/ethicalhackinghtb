# On Your Own

The top 10 OWASP vulnerabilities cover a large topic area and so you could pick almost any Hack The Box machine that features a web server and find an example of one of these vulnerabilities. The box Magic is a good example of using SQL injection to bypass authentication. Start with an nmap scan and the enumerate the website you find by running Gobuster on the site. You will find a /images directory and so run Gobuster on that directory as well.

Try running sqlmap on the login page. To do this, intercept the login request in Burp and send the request to the Repeater tab. In the Repeater tab, right click on the request text and select "Copy to file". Call the file login.req.

We will initially run sqlmap to let it discover what database server is running, what fields are injectable and how it can be exploited. The command you want to run is:

sqlmap -r login.req --batch --level=3 --risk=5

Note what that tells you, especially the type of injection vulnerability it has found. We can now dump the contents of the database that the website is using by running the command:

sqlmap -r login.req --batch --dump --current-db

This should tell you what the database name is, the table name and show the contents of the table which includes a user and password!

