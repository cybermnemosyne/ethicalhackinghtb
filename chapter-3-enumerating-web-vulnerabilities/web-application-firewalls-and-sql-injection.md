# Web Application Firewalls and SQL Injection



A few of the principal mitigations against SQL injection are to code applications in such a way as to not allow dynamic queries, to use parameterized calls to databases and to use Object Relational Mapping tools. A more general defence that works across any application is to use a web application firewall \(WAF\) that monitors http traffic to an application and specifically looks for requests that may be exploiting vulnerabilities such as SQL injection and XSS. An Open Source WAF is ModSecurity[\[3\]]() which can work with a variety of rule sets including the OWASP ModSecurity Core Rule Set which attempts to protect against a range of injection attacks, XSS, data leakages and other things. The rule sets detect probing of the type you outlined above and the presence of SQL commands.

WAFs can sometimes be bypassed using a variety of techniques. In part the bypass will depend on whether the WAF simply removes offending keywords and allows the request to proceed or whether it blocks the request entirely. One technique involves inserting comment characters into the select statement. For example:

```sql
?id=1'+un/**/ion+sel/**/ect+1,2,3--
```

The comments are ignored creating a statement

```sql
?id=1'+union+select+1,2,3--
```

In the case of keyword removal, this would work:

```sql
?id=1+UNunionION+SEselectLECT+1,2,3--
```

Another technique involves changing the case of the key words or replacing characters with their url encoded characters

```sql
char(37,%20112,%2097,%20115,%20115,%2037) = %pass%
```

A more destructive type of bypass involves trying to crash the firewall or doing a buffer overflow on the input.

