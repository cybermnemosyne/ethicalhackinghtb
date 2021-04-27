# File Inclusion, Broken Authentication, Cracking Hashes

## File Inclusion

File inclusion vulnerabilities are a related set of vulnerabilities to injection in that an attacker manipulated inputs to allow for the disclosure of unintended information. They are caused when web application code uses a variable to select the name of a file to include into another code file. In php, the “include” statement allows code such as:

```php
<?php
  if (isset($_GET['category'])) {
    include($_GET['category']);
  }
?>
```

This code is then vulnerable to both local and remote file inclusion. If this code was hosted as a page lfi.php on a Linux system for example, the code could be exploited with URLs such as:

`https://www.vulnerablesite.com/lfi.php?category=../../../../../etc/passwd`

