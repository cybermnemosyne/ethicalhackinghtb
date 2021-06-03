# Security Misconfiguration and Insecure Deserialisation

Security misconfiguration is a category of a range of different vulnerabilities. Vulnerability scanners may find some of these types of vulnerabilities. The vulnerabilities covered here include:

* Leaving default settings of applications that do not implement security features
* Using default accounts and passwords
* Not updating software or patching known vulnerabilities
* Leaving debugging or development options switched on in the application
* Leaving unneeded features in the application such as demo applications or code

Searching for these vulnerabilities will become second nature when hunting for bugs on a new machine. Whilst application software developers are getting better at not allowing a default username and password, forcing it to be changed on installation, the problem is still very prevalent on Internet of Things devices and devices such as consumer Internet routers.

## Insecure Deserialisation

Deserialization is a slightly advanced topic because it involves the way objects, which is a collection of code and data, can be stored. Languages that support objects, so called object-oriented languages like C\#, Swift, PHP, Java and Python all offer object serialisation capabilities. To take a simple example in PHP, the code to serialize an array of strings is as follows:

```php
<?php
    $data = serialize(array("Red","Green","Blue"));
    echo $data;
?>
```

Executing this code gives us:

```bash
┌─[rin@parrot]─[~/boxes/book]
└──╼ $php serial.php
a:3:{i:0;s:3:"Red";i:1;s:5:"Green";i:2;s:4:"Blue";}
```

The a:3 represents an array type object with 3 elements. The array elements are in the braces and the first element is a string of 3 characters \(s:3\) with a value of "Red". The entire serialized object can then be written to a file or stored in a database.

To unserialize the array and use it in code, you simply do

```bash
$a = unserialize($data);
echo $a[0];
```

This will recreate the array and so it can be used to print the first value in the array which is "Red".

Serialization is used to transmit objects in messages between applications and to store their state in files and databases. There are obvious vulnerabilities in this process however if an attacker manages to be able to change the serialized data to allow them to manipulate the application once the objects is deserialized. An example of this given by OWASP is the manipulation of cookies that use PHP serialisation to save user credentials. An attacker can elevate their privileges in the case of an application that uses an object such as the following:

```bash
a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";
i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}
```

and changes it to:

```bash
a:4:{i:0;i:132;i:1;s:7:"Alice";i:2;s:4:"admin";
i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}
```

Whilst this is at the more advanced level, attacking deserialization vulnerabilities is made easier thanks to frameworks such as YSoSerial for Java and YSoSerial.Net for Microsoft .Net. you will look at how this works in the Hack The Box case study of the machine JSON.

