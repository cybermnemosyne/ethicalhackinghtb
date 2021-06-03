# Broken Access Control

Users should only be allowed to access functions and information that they have been given the right to access. This means that one user should not be able to see another user’s data and that ordinary users should not be able to access administrative functionality. Unfortunately, controlling user access is sometimes complicated and the range of vulnerabilities that arise because of misconfigurations and program errors is quite wide. The type of vulnerabilities that occur are:

* No access control applied to resources such as file shares, directory listings
* Modifying urls \(Parameter Tampering\) to change an id to that of a record that the user should not be able to access. This vulnerability is also referred to as IDOR \(Insecure Direct Object Reference\)
* Stealing cookies that allow a user to masquerade as another
* Lack of checking of access on APIs and web pages allowing unauthorized access

This is one of the most prevalent vulnerabilities that you will come across when doing Hack The Box machines. you will look at cookie stealing as part of the section on Cross-Site Scripting \(XSS\) below. Parameter tampering is always worth trying when anything like an ID is found in a url.

