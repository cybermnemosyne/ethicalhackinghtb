# Broken Authentication

Broken authentication covers any vulnerability that is related to password authentication that is not secure. This might result from a number of causes:

* The password used is the default for an application
* The password is easily guessable, or is weak and can be brute forced
* Passwords are reused across multiple applications
* Unlimited login attempts are allowed
* Credentials are transmitted or stored in the clear

The continuing breaches of millions of users’ accounts have given rise to dumps of usernames and cracked passwords that can be used in “Credential Stuffing” attacks. In these attacks, the credentials from a dump are tried on other sites on the assumption that many users use the same email address and password across multiple services. Another type of attack relies on many users using simple and common passwords. In this attack, called “Password Spraying”, the same password is tried against multiple user accounts.

Default usernames and passwords for applications is becoming less common but is still a major issue with Internet of Things devices. In the past, the initial default administrator account would have a default username and password. Applications now are requiring this password to be changed on installation or first use and so this is less common now.

From an ethical hacking perspective, it is always worth trying default usernames and passwords when encountering a login page. When collecting usernames and possible passwords, it is also a good idea to test these username password combinations with different services. Many tools that allow enumeration of services will take a file of usernames and passwords and automated the login process with these candidate credentials.

