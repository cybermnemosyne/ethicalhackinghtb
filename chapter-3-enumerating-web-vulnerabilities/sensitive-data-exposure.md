# Sensitive Data Exposure

A security misconfiguration vulnerability, sensitive data exposure occurs when data is exposed unintentionally in a non-encrypted or other insecure state. OWASP details scenarios that include storing passwords as clear text or as unsalted or simple hashes. In another example, the site does not use, or does not enforce the use of TLS. In another scenario, credit card or personally identifiable information is stored in clear text or in an encrypted form that is automatically decrypted when retrieved making retrieval in the clear relatively easy to achieve.

From an attacker’s perspective, these vulnerabilities are part of the gathering “loot” process. It is one thing to find a vulnerability that gives you unintended access to a machine but the ultimate goal is to obtain information of value. Gaining access to a HoneyPot for example, a machine that is deliberately constructed to lure attackers to break in, does not pose much of a security risk even though an attacker has gained some access to a network. This act has not affected the confidentiality, availability or integrity of the affected organization.

There are numerous examples of exposed sensitive data both in the real world and on Hack The Box. The password list rockyou.txt as mentioned above, was obtained from a data breach of the company RockYou. More recently in 2019, security researchers found 100 Terabytes of data on Amazon Web Service’s S3 storage site. The data belonged to a company called Attunity that contained data from their customers, including passwords and sensitive employee information. This type of vulnerability has been common because Amazon did not prevent public access by default in its settings of S3. This type of vulnerability also appears in the category of security misconfiguration which will be covered below.

## 

