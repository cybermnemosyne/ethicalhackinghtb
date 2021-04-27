# Brute forcing remote service passwords

We have already come across some examples of brute forcing passwords \(and usernames\) but we are going to go into the subject a bit more deeply here and look one tool in particular THC Hydra to brute force a variety of remote services. First, it is worth mentioning some background about passwords. The perceived wisdom about passwords has changed with the main recommendation for passwords being length and not complexity \(NIST SP 800-63B \([https://pages.nist.gov/800-63-3/sp800-63b.html\)\](https://pages.nist.gov/800-63-3/sp800-63b.html%29\)\). The determination was that adding rules about specific characters and complexity only added a burden on users to remember the password and led to behaviors where users used patterns to choose their passwords. The advent of highly efficient offline password hashing and checking computers along with millions of available breached passwords has led to the increased possibility of a password being brute forced.

Password hashing depends on the use of a mathematical function that is called a one-way function. It is easy to calculate the hash of a piece of plain text but almost impossible to generate the text from the hash. Hashes are also of fixed length, so no matter how long the piece of text being hashed, the hash itself is always the same length. In the case of the SHA-512 hashing algorithm commonly used on modern Linux-based systems, the output is 64 bytes long. If the only thing that was done with a password was to take the plain text and hash it, it would not be very secure. This is because it would be possible to use tables of pre-computed hashes, called rainbow tables\) for millions of common passwords and compare them to the hash to get a match. That process would be very fast. Even without the rainbow tables, doing a brute force on a dictionary of words by hashing each word and comparing it with the hash we want to crack would also be very fast, especially on modern computers with Graphical Processing Units \(GPUs\).

To prevent these types of attacks, password hashing uses a salt, a piece of random text that is up to 16 characters long \(for the SHA-512 hashing algorithm\) and adds that to the password and hashes that. However, it doesn't just do this one, it does it a minimum of 1,000 times taking the product of each round and adding it back in a variety of ways. The aim of this process is to make the calculation of hashes computationally expensive i.e. to slow it down.

Of course, not all password hashes are generated in this way and despite the improvements in hashing algorithms, it is still possible to brute force passwords if they are short and are a common dictionary word.

There are two main ways of brute forcing a password: online and offline. We have encountered methods for both already but let's start with offline cracking. Obtaining password hashes is only the beginning of the process of being able to crack them. We first have to identify what type of hash we are dealing with. The password cracking software hashcat has a flag that will show example hashes for all of the different hashing modes. To list all of the modes of hashing that hashcat supports, you can use the --help flag

```bash
┌─[rin@parrot]─[~/book]
└──╼ $hashcat --help
…
- [ Hash modes ] -
 #     | Name                | Category
 ======+=====================+======================================
 900   | MD4                 | Raw Hash
 0     | MD5                 | Raw Hash
 100   | SHA1                | Raw Hash
 1300  | SHA2-224            | Raw Hash
 1400  | SHA2-256            | Raw Hash
 10800 | SHA2-384            | Raw Hash
 1700  | SHA2-512            | Raw Hash
 17300 | SHA3-224            | Raw Hash
 17400 | SHA3-256            | Raw Hash
 17500 | SHA3-384            | Raw Hash
 17600 | SHA3-512            | Raw Hash
 6000  | RIPEMD-160          | Raw Hash
 600   | BLAKE2b-512         | Raw Hash
…
```

For each of these modes, we can show an example of the hash by using --example-hashes

```bash
┌─[rin@parrot]─[~/boxes]
└──╼ $hashcat -m 1800 --example-hashes
hashcat (v6.1.1) starting...
MODE: 1800
TYPE: sha512crypt $6$, SHA512 (Unix)
HASH: $6$72820166$U4DVzpcYxgw7MVVDGGvB2/H5lRistD5.Ah4upwENR5UtffLR4X4SxSzfREv8z6wVl0jRFX40/KnYVvK4829kD1
PASS: hashcat
```

Password cracking can operate in a number of different ways. The first and most basic is to simply try every character combination in sequence. At the opposite end of the scale is to use dictionaries of common passwords and/or common character combinations. As variants of these two approaches, we can optimize the dictionaries by applying what we know about the password syntax rules and also information we may have gathered about the target, personal details like hobbies and interests, dates of birth, where they work etc.

In terms of password syntax, we may know what the minimum and maximum numbers of characters are, whether there needs to be a capital letter, special characters and numbers. Armed with this knowledge, we can simply parse dictionaries like rockyou.txt with a tool like grep. For example, if we wanted to get words that are between 8 and 9 characters long, we could use:

`egrep '^.{8,9}$' passwords.txt`

egrep is an alias for grep -E which supports extended regular expressions. Regular expressions are a set of patterns that will match text according to certain rules. In this expression, the ^ matches the start of a string. The . matches any character and the {8,9} will match characters 8 or 9 times. Finally, the $ matches the end of the word. We can make this expression exclude words that have uppercase letters in them:

`egrep '^[^[:upper:]]{6,7}$' passwords.txt`

The expression \[\[:upper:\]\] matches uppercase letters and the ^ within the \[\] means 'not'.

The approach of taking a password list and refining it certainly makes the process of cracking faster, provided the password you are looking for is in the list. However, even though a person may use a common password, they will often change it by altering numbers at the end, either a sequence or referring to a specific date for example. A fan of the French soccer team may have the password France2018 representing one of the years that France won the FIFA World Cup.

The tool CUPP \(Common User Passwords Profiler\) \([https://github.com/Mebus/cupp\](https://github.com/Mebus/cupp\)\) will ask a series of questions about a target to create a set of possible password combinations. Of course this relies on having access to personal information about the target such as their family members' names, dates of birth, pet names, work and hobbies.

Another approach is to crawl a company website for potential words that could be used as a password using a tool like CeWL \(Custom Word List Generator [https://digi.ninja/projects/cewl.php\](https://digi.ninja/projects/cewl.php\)\). Again, this isn't sophisticated, it just takes words that it finds and creates a password list.

Once you have a wordlist, you can use tools to take the words and create different combinations to create a more extensive list of passwords. One of these is Mentalist \(git clone [https://github.com/sc0tfree/mentalist.git\](https://github.com/sc0tfree/mentalist.git\)\) which allows you to take a wordlist and then apply a chain of transformations that will do things like change case, substitute numbers for letters and other substitutions \(e.g. zero instead of the letter O, 3 instead of e, 5 instead of s\) and to take things like zip or postal codes and other words and prepend or postpend them to the word. You can either use this to generate a new dictionary to use for cracking, or create a set of rules that can be directly used by John The Ripper or Hashcat.

We will go through an example of generating a custom word list in a moment, but first we can turn to tools for testing passwords directly with an application online. This has become much more challenging recently with improvements in applications that will lock users out after a small number of failed login attempts. However, it can still work where these protections have not been applied, websites with poor security practices, services that do not have the means for password protections of this sort and devices like the Internet of Things where again, password protection is not implemented by default.

## Online Password Brute Force

We have already seen a number of tools that can be used to test usernames and passwords for specific remote services. The most comprehensive of these is THC Hydra \([https://github.com/vanhauser-thc/thc-hydra\](https://github.com/vanhauser-thc/thc-hydra\)\) which supports more than 50 different protocols. The basic syntax of Hydra is illustrated in the examples printed out with the use of hydra -h

```bash
hydra -l user -P passlist.txt ftp://192.168.0.1
hydra -L userlist.txt -p defaultpw imap://192.168.0.1/PLAIN
hydra -C defaults.txt -6 pop3s://[2001:db8::1]:143/TLS:DIGEST-MD5
hydra -l admin -p password ftp://[192.168.0.0/24]/
hydra -L logins.txt -P pws.txt -M targets.txt ssh
```

The -l and -p flags expect a username and password respectively. The capital versions -L and -P will accept files of usernames and passwords. The service is of the format:

`<protocol>://<IP Address>:<Port>/<Protocol Options>`

&lt;protocol&gt; will be the type of service such as http, smb, ftp pop3. The port can be specified in addition to the IP address although the default port will be used if this is omitted. Finally, there is the ability to specify particular authentication variants as part of the protocol specification.

Medusa is another tool, like hydra, which will allow the brute forcing of a range of different services but it has been largely unmaintained since 2015.

Metasploit also has a number of scanners for services such as FTP, SMB and SSH that will do brute force logins as well. There are also other tools such as Crackmapexec which supports a few protocols such as SMB, HTTP and MSSQL \(Microsoft SQL Server\).

As we will see however, all of these tools respond differently to different settings and protocols and so it is possible to get both false positives and negatives. Checking with another tool is always a good idea.

