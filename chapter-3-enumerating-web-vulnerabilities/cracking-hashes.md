# Cracking Hashes

Passwords are normally not stored in clear text but as a cryptographic hash that is obtained usually by combining the password with a random “salt” value and then hashing with a hash function, sometimes multiple times. Applications use different algorithms for hashing passwords, the relative strength of these has gotten stronger over time. An example of a password hashing process is Microsoft’s LAN Manager \(LM\) protocol that used an encryption algorithm known as DES \(Data Encryption Standard\). The process went as follows:

1. The password is first converted to upper case
2. It is then padded with NULL characters to make sure it was 14 characters long.
3. The password is then split into two 7-character halves.
4. Each 7-character half is used to encrypt the string “KGS!@\#$%” using DES
5. The resulting encrypted bytes are then concatenated to create a 16-byte LM hash.

This algorithm makes cracking these types of hashes relatively easy. The hashes can be first compared against large tables, called “Rainbow Tables” of pre-calculated hashes of common passwords and dictionary words. This won’t work if the password was hashed with a salt. The alternative is to use a dictionary of common passwords and a tool like John The Ripper or hashcat. It is important to know that cracking hashes requires a great deal of computational resources and so doing it on a VM is always going to be slow. For Hack The Box challenges, this isn’t usually a problem because any password that is meant to be crackable will crack within 10 minutes or so. In the real world of course, things aren’t that simple and so having a dedicated machine for password cracking that has access to high powered CPUs or GPUs \(Graphical Processing Units\) is essential.

John has a number of utility programs that will convert password files from applications into a suitable “John” format for cracking. As an example, john can extract the password hash from a zip file that has been password protected using the application zip2john. Key files for ssh that are password protected can be converted to a john hash using ssh2john \(in the “jumbo” version of John The Ripper[\[5\]]()\).

If a hash is obtained, John the Ripper will try and identify it but it is worth determining the hash type explicitly. There are hash identifying services online that can be used to help with this.

As with the choice of word lists for other fuzzing tasks, choosing a word list for cracking passwords is also an art. The default is to use the password list rockyou.txt which contains 14,341,564 passwords that came from a breach of a company called RockYou in 2009. It is also possible to craft subsets of rockyou.txt if information is available about the password type and length. This can make a big difference in looking for variants. Finally, it is also possible to brute force the password by going through all of the permutations of characters and numbers. However, for any password longer than a few characters this becomes infeasible unless you have acces to a supercomputer \(or botnet\). On a modern 8 core computer for example, an 8 character lowercase password would take around 2 days if the password was hashed with SHA512. Of course, passwords that combine, numbers, upper and lower case letters and special characters would take years.

Another tool that can be used for cracking passwords, especially on computers with GPUs is hashcat. It can be used in CPU only mode, but it has then little advantage over John The Ripper.

Hack The Box has numerous examples of cracking hashes that can be done with John The Ripper or hashcat and we will highlight the use of these tools in future exercises.

## 

