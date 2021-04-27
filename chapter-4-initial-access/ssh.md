# SSH

Secure Shell \(SSH\) operates in a client server configuration with the server usually listening on TCP port 22. Normally, the process for a client connecting to a remote machine involves using either a password or a private key. Keys are generated using ssh-keygen which by default will use RSA as the algorithm. Running ssh-keygen will produce a private key and a public key. The public key is added to a file "authorized\_keys" normally located in the .ssh directory in the user's home directory. The private key is then held by the user on their client machine. SSH also supports password access. Although it is not normal to find a private key in the .ssh directory on the server, it is always worth checking, using the default filename for the private key "id\_rsa".

As an added layer of protection, SSH private keys can be encrypted. John The Ripper will extract a hash from the encrypted SSH key with a program called "sshng2john.py".

Another useful utility supported by SSH is "scp" a ssh file copying utility. To copy a file to a remote machine you can use the command:

```bash
scp -I remote.key localfile.txt user@remote.com:/tmp/remotefile.txt
```

To copy the remote file to a local file, you just reverse the order of the file paths.

### SSH Tunnels

SSH can be used to create an encrypted tunnel that supports port forwarding. There are two types of port forwarding, local and remote. This can be confusing because local forwarding forwards packets from a local port to a port on a remote machine. Remote port forwarding is the opposite, taking packets for a port on a remote machine and forwarding them to a port on the local machine. As an example, let us imagine that you have ssh'd onto a remote machine that is behind a firewall that doesn't allow any traffic out. You would like to access a web server on our local machine to be able to access file from the remote box. To do this, you could use an SSH tunnel as:

```bash
ssh -R 8000:127.0.0.1:8000 user@remoteserver.htb
```

From the remote machine, you can now access the web server on the local machine by using the URL [http://127.0.0.1:8000](http://127.0.0.1:8000). Of course, you would need to make sure that nothing was running on port 8000 already on the remote machine.

The converse of this is where you would like to access a port on a remote machine that is only available from that machine. In this case, you use SSH in the same was as before but using the -L flag instead of -R.

```bash
ssh -L 8000:127.0.0.1:8000 user@remoteserver.htb
```

From the local machine, you can access the remote server by once again using the URL [http://127.0.0.1:8000](http://127.0.0.1:8000).

A tunnel can be created without actually logging into the machine \(i.e. not running a shell\) by specifying the -N flag.

## Dynamic Port Forwarding

Specifying individual ports to forward works well when you are interested in a specific target for this. There are situations however when there is more than one port that you would like to forward, or indeed a range of ports. To do this you can use dynamic port forwarding which works as a SOCKS proxy.

```bash
ssh -D 1080 user@remoteserver.htb
```

Once this is running, a SOCKS proxy can be configured in settings of the browser, or you can use the application proxychains which allows any application that uses the network to send its commands over the SOCKS proxy you have established. For example, to curl a web server running on the remote host on port 8000, you would use proxychains as:

```bash
proxychains curl http://remoteserver.htb:8000
```

Depending on the tool however, there is often built in support for proxying and so with curl for example, the SOCKs proxy can be specified directly:

```bash
curl socks5://localhost:1080 http://remoteserver.htb:8000
```

