# Telnet and FTP

## Telnet

Telnet is an old protocol that provides a command-line interface via remote access. The telnet server usually listens on TCP port 23. Because it was never designed with security in mind, it is less used for administration purposes on computers but is still used on network devices and Internet of Things devices. A large number of IoT devices have shipped with default passwords set for Telnet access allowing attackers to access and take over the devices to enlist them in "botnets". Botnets are a collection of devices all running similar software/malware that can be coordinated in an attack like a Distributed Denial of Service \(DdoS\).

What commands are supported by the telnet server depends on the platform. On windows for example, it will be the cmd.exe commands that are supported. On a Cisco network switch, you will be presented with the Cisco CLI \(Command Line Interface\). In this regard, it is similar to SSH in running a specific shell after a successful login.

## FTP

File Transfer Protocol allows a client to upload and download files using a set of simple commands. The FTP server normally has 2 TCP ports that it uses, port 21 for FTP commands and port 20 for sending and receiving data. FTP operates in two different modes active and passive. In active mode, the FTP client connects to the command port of the server on port 21. The client starts listening for data on a port that is the next port from the one it opened to connect to the server. The FTP server connects to this port on the client from its local data port and sends or receives data when requested by the client.

The trouble with active mode is that clients are often behind firewalls or on a private network that does not allow for inbound connections on dynamic ports. For this reason, FTP also supports a passive mode. In passive mode, the server opens a random port for data connections and passes this to the client to connect to. Of course, having the FTP server open to a range of open ports to support passive mode creates security vulnerabilities of its own.

