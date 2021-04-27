# Setting up the VM

It is important when doing ethical hacking to do it from an environment which is not directly your work or personal computer. Fortunately, virtual machine \(VM\) technologies have made it simple to run guest operating systems on a computer and to configure these VMs with a suite of tools commonly used in the ethical hacking process. This is usually based on a Linux platform, but there are equivalent environments built for Windows as well. On the Linux side, two of the most popular VM distributions are Kali from Offensive Security \([https://www.kali.org/downloads/\](https://www.kali.org/downloads/\)\) and the other is ParrotOS from the Parrot Project \([https://www.parrotsec.org/\](https://www.parrotsec.org/\)\). These two platforms are very similar and if you are familiar with one, switching between them will not present a problem. For the purposes of this book, we will use ParrotOS, mainly because it is the one I prefer. However, if you are planning to do the OSCP, the training material will be based on Kali Linux and so it might make more sense to use Kali. Both platforms are Debian-based and feature the same tool sets. In most cases, we will be downloading and using the latest versions of tools in any event.

Sometimes it is very useful to use a Windows VM and for this, we will refer to Windoes Commando VM from Fireeye \([https://github.com/fireeye/commando-vm\](https://github.com/fireeye/commando-vm\)\). Commando VM is actually a set of scripts that install a range of useful software on a regular Windows 10 environment and configures it to stop it deleting everything thinking it is malware.

## Virtual Machine Software VMWare or VirtualBox

Both VMWare and VirtualBox \([https://www.virtualbox.org/\](https://www.virtualbox.org/\)\) offer similar features with VirtualBox's main advantage being that it is open source and free. Whichever platform you decide to use, it is worth getting into the habit of taking snapshots of your VMs and storing them on an external disk. VMs occasionally crash and get corrupted and so having a backup that you can revert to is important especially as you will accumulate notes, software and scripts that you will want to be able to refer back to.

We will not go through the setting up of a desktop environment in this book. There are plenty of good guides on the Internet to do that.

## Taking Notes

Taking notes as you go along any penetration testing engagement or challenge on Hack The Box is vital. A great application for this is Cherrytree \([https://www.giuspen.com/cherrytree/\](https://www.giuspen.com/cherrytree/\)\) which can be installed easily using apt:

`sudo apt install cherrytree`

Cherrytree’s node structure allows for simple organisation of different aspects of an engagement with the ability to preserve code, screenshots and other artefacts that would make writing up a final report relatively easy.

We will come back to the structure of notes that you would take with each step in the process of engagement.

## Tmux

Tmux is a terminal multiplexer and allows you to run a number of different shell sessions in windows and panes. It has a number of advantages over using the native bash or other shell window. The tmux session itself can be detached and re-attached to a shell easily and splitting windows into vertical and horizontal panes allows you to have better control when handling two related activities, for example communicating between a local and remote machine.

Organising activities according to the windows in a tmux session makes it easier to do activities in parallel and make more efficient use of your time.

We will only cover the basic commands here. Most of the commands are accessed using the control key and the ‘b’ key \(ctrl-b\) and then a letter for the command.

To start a session type the following in a shell window

`tmux new -s HTB`

To create a window

`ctrl-b c`

To switch between windows use:

Next window: `ctrl-b n`

Previous window: `ctrl-b p`

It is worth naming windows so that you know what you are doing in each window. To do that use:

`ctrl-b`

To split a window into two panes arranged horizontally, use:

Split horizontally: `ctrl-b “`

Split vertically: `ctrl-b %`

Switch panes: `ctrl-b o`

For a full list of commands have a look here [https://tmuxcheatsheet.com/](https://tmuxcheatsheet.com/) A good introductory video by IppSec on tmux is on YouTube [https://youtu.be/Lqehvpe\_djs](https://youtu.be/Lqehvpe_djs)

A good way of arranging the first few windows is as follows:

* Window 0: run openvpn connection to connect to Hack The Box
* Window 1: run nmap and other network enumeration tools
* Window 2: run gobuster and other web enumeration tools
* Window 3+: other activities

Although it is always a good idea to save output from running exploration tools, having the windows to jump back to for reference is useful as well.

