# Process Injection

Process injection is a defense evasion technique on Windows whereby code is run within the address space of another running process. Meterpreter has a post exploitation function called migrate. This takes the process ID \(PID\) of a running process such as svchost.exe and migrates the currently running shell into that process. It does this[\[1\]]() through a series of steps:

1. Gets the PID of the process to migrate into
2. Check whether the target process is 32 or 64 bit
3. Verifies that the running Meterpreter process has the SeDebugPrivilege which is used to get a "Handle" to the running process
4. Make an API call to get access to the virtual memory of the running process \(OpenProcess\(\)\).
5. Allocate memory in the running process with the attributes RWX \(Read, Write and Execute\) using the API call VirtualAllocEx\(\).
6. Write the shell code to this memory using WriteProcessMemory\(\)
7. Call the CreateRemoteThread\(\) function to get the running process to execute the memory
8. Terminate the previously running Meterpreter process thread.

The migrate function in Metasploit is sometimes referred to as Portable Executable Injection \(PE Injection\). There are a range of different approaches to this however that include techniques such as:

**Process hollowing**: In this procedure, the attacker creates a new legitimate process in a suspended state. The code of the legitimate process is unloaded \(unmapped\) from memory and replaced with the malicious code. The process thread is made to point to this code and the process is resumed. This does create a new process but it is from outside appearances a legitimate process and so may go undetected.

**DLL Injection**: This procedure maps a link to a malicious DLL within a running processes memory space and causes it to run a thread using this memory. This technique suffers from having a DLL on disk where it can be potentially detected.

Process injection is also one of the techniques used to achieve persistence.

Although we have concentrated on Windows, the process injection is possible on Linux using the same sort of mechanism as outlined in PE Injection above. On Linux, the technique uses ptrace\(\), a system call that allows control of another running process for the purposes of inspection and debugging. For this reason, the ability of ptrace to call a process it didn't create is limited on Linux systems and it may be necessary to change this using the command:

echo 0 \| sudo tee /proc/sys/kernel/yama/ptrace\_scope

The technique varies in where the malicious code is written with the easiest place to replace the main\(\) function. This is destructive in that the malicious code can't return to the host function and so is not absolutely ideal.

Other techniques

There are a range of techniques that can be used to avoid detection and to remove activity traces. These include:

* Hide artifacts
  * Hide files and directories
  * Hide a file system
  * Hide users
  * Hide windows
  * Run virtual instance
* Disable or modify AV, Firewalls, IDS/IPS
* Remove indicators
  * Clear Windows Event Logs
  * Clear Linux system logs
  * Clear command history
  * Delete files
  * Remove any connected network shares
  * Timestomp \(alter time creation or modification dates on files or directories to fit in with other files and directories\)

Many of these techniques don't impact anything that you will do on Hack The Box, but they are of obvious importance when penetration testing or undertaking red team engagements.

