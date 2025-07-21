# Collection of my forensic analysis notes
---------------------------------------------------------
SYSINTENNALS SUITE - PSTOOLS
Using PsLoggedOn from PsTools part of Sysinternals, you can find users that have logged on locally and remotely onto shares.

- psloggedon
-- Pop-up screens opens
--- Click on Agree

Other tools to use after mounting an image:
- psexec
--- Shows remotely executed processes
- psfile
--- Shows remotely opened documents
- psgetsid
-- psgetsid <user>
--- Displays SID of a user
- psinfo
-- Lists information about a system
- psloglist
-- psloglist > out.txt
--- Dumps event logs to a text file
--- Good for YARA scanning

Others commands not for analysis:
- pspasswd
--- Changes account passwords
- psservice
--- View and control services
- psshutdown
--- Shuts down and reboots a computer
- pssuspend
--- Suspends processes
- psuptime
--- Now part of psinfo
- psping
--- measures network performance
- pskill
--- Kills processes by ID
- pslist
--- list
---------------------------------------------------------
USING THE REGISTRY TO FIND DELETED PROGRAMS
The following key will allow for an analyst to view all the software that has been uninstall from a machine:
- HKEY\LOCAL\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
  --This is the SOFTWARE hive
---------------------------------------------------------
RECOVERING A CORRUPTED RECYCLE BIN
- Open CMD Prompt with Administrator rights
- Type: rd /s /q c:\$Recycle.bin
Note: This will clear out all files from the Recycle Bin but you can then use a software recovery program to get them back. Use Recuva, GetData or Stellar.
---------------------------------------------------------
HACKER'S SEARCH ENGINES
- shodan.io/censys.io
-- servers
- hunter.io
-- email
- urlscan.io
-- other websites
- grep.app
-- source codes
- intelx.io
-- OSINT
- wigle.net
-- wifi routers
- fullhunt.io
-- attack surface
- vulners.com
-- system vulnerabilities
- viz.greynoise.io
-- threat intel
---------------------------------------------------------
PORTS USED BY MALWARE
Port 80
-- HTTP
-- Most common
-- Hides communication through web traffic

Port 443
-- HTTPS
-- Communication is encrypted

Port 21
-- FTP
-- Payload and exfiltration
--- If not in used block it in firewall

- Port 23
-- telnet
-- Less common today
-- Used for remote command execution/system control
--- If not in used block it in firewall

Port 445
-- SMB - Windows file sharing
-- For lateral movement or gain unauthorized access
-- Older systems use port 138/139
--- If not in used blocked them in firewall

Port 3389
-- RDP
-- Compromise/control systems
--- If not in used block it in firewall

Port 6660-6669
-- IRC - Internet relay chat
-- Command and control (C2)
-- Chat and botnet communications

Port 4444
-- Metasploit
-- Common exploit port
-- To deploy RATs
-- Possible default for exploits/comms

Port 5555
-- Android Debug Bridge (ADB)
-- Remote access and control

Port 8080
-- HTTP Proxy
-- Alternate HTTP
-- For proxy servers
-- Often open in network configs

Port 5000
-- UPnP – universal plug and play
-- Dangerous especially if enabled in routers and other devices
-- Used to exploit UPnP vulnerabilities in IoT devices
-- Gain access or spread access across a network

Port 12345
-- NetBus RAT
-- Default for C2

High-randomized or Dynamic ports
-- Some RATs may select a port in the high range (49152-65535) to avoid detection or bypass firewall rules
-- Typically used for outbound communications after initial compromise

Use of non-standard ports
- Advanced RATs may use ports between 1024-49151 to avoid detection from traditional security monitoring tools
Note: njRAT uses port 1177
---------------------------------------------------------
SAFARI BROWER HISTORY PATHS (IOS)
Based on cross-examination testimony of the cyber-forensics expert in the Karen Read murder trial.

A browser tab with a search that is opened today, will retain the timestamp of today even if the same tab is reused a week/month, etc., from now.
- number_files_full.zip/private/var/mobile/Library/Safari/BrowserState.db-wal: 0x298AC1
- number_files_full.zip/private/var/mobile/Containers/Data/Application/Library/Preferences/com.apple.mobilesafari.plist: 0x2155
- number_files_full.zip/private/var/mobile/CoreDuet/Knowledge/KnowledgeC.db : 0x481569E
---------------------------------------------------------
LIST REGISTRIES USING A RUNNING PID WITH VOLATILITY
Note: These steps are only for the old volatility version.
Note: In REMnux use vol.py -f <mem.dump> imageinfo

Let’s assume we need to find the PID of a running program and what registries are using it.

Open PowerShell in Windows or the terminal screen in REMnux VM and find the image profile:
-- ./volatility_2.6_win64_standalone.exe -f <mem.dump> imageinfo
--- This will take a while to complete depending on the size of the image
-- ./volatility_2.6_win64_standalone.exe -f <mem.dump> kdbgscan
--- You can also use the kdbgscan plugin to scan the kernel debugger and list suggested profiles but it outputs more info

Note: If you need help with the plugins use -h with the command.

Say we found the profiles WinXPSP2x86 and WinXPSP3x86. You can use a generic profile for both 32/64bit OS versions by just using WinXPSP2. There are other generic profiles for other OS versions.
Note: In a PS prompt you can use./volatility_2.6_win64_standalone.exe - -info | more to view generic profiles you can use instead of waiting for one to be identified.

Once you have the profile, find the network connections:
-- ./volatility_2.6_win64_standalone.exe -f <mem.dump> profile=<profile_suggested> netscan
--- If there is no connection captured then this option won’t work

The command above shows all processes that had/have a network connection established (e.g., rundll32.exe with a PID 1896 shows an active connection to a suspected machine).
Now find any process information:
-- ./volatility_2.6_win64_standalone.exe -f <mem.dump> profile=<profile_suggested> psinfo
--- Or netscan, malutil, psscan, pslist,

This last command shows details about each running process. Let’s list the processes a bit more clearly.
Check for all running PIDs now:
-- ./volatility_2.6_win64_standalone.exe -f <mem.dump> profile=<profile_suggested> pslist
--- Write down the PID # you suspect

Now we need to list all the files that are using that running PID #:
-- ./volatility_2.6_win64_standalone.exe -f <mem.dump> profile=<profile_suggested> handles -p <PID#> -t file
--- Replace -p <PID#> with the actual PID number you need

List the registries using that same running PID #:
-- ./volatility_2.6_win64_standalone.exe -f <mem.dump> profile=<profile_suggested> handles -p <PID#> -t key
--- Use -h to see even more options

To view a process tree (Parent > Child) use:
-- ./volatility_2.6_win64_standalone.exe -f <mem.dump> profile=<profile_suggested> pstree
--- Shows you Parent and Child process tree
Notes:
-- To list all options you can use: -h | more
-- To find a specific option use -h | grep malfind

OTHER
Filescan:
-- vol.py -f <mem.dump> profile=<profile_suggested> filescan

Inactive processes:
-- vol.py -f <mem.dump> profile=<profile_suggested> psscan

Process loaded DLLs:
-- vol.py -f <mem.dump> profile=<profile_suggested> dlllist

Process loaded DLLs + running PID:
-- vol.py -f <mem.dump> profile=<profile_suggested> dlllist -p 1896

Dump all DLLs:
-- vol.py -f <mem.dump> profile=<profile_suggested> dlldump -D <output/>

Dump a PE file:
-- vol.py -f <mem.dump> profile=<profile_suggested> dlldump –pid=492 -D out –base=<offset>
--- find the offset with dlllist

Search for commands from attackers via a console shell (cmd.exe):
-- vol.py -f <mem.dump> profile=<profile_suggested> cmdscan   

Get SIDs:
-- vol.py -f <mem.dump> profile=<profile_suggested> getsids
--- Reads the shell command history (default = 50 lines)

Search:
- vol.py -f <mem.dump> profile=<profile_suggested> consoles
---------------------------------------------------------
INSTALLING PYTHON SCRIPTS IN WINDOWS
Get your script from github:
-- git clone https://github.com//the_script.git
--- Command for Linux
--- For Windows, just download the files using the Download button and unzip

Make sure you have python installed:
-- python --version
-- pip --version
Note: If you’re installing python for the first time, make sure you select the option to add it to the environment variables (Windows) and also associate any .py file to it.

Update it:
-- python -m pip install --upgrade pip
--- Works for both OS

Go to the scripts location and download its dependencies:
-- pip install -r requirements.txt
--- Almost all scripts come with the requirements.txt file

To run a script:
-- python <script.py>
--- If you associated the file to python, then just enter the script name and it should run

Note: You can also use pip3 or python3 depending in the OS

PYTHON FIX
- If you get upgrade or incompatible errors, it’s better to downgrade to an older version then try to upgrade it using the commands above. You can also try to upgrade to a newer version. Try both ways. 
- Another issue is that a script may be too old to work with the current python engine. You will have to fix the script itself to make it compatible or get an older version of python for it.
---------------------------------------------------------
 

 

 


 
