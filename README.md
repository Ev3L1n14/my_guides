# Collection of my guides
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
- shodan.io / censys.io
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
- Port 80
-- HTTP
-- Most common
-- Hides communication through web traffic

- Port 443
-- HTTPS
-- Communication is encrypted

- Port 21
-- FTP
-- Payload and exfiltration
--- If not in used block it in firewall

- Port 23
-- telnet
-- Less common today
-- Used for remote command execution/system control
--- If not in used block it in firewall

- Port 445
-- SMB - Windows file sharing
-- For lateral movement or gain unauthorized access
-- Older systems use port 138/139
--- If not in used blocked them in firewall

- Port 3389
-- RDP
-- Compromise/control systems
--- If not in used block it in firewall

- Port 6660-6669
-- IRC - Internet relay chat
-- Command and control (C2)
-- Chat and botnet communications

- Port 4444
-- Metasploit
-- Common exploit port
-- To deploy RATs
-- Possible default for exploits/comms

-Port 5555
-- Android Debug Bridge (ADB)
-- Remote access and control

- Port 8080
-- HTTP Proxy
-- Alternate HTTP
-- For proxy servers
-- Often open in network configs

- Port 5000
-- UPnP – universal plug and play
-- Dangerous especially if enabled in routers and other devices
-- Used to exploit UPnP vulnerabilities in IoT devices
-- Gain access or spread access across a network

- Port 12345
-- NetBus RAT
-- Default for C2

- High-randomized or Dynamic ports
-- Some RATs may select a port in the high range (49152-65535) to avoid detection or bypass firewall rules
-- Typically used for outbound communications after initial compromise

- Use of non-standard ports
-- Advanced RATs may use ports between 1024-49151 to avoid detection from traditional security monitoring tools
Note: njRAT uses port 1177
