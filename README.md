# my_guides
Collection of my forensic guides








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
