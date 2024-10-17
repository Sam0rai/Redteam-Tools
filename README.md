# Redteam-Tools
Tools for the usage of the Red Team.

* **Trusted Installer** <br>
**Purpose:** A Windows privilege Escalation tool which allows a user with an Administrator security-context to elevate their security-context to **NT AUTHORITY\SYSTEM**
  and be a member of the **"TrustedInstaller"** local group. <br>
**Requirements:** User must be an Admin on the local machine. <br>
**Version:** 1.0.

This tool was written in rust, and is a port from FourCoreLab's [POC tool](https://github.com/FourCoreLabs/TrustedInstallerPOC/tree/master), which was written in Golang.
It was created by me as an exercise in understanding Golang code, programming in Rust, as well as getting to know some Windows API calls which are in common use by the Red Team.  

**Note:** The advantage of elevating to **NT AUTHORITY\SYSTEM**, **and** being a member of the **"TrustedInstaller"** local group, is that TrustedInstaller can write or delete certain files 
and folders on the local machine, that even a user running as **NT AUTHORITY\SYSTEM** cannot change.
