# Introduction
The script `kaliBoost.sh` tries to improve Kali Linux by installing new tools and dictionaries and bringing back some tools that don't come with kali anymore, like the old bashrc style and pip2.
Furthermore, this script creates some useful aliases that you might need in your pentesting activities and some folders where you can store your shared files from HTB or THM.

# Pre-Installation
I have added a `config.cfg` where you need to choose:

* Tools to be installed (**Default**: All)
* The keyboard layout (**Default**: es)
* The hypervisor you are using (VBox or VMWare ) (**Default**: VBox)
* Add configuration files (**Default**: true)
* ....

I encourage you to check it out before executing the script. Also, for the variables with a path, if you do not want to be executed that part of the script, just remove the whole path like `wallpaper=`.

# Installation

Because this script creates folders in your shared folder `/media/<shared_folder>/` (VB) o `/mnt/hgfs/<shared_folder>` (VMWare) you need to download the repo in the same shared folder.

```bash
git clone https://github.com/Marmeus/Kali-Booster.git
cd Kali-Booster
chmod +x kaliBoost.sh
./kaliBoost.sh
```
# What does it do?

## New Wallpaper

Changes the default Kali-Linux wallpaper but the one stored at `./Wallpaper.png`. The actual wallpaper was made by [Samiel](https://www.teepublic.com/user/samiel).

## Hack font

Install the [Hack](https://github.com/source-foundry/Hack) font on the system.

# New Aliases
Sometimes you are tired of executing the same long command over and over this is why I created the following aliases.
-  **mkcd**: Creates and accesses the directory.
-  **sttysize**: Sends to your clipboard the command `stty rows X columns Y` with the correct rows and columns for your full TTY shell. 
- **rot13**: Does rot13 to the input sent through a pipe.
-  **htb**: Starts openvpn for hackthebox.
-  **htbr**: Starts openvpn for hackthebox release arena.
-  **htbf**: Starts openvpn for hackthebox fortress.
-  **thm**: Starts openvpn for hackthebox tryhackme arena.
-  **certificatesDomain**: Obtains the domains of the certificate of the specified URL.
-  **allports**: Obtains all opened TCP ports from the specified hosts.
-  **allportsUDP**: Obtains all opened UDP ports from the specified hosts.
-  **puertos**: Sends to your clipboard all opened ports obtained from the stored output of **allports** and **allportsUDP**. A file must be specified. 
-  **portsDepth**: Scan the specified ports to the specified IPs.
-  **vulns**: Run the vulns Nmap scripts against the specified hosts.

# New Wordlists

-  [TopDomains](https://github.com/rbsec/dnscan)
-  [SecLists](https://github.com/danielmiessler/SecLists)
-  [Active Directory](https://github.com/Cryilllic/Active-Directory-Wordlists)
-  Adds `.git` to `directory-list-2.3-medium.txt`
-  SQLi Auth Bypass - Master List

# Hashcat Rules
Added hashcat rules at `/opt/HashcatRules/`
- OneRuleToRuleThemAll

# Tools
- [FFUZ](https://github.com/ffuf/ffuf/)
- [Impacket](https://github.com/ffuf/ffuf)
- [Volatility2](https://github.com/volatilityfoundation/volatility) aka. `vol.py`
- [Volatility3](https://github.com/volatilityfoundation/volatility3) aka. `vol`
- [JWT_TOOL](https://github.com/ticarpi/jwt_tool)
- [WINDOWS EXPLOIT SUGGESTER](https://github.com/AonCyberLabs/Windows-Exploit-Suggester/)
- [KERBRUTE](https://github.com/ropnop/kerbrute/)
- [STEGSEEK](https://github.com/RickdeJager/stegseek/)
- [STEGO-TOOLKIT](https://github.com/DominicBreuker/stego-toolkit)
- [EVIL-WINRM](https://github.com/Hackplayers/evil-winrm)
- [GIT-DUMPER](https://github.com/arthaud/git-dumper)

# Firefox plugins
- [Foxy-Proxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) & add proxies
- [Wappalyzer](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/)
- [User-Agent editor](https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/)
- [Cookie-Editor](https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/)

# Custom Scripts
Some useful scripts are downloaded to `~/Scripts`.

- **checkSMBPermissions**: Checks the permissions of each SMB disk share because tools like smbmap can sometimes through false positives.

  ```bash
  kali@kali:~/Documents/Scripts$ ./checkSMBPermissions.sh <DOMAIN\\USER> <PASSWORD> <IP>
  Checking share: 'ADMIN$'
  Checking share: 'C$'
  Checking share: 'D$'
  Checking share: 'print$'
    - <USER> has READ access
  Checking share: 'bills$'
    - <USER> has READ WRITE access
  ```

- **massScan.sh**: Scans all the hosts in a given network, creating a folder structure which can be very handy for later steps in a pentest.

```bash
kali@kali:~/Documents/Scripts$ ./massScan.sh 192.168.1.1/24 /tmp/massScan/
ali@kali:/tmp$ tree /tmp/massScan/
/tmp/results
├── 192.168.1.1
│   ├── AllPorts.gnmap
│   ├── AllPorts.nmap
│   └── AllPorts.xml
├── 192.168.1.2
│   ├── AllPorts.gnmap
│   ├── AllPorts.nmap
│   └── AllPorts.xml
[...]
```

- **massScan_depth.sh**: Based on the output of `massScan.sh`, it makes a Nmap with default scripts to get more information about each opened port.

```bash
kali@kali:~/Documents/Scripts$ ./massScan_depth.sh /tmp/massScan/
kali@kali:~/Documents/Scripts$ tree /tmp/massScan/
/tmp/massScan/
├── 192.168.1.1
│   ├── AllPorts.gnmap
│   ├── AllPorts.nmap
│   ├── AllPorts.xml
│   └── PortsDepth.txt
├── 192.168.1.229
│   ├── AllPorts.gnmap
│   ├── AllPorts.nmap
│   ├── AllPorts.xml
│   └── PortsDepth.txt
[...]
```

# Utilities
Interesting files at `~/UTILS/` that might be usefull during an attack.

- LinEnum
- Linpeas
- LinuxExploitSuggester
- WinPeas
- pspy
- PowerUp
- PowerView
- Shelock
- POSTMAN
- easy-simple-php-webshell.php
- ProcessMonitor
- AccessChk
- Invoke-Rubeus.ps1
- Invoke-Kerberoast.ps1
- Malicous images with PHP code. **Made by**: [x4v1l0k](https://twitter.com/x4v1l0k)

# Changes kali behaviour
- Doesn't lock screen or suspend the machine.
- Configure proxychains

# Brought back
- Default old kali linux `.bashrc`
- Changes the shell to bash.
- Pip2

