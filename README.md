# Introduction
The script `kaliBoost.sh` tries to improve Kali Linux by installing new tools, dictionaries and bringing back some tools that doesn't come with kali anymore like the old bashrc stytle and pip2.
Furtheremore, this script creates some usefull aliases that you might need in your pentesting activities and some folders where you can store your shared files from HTB or THM.

# Pre-Installation
1. Because a I have a spanish keyboard it adds the spanish keyboard layout to `.bashrc`, if you have a different layout change it at line 61.
2. The openvpn aliases executes my openvpn files change them by your HackTheBox/tryHackMe name.

# Installation

Because this script creates folders in your shared folder `/media/<shared_folder>/` (VB) o `/mnt/hgfs/<shared_folder>` (VMWare) you need to download the repo in the same shared folder.

```bash
git clone https://github.com/Marmeus/Kali-Booster.git
cd Kali-Booster
chmod +x kaliBoost.sh
./kaliBoost.sh
```

# New Aliases
Sometimes you are tired of executing the same long comand over and over this is why I created the following aliases.
-  **mkcd**: Creates and access the directory.
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
-  **vulns**: Run the vulns nmap scripts against the specified hosts.

# New Wordlists

-  [TopDomains](https://github.com/rbsec/dnscan)
-  [SecLists](https://github.com/danielmiessler/SecLists)
-  [Active Directory](https://github.com/Cryilllic/Active-Directory-Wordlists)
-  Adds `.git` to `directory-list-2.3-medium.txt`

# Hashcat Rules
They are saved at `/opt/HashcatRules/`
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
- STEGO-TOOLKIT
- EVIL-WINRM
- GIT-DUMPER

# Utilies
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
- Malicous images with PHP code

# Brought back
- Default old kali linux `.bashrc`
- Changes the shell to bash.
- Pip2


