#!/bin/bash
setxkbmap -layout es
sudo apt-get update
sudo apt-get upgrade -y && sudo apt-get dist-upgrade -y
sudo apt-get install make vim tmux vim-gtk wget openjdk-11-jdk-headless default-jdk xclip ghidra -y

# Configurar el teclado
# echo Configurando el teclado...
# sudo dpkg-reconfigure keyboard-configuration

#echo Deshabilitando ping reply
#sudo bash -c 'echo "net.ipv4.icmp_echo_ignore_all=1" >> /etc/sysctl.conf'
#sudo sysctl -p

echo MODIFICANDO .vimrc
echo ==================
cat << EOF > ~/.vimrc
:set number
:set tabstop=4 shiftwidth=4 expandtab 
:set noai nocin nosi inde= 
:syntax on
EOF


echo MODIFICANDO .tmux.conf
echo ======================
cat << EOF > ~/.tmux.conf
set-option -g history-limit 30000
set -g status-right-length 100
set -g status-right "#[fg=colour255,bg=colour000] #(ip -o -4 add show dev tun0 2>/dev/null |  awk {'print \$4'} | cut -f1 -d/) #[fg=colour000,bg=colour11] #((ip -o -4 add show dev eth0 || ip -o -4 add show dev enp0s3) 2>/dev/null |  awk {'print \$4'} | cut -f1 -d/) #[fg=colour255,bg=colour1] #H  #[fg=colour0,bg=colour25] %H:%M |#[fg=colour255] %d/%m/%Y "
EOF


echo MODIFICANDO .bashrc
echo ===================
sudo chsh -s /bin/bash $(whoami)
wget https://raw.githubusercontent.com/Marmeus/Kali-Linux-bashrc/main/bashrc -O ~/.bashrc

echo  INSTALANDO KALI TOOOLS
==========================================================================
sudo apt-get install gobuster dnsutils chisel libimage-exiftool-perl starkiller mingw-w64 mono-devel -y
echo "setxkbmap es"  >> ~/.bashrc
echo 'mkcd (){ mkdir -p -- "$1" &&    cd -P -- "$1"; }' >> ~/.bashrc
echo "puertos (){ puertos=\$(cat \$1 | tail -n +2 | grep open | awk -F/  '{print \$1}'  ORS=',' | sed 's/.\$//'); echo -n \$puertos | xclip -sel clip; echo \$puertos; } " >> ~/.bashrc
echo "sttysize(){ f=\$(mktemp); echo -n stty rows \$(stty size | awk '{print \$1}') >>\$f; echo -n ' '>>\$f; echo -n columns \$(stty size | awk '{print \$2}')>>\$f; cat \$f | xclip -sel clip; cat \$f; echo; }" >> ~/.bashrc
echo "alias htb=\"sudo openvpn $PWD/HTB/Marmeus.ovpn\"" >> ~/.bashrc
echo "alias htbr=\"sudo openvpn $PWD/HTB/Marmeus-release.ovpn\"" >> ~/.bashrc
echo "alias htbf=\"sudo openvpn $PWD/HTB/Marmeus-fortress.ovpn\"" >> ~/.bashrc
echo "alias htbv=\"sudo openvpn $PWD/HTB/Marmeus-vip.ovpn\"" >> ~/.bashrc
echo "alias thm=\"sudo openvpn $PWD/THM/Marmeus.ovpn\"" >> ~/.bashrc>> ~/.bashrc
echo 'alias bashScan="~/Scripts/bashScan"' >> ~/.bashrc
echo "alias rot13=\"tr 'A-Za-z' 'N-ZA-Mn-za-m'\"" >> ~/.bashrc
echo 'alias allports="sudo nmap -sS -p- -n -T5 -oN AllPorts.txt"' >> ~/.bashrc
echo 'alias allportsUDP="sudo nmap -v -sU -p- -n -T5 -oN AllPortsUDP.txt"' >> ~/.bashrc
echo 'alias portsDepth="sudo nmap -sC -sV -n -T5 -oN PortsDepth.txt -p"' >> ~/.bashrc
echo 'alias vulns="sudo nmap --script vuln -n -T5 -oN VulnsPorts.txt -p" >> ~/.bashrc

echo Descomprimiendo rockyou
echo =======================
cd /usr/share/wordlists/
sudo gzip -d rockyou.txt.gz

echo Añadiendo .git a directory-list-2.3-medium.tx
echo =============================================
sudo sed -i '1s/^/.git\n/' /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 

echo Añadiendo links simbólicos
ln -s $(pwd)/HTB ~/Documents/HTB
ln -s $(pwd)/THM ~/Documents/THM

echo Descargando TOP domains
echo =======================
sudo git clone https://github.com/rbsec/dnscan.git /usr/share/wordlists/TopDomais

echo  Descargando SecLists
echo =======================
sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists

echo     Active Directory 
echo =======================
sudo git clone https://github.com/Cryilllic/Active-Directory-Wordlists.git /usr/share/wordlists/Active-Directory

echo         FFUZ
echo =======================
wget https://github.com/ffuf/ffuf/releases/download/v1.3.1/ffuf_1.3.1_linux_amd64.tar.gz -O /tmp/FFUZ.tar.gz
cd /tmp/
tar -xvzf ./FFUZ.tar.gz
sudo cp ./ffuf /usr/bin/

echo        IMPACKET
echo =======================
sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
cd /opt/impacket
pip3 install -r /opt/impacket/requirements.txt
cd /opt/impacket/ && sudo python3 ./setup.py install

echo      VOLATILITY
echo =======================
sudo git clone https://github.com/volatilityfoundation/volatility.git /opt/volatility
cd /opt/volatility
sudo python setup.py install

echo        EMPIRE
echo =======================
sudo git clone https://github.com/BC-SECURITY/Empire/ /opt/Empire
cd /opt/Empire && sudo ./setup/install.sh
echo 'alias empire="cd /opt/Empire/; sudo ./empire"' >> ~/.bashrc

echo     STAR KILLER
echo =======================
cd /opt
sudo wget https://github.com/BC-SECURITY/Starkiller/releases/download/v1.7.0/starkiller-1.7.0.AppImage
sudo chmod +x starkiller-1.7.0.AppImage 
echo 'alias starkiller="/opt/starkiller-1.7.0.AppImage"' >> ~/.bashrc

# echo        GHIDRA
# echo =======================
# wget https://ghidra-sre.org/ghidra_9.2.2_PUBLIC_20201229.zip -O /tmp/ghidra.zip
# cd /tmp/
# unzip ghidra.zip
# mv ghidra_9.2.2_PUBLIC/ ~/Documents/ghidra/
# echo 'alias ghidra="~/Documents/ghidra/ghidraRun"' >> ~/.bashrc

echo       EVIL-WINRM
echo =======================
sudo gem install evil-winrm

echo        STEGSEEK
echo =======================
wget https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb -O /tmp/stegseek.deb
sudo dpkg -i /tmp/stegseek.deb

echo        KERBRUTE
echo =======================
wget wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O /usr/bin/kerbrute
sudo chmod +x /usr/bin/kerbrute

echo        GIT-DUMPER
echo =======================
sudo pip install git-dumper

echo ======================================================================
echo                      DESCARGANDO ENUM SCRIPTS
echo ======================================================================
mkdir ~/UTILS/
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O ~/UTILS/LinEnum.sh
wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh -O ~/UTILS/linpeas.sh
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O ~/UTILS/linux-exploit-suggester.sh
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/Release/winPEASany.exe -O ~/UTILS/winPEASany.exe 
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe -O ~/UTILS/winPEASx64.exe
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/x86/Release/winPEASx86.exe -O ~/UTILS/winPEASx86.exe
wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat -O ~/UTILS/winPEAS.bat
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O ~/UTILS/pspy32; chmod +x ~/UTILS/pspy32
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -O ~/UTILS/pspy64; chmod +x ~/UTILS/pspy64
wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1 -O ~/UTILS/PowerUp.ps1
wget https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1 -O ~/UTILS/Sherlock.ps1
wget https://gist.githubusercontent.com/joswr1ght/22f40787de19d80d110b37fb79ac3985/raw/50008b4501ccb7f804a61bc2e1a3d1df1cb403c4/easy-simple-php-webshell.php -O ~/UTILS/sws.php

echo ######################################################################
echo                           REINICIANDO
echo ######################################################################
echo -n "3," && sleep 1 && echo -n "2," && sleep 1 && echo -n "1..." && sleep 1 && echo BOOOM && sudo reboot
