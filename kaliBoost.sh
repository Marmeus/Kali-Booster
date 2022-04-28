#!/bin/bash
path=$(pwd)
setxkbmap -layout es
sudo apt-get update
sudo apt-get upgrade -y && sudo apt-get upgrade -y
sudo apt-get install make vim tmux vim-gtk wget openjdk-11-jdk-headless default-jdk xclip ghidra docker.io rlwrap sshuttle apktool -y
# VMWare tools
# sudo apt intall fuse open-vm-tools-desktop -y
# Share folders mount at boot time: echo "@reboot         root    mount-shared-folders" | sudo tee -a /etc/crontab

sudo pip uninstall pip
sudo python2.7 get-pip2.7.py
sudo python3 get-pip3.py
pip2 -V
pip3 -V

# For kirbi2john.py
pip2 install pyasn1


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


echo Overwritting .bashrc
echo ====================
sudo chsh -s /bin/bash $(whoami)
cp bashrc ~/.bashrc

echo Firefox plugins: foxyproxy, cookie-editor, user-agent, wappalyzer
echo =================================================================
echo 
echo CLOSE FIREFOX ONCE THE THE PLUGINS HAVE BEEN INSTALED
wget $(curl https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/ 2>/dev/null | grep -Po 'href="[^"]*">Download file' | awk -F\" '{print $2}')
wget $(curl https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/ 2>/dev/null | grep -Po 'href="[^"]*">Download file' | awk -F\" '{print $2}')
wget $(curl https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/ 2>/dev/null | grep -Po 'href="[^"]*">Download file' | awk -F\" '{print $2}')
wget $(curl https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/ 2>/dev/null | grep -Po 'href="[^"]*">Download file' | awk -F\" '{print $2}')
firefox *.xpi


echo Changing Wallpaper
echo ==================
cp Wallpaper.png ~/Pictures/Wallpaper
sed -if 's/\/usr\/share\/backgrounds\/kali-16x9\/default/.\/Pictures\/Wallpaper.png/g' ~/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-desktop.xml

echo Adding MIBS to snmp
echo ===================
sudo apt install snmp-mibs-downloader -y
sudo cp /etc/snmp/snmp.conf /etc/snmp/snmp.confBkp
echo "" | sudo tee /etc/snmp/snmp.conf

echo "adding Scripts to ~/Scripts"
mkdir ~/Scripts
cp -r Scripts/ ~/Scripts/


echo  ADDING USER ALIASES
==========================================================================
sudo apt-get install gobuster dnsutils chisel libimage-exiftool-perl starkiller mingw-w64 mono-devel -y
echo "setxkbmap es"  >> ~/.bashrc
echo 'mkcd (){ mkdir -p -- "$1" &&    cd -P -- "$1"; }' >> ~/.bashrc
echo "puertos (){ puertos=\$(cat \$1 | tail -n +2 | grep open | awk -F/  '{print \$1}'  ORS=',' | sed 's/.\$//'); echo -n \$puertos | xclip -sel clip; echo \$puertos; } " >> ~/.bashrc
echo "sttysize(){ temp=\$(echo \$(stty size) | awk '{split(\$0,val,\" \"); printf \"stty rows %i columns %i\n\", val[1], val[2]}'); echo \$temp; echo -n \$temp | xclip -sel clip;}" >> ~/.bashrc
echo "alias htb=\"sudo openvpn $PWD/HTB/Marmeus.ovpn\"" >> ~/.bashrc
echo "alias htbr=\"sudo openvpn $PWD/HTB/Marmeus-release.ovpn\"" >> ~/.bashrc
echo "alias htbf=\"sudo openvpn $PWD/HTB/Marmeus-fortress.ovpn\"" >> ~/.bashrc
echo "alias htbv=\"sudo openvpn $PWD/HTB/Marmeus-vip.ovpn\"" >> ~/.bashrc
echo "alias thm=\"sudo openvpn $PWD/THM/Marmeus.ovpn\"" >> ~/.bashrc>> ~/.bashrc
echo "alias rot13=\"tr 'A-Za-z' 'N-ZA-Mn-za-m'\"" >> ~/.bashrc
echo 'alias allports="sudo nmap -v -sS -p- -n -T4 -oN AllPorts.txt"' >> ~/.bashrc
echo 'alias allportsUDP="sudo nmap -v -sU -p- -n -oN AllPortsUDP.txt"' >> ~/.bashrc
echo 'alias portsDepth="sudo nmap -sC -sV -n -T4 -oN PortsDepth.txt -p"' >> ~/.bashrc
echo 'alias vulns="sudo nmap --script vuln -n -T4 -oN VulnsPorts.txt -p"' >> ~/.bashrc
echo 'certificatesDomain(){ echo | openssl s_client -connect $1:443  | openssl x509 -noout -text | grep DNS | sed "s/,/\n/g"; }' >> ~/.bashrc
echo 'alias fixVBox="sudo killall -HUP VBoxClient; VBoxClient --clipboard; VBoxClient --draganddrop; VBoxClient --seamless; VBoxClient --vmsvga"' >> ~/.bashrc

echo 

echo Adding Simbolic Link
echo ====================
mkdir ../HTB
mkdir ../THM
ln -s $(pwd)/../HTB ~/Documents/HTB
ln -s $(pwd)/../THM ~/Documents/THM

echo Unzipping rockyou
echo =================
cd /usr/share/wordlists/
sudo gzip -d rockyou.txt.gz

echo Adding .git to directory-list-2.3-medium.txt
echo ==============================================
sudo sed -i '1s/^/.git\n/' /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 

echo Downloading TOP domains
echo =======================
sudo git clone https://github.com/rbsec/dnscan.git /usr/share/wordlists/TopDomais

echo Downloading SecLists
echo ====================
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

echo      VOLATILITY_2
echo =======================
sudo apt-get install yara python2.7-dev -y
sudo git clone https://github.com/volatilityfoundation/volatility.git /opt/volatility
cd /opt/volatility
sudo python setup.py install
sudo git clone https://github.com/gdabah/distorm.git 
cd distorm
sudo python2.7 setup.py build install
wget https://ftp.dlitz.net/pub/dlitz/crypto/pycrypto/pycrypto-2.6.1.tar.gz
tar -xvzf pycrypto-2.6.1.tar.gz
cd pycrypto-2.6.1
sudo python2.7 setup.py build install


echo      VOLATILITY_3
echo =======================
sudo git clone https://github.com/volatilityfoundation/volatility3.git /opt/volatility3
cd /opt/volatility3
sudo python3 setup.py build 
sudo python3 setup.py install
sudo pip3 install -r requirements.txt

echo        JWT_TOOL
echo =======================
sudo git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool
cd /opt/jwt_tool
sudo python3 -m pip install termcolor cprint pycryptodomex requests
echo 'alias jwt_tool="python3 /opt/jwt_tool/jwt_tool.py"' >> ~/.bashrc

echo   WINDOWS EXPLOIT SUGGESTER
echo =============================
sudo wget https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py -O /opt/windows-exploit-suggester.py
pip2.7 install xlrd==1.2.0
echo 'alias windows-exploit-suggester="python2.7 /opt/windows-exploit-suggester.py"' >> ~/.bashrc

echo       EVIL-WINRM
echo =======================
sudo gem install evil-winrm

echo        STEGSEEK
echo =======================
wget https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb -O /tmp/stegseek.deb
sudo apt install /tmp/stegseek.deb

echo      STEGO-TOOLKIT
echo =======================
sudo docker pull dominicbreuker/stego-toolkit
echo 'alias stego-toolkit="echo 'WIKI: https://github.com/DominicBreuker/stego-toolkit'; sudo docker run -v $(pwd):/data -it dominicbreuker/stego-toolkit:latest /bin/bash"' >> ~/.bashrc

echo     JAVA DECOMPILER
echo =======================
sudo wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar -O /opt/javaDecompiler.jar
echo 'alias javaDecompiler="java -jar /opt/javaDecompiler.jar &>/dev/null &"' >> ~/.bashrc

echo        KERBRUTE
echo =======================
wget wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O /usr/bin/kerbrute
sudo chmod +x /usr/bin/kerbrute

echo        GIT-DUMPER
echo =======================
sudo pip install git-dumper



echo ======================================================================
echo                        POPULATING ~/UTILS/
echo ======================================================================
cd $path
mkdir ~/UTILS/
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O ~/UTILS/LinEnum.sh
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O ~/UTILS/linpeas.sh
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O ~/UTILS/linux-exploit-suggester.sh
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/Release/winPEASany.exe -O ~/UTILS/winPEASany.exe 
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe -O ~/UTILS/winPEASx64.exe
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/x86/Release/winPEASx86.exe -O ~/UTILS/winPEASx86.exe
wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat -O ~/UTILS/winPEAS.bat
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O ~/UTILS/pspy32; chmod +x ~/UTILS/pspy32
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -O ~/UTILS/pspy64; chmod +x ~/UTILS/pspy64
wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1 -O ~/UTILS/PowerUp.ps1
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -O ~/UTILS/PowerView.ps1
wget https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1 -O ~/UTILS/Sherlock.ps1
wget https://gist.githubusercontent.com/joswr1ght/22f40787de19d80d110b37fb79ac3985/raw/50008b4501ccb7f804a61bc2e1a3d1df1cb403c4/easy-simple-php-webshell.php -O ~/UTILS/sws.php
wget https://download.sysinternals.com/files/ProcessMonitor.zip -O ~/UTILS/ProcessMonitor.zip
wget https://download.sysinternals.com/files/AccessChk.zip -O ~/UTILS/AccessChk.zip
wget https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1 -O ~/UTILS/Invoke-Rubeus.ps1
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1 -O ~/UTILS/Invoke-Kerberoast.ps1
cp -r ./MalicousImages/ ~/UTILS/

echo Adding hashcat rules
echo ====================
sudo mkdir /opt/HashcatRules/
sudo wget https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule -O /opt/HashcatRules/OneRuleToRuleThemAll.rule




echo ######################################################################
echo                           REINICIANDO
echo ######################################################################
echo -n "3," && sleep 1 && echo -n "2," && sleep 1 && echo -n "1..." && sleep 1 && echo BOOOM && sudo reboot
