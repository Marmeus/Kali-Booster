#!/bin/bash
source ./config.cfg
KALI_BOOSTER_PATH=$(pwd)

echo "SYSTEM PACKAGES"
echo =================
echo Updating package repositories...´
sudo apt-get -qq update >/dev/null
echo 

echo "Upgrading system..."
echo "-------------------"
if [[ $upgrade_system == "true" ]];then
    echo THIS WILL TAKE A LOT OF TIME :D
    sudo apt-get -qq dist-upgrade -y
else
    echo Nope\n\n
fi

echo "Installing Tools"
echo "----------------"
if [[ $tools == "true" ]]; then
    echo "Installing tool packages..."
    sudo apt-get -qq install make vim tmux wget openjdk-11-jdk-headless default-jdk xclip ghidra docker.io rlwrap sshuttle apktool pgp curl sqlite3 python3-virtualenv bat curl virtualenv golang-go gobuster dnsutils chisel libimage-exiftool-perl starkiller mingw-w64 mono-devel python3-venv -y 
else
    echo Nope\n\n
fi

echo "Installing VM requirements"
echo "--------------------------"
if [[ $vm == "VBox" ]]; then
    sudo apt-get -qq install virtualbox-guest-utils -y 
    vboxsf=$(grep vboxsf /etc/group | cut -d ':' -f 3)
    sudo usermod -aG $vboxsf $USER
elif [[ $vm == "VMWare" ]]; then
    sudo apt-get -qq intall fuse open-vm-tools-desktop -y
    # Share folders mount at boot time: 
    echo "@reboot         root    mount-shared-folders" | sudo tee -a /etc/crontab
else
    echo Nope\n\n
fi

echo "Installing PIP"
echo "--------------"
if [[ $install_pip2 == "true" ]]; then
    echo Uninstalling pip3...
    sudo pip uninstall pip >/dev/null
    echo Installing pip2.7....
    sudo python2.7 Assets/get-pip2.7.py >/dev/null
    echo installing pip3...
    sudo python3 Assets/get-pip3.py >/dev/null
    sudo pip2.7 install --upgrade setuptools
    pip2.7 install --upgrade setuptools
    echo Check correct installation
    pip2 -V
    pip3 -V
    # For kirbi2john.py
    pip2 install -q pyasn1
else
    echo Nope\n\n
fi




# Configurar el teclado
# echo Configurando el teclado...
# sudo dpkg-reconfigure keyboard-configuration

echo "PING REPLY"
echo ============
if [[ $disable_ping_reply == "true" ]]; then
    echo Ping reply disabled
    sudo bash -c 'echo "net.ipv4.icmp_echo_ignore_all=1" >> /etc/sysctl.conf'
    sudo sysctl -p
else
    echo Nope\n\n
fi

echo ".VIMRC"
echo ========
if [[ $add_vim_conf == "true" ]]; then
echo Changing .vimrc
cat << EOF > ~/.vimrc
:set number
:set tabstop=4 shiftwidth=4 expandtab 
:set noai nocin nosi inde= 
:syntax on
:noremap Zi <c-w>_ \| <c-w>\|
:noremap Zo <c-w>=
:autocmd FileType * retab
EOF
else
    echo Nope\n\n
fi

echo ".tmux.conf"
echo ============
if [[ $add_tmux_conf == "true" ]]; then
echo changing .tmux.conf
cat << EOF > ~/.tmux.conf
set-option -g history-limit 30000
set -g status-right-length 100
set -g status-right "#[fg=colour255,bg=colour000] #(ip -o -4 add show dev tun0 2>/dev/null |  awk {'print $4'} | cut -f1 -d/) #[fg=colour000,bg=colour11] #(hostname -I | awk '{print $1}') #[fg=colour255,bg=colour1] #H  #[fg=colour0,bg=colour25] %H:%M |#[fg=colour255] %d/%m/%Y "
EOF

# Modify hiustory to avoid duplicates and to store all the commands executed in any pannel
cat << 'EOF' >> ~/.bashrc

# Avoid duplicates
HISTCONTROL=ignoredups:erasedups # Ubuntu default is ignoreboth
# When the shell exits, append to the history file instead of overwriting it
shopt -s histappend  # In Ubuntu this is already set by default

# After each command, append to the history file and reread it
PROMPT_COMMAND="\${PROMPT_COMMAND:+\$PROMPT_COMMAND\$'\n'}history -a; history -c; history -r"
EOF

else
    echo Nope\n\n
fi


echo "Changing user power management"
echo ================================
cat << EOF > ~/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml
<?xml version="1.0" encoding="UTF-8"?>

<channel name="xfce4-power-manager" version="1.0">
  <property name="xfce4-power-manager" type="empty">
    <property name="power-button-action" type="empty"/>
    <property name="show-panel-label" type="empty"/>
    <property name="show-tray-icon" type="bool" value="false"/>
    <property name="blank-on-ac" type="int" value="0"/>
    <property name="dpms-on-ac-sleep" type="uint" value="0"/>
    <property name="dpms-on-ac-off" type="uint" value="0"/>
    <property name="inactivity-on-ac" type="uint" value="14"/>
    <property name="dpms-enabled" type="bool" value="false"/>
  </property>
</channel>
EOF

echo "Adding proxychains"
echo "socks5 127.0.0.1 1080" | sudo tee -a /etc/proxychains4.conf 


echo Overwritting .bashrc
echo ====================
if [[ $terminal=="bash" ]]; then
    sudo chsh -s /bin/bash $(whoami)
    cp Assets/bashrc ~/.bashrc
fi

echo "Changing layout"
echo ================
setxkbmap -layout $keyboard_layout
echo "setxkbmap $keyboard_layout"  >> ~/.bashrc

echo "FIREFOX PLUGINS"
echo =================
if [[ $firefox_plugins == "true" ]]; then
    echo Installing Firefox plugins: foxyproxy, cookie-editor, user-agent, wappalyzer, onetab
    echo NOTE: CLOSE FIREFOX ONCE THE THE PLUGINS HAVE BEEN INSTALED
    wget -q $(curl https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/ 2>/dev/null | grep -Po 'href="[^"]*">Download file' | awk -F\" '{print $2}')
    wget -q $(curl https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/ 2>/dev/null | grep -Po 'href="[^"]*">Download file' | awk -F\" '{print $2}')
    wget -q $(curl https://addons.mozilla.org/en-US/firefox/addon/multi-account-containers/ 2>/dev/null | grep -Po 'href="[^"]*">Download file' | awk -F\" '{print $2}')
    wget -q $(curl https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/ 2>/dev/null | grep -Po 'href="[^"]*">Download file' | awk -F\" '{print $2}')
    wget -q $(curl https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/ 2>/dev/null | grep -Po 'href="[^"]*">Download file' | awk -F\" '{print $2}')
    wget -q $(curl https://addons.mozilla.org/en-US/firefox/addon/multi-account-containers/ 2>/dev/null | grep -Po 'href="[^"]*">Download file' | awk -F\" '{print $2}')
    wget -q $(curl https://addons.mozilla.org/en-US/firefox/addon/onetab/ 2>/dev/null | grep -Po 'href="[^"]*">Download file' | awk -F\" '{print $2}')
    firefox *.xpi
else
    echo Nope\n\n
fi

echo "FIREFOX BOOKMARKS"
echo ==================
if [[ ! $bookmark_links == "" ]]; then
    echo Adding bookmarks...
    bash add_bookmarks.sh "$bookmark_links"
else
    echo Nope\n\n
fi

echo "KALI ICONS"
echo ===========  
cp ./Assets/BurpPro.png ~/Pictures/
cd $KALI_BOOSTER_PATH
if [[ $wallpaper == "./Assets/"* ]]; then
    echo Changing backgroung to Marmeus\' Wallpaper...
    cp $wallpaper ~/Pictures/wallpaper.png
    sed -if "s/\/usr\/share\/backgrounds\/kali-16x9\/default/\/home\/$(whoami)\/Pictures\/wallpaper.png/g" ~/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-desktop.xml
elif [[ ! $wallpaper ]]; then
    # Empty string
    echo No changes were made
    echo -n
else
    echo Changing background to custom Wallpaper...
    cp $wallpaper ~/Pictures/wallpaper.png
fi

if [[ $icon_panel_menu == "./Assets/"* ]]; then
    echo Changing panel menu icon to Marmeus\' icon...
    cp $icon_panel_menu ~/Pictures/button-icon.png
    cp ./Assets/whiskermenu-1.rc ~/.config/xfce4/panel/whiskermenu-1.rc
    sed -if "s/kali-panel-menu/\/home\/$(whoami)\/Pictures\/button-icon.png/g" ~/.config/xfce4/panel/whiskermenu-1.rc
elif [[ ! $icon_panel_menu ]]; then
    # Empty string
    echo No changes were made
else
    echo Changing panel menu icon to custom icon...
    cp "$icon_panel_menu" ~/Pictures/button-icon.png
fi

echo "Adding MIBS to snmp"
echo =====================
sudo apt-get -qq install snmp-mibs-downloader -y
sudo cp /etc/snmp/snmp.conf /etc/snmp/snmp.confBkp
echo "" | sudo tee /etc/snmp/snmp.conf


echo "SCRIPTS"
echo =========
echo "Adding Scripts to ~/Scripts"
mv ./Assets/Scripts/ ~/Scripts/


echo "ALIASES 2 BASHRC"
echo =========
if [[ $aliases_2_bashrc == "true" ]]; then
    echo  Adding aliases...
    echo 'mkcd (){ mkdir -p -- "$1" &&    cd -P -- "$1"; }' >> ~/.bashrc
    echo "puertos (){ puertos=\$(cat \$1 | tail -n +2 | grep open | awk -F/  '{print \$1}'  ORS=',' | sed 's/.\$//'); echo -n \$puertos | xclip -sel clip; echo \$puertos; } " >> ~/.bashrc
    echo "sttysize(){ temp=\$(echo \$(stty size) | awk '{split(\$0,val,\" \"); printf \"stty rows %i columns %i\n\", val[1], val[2]}'); echo \$temp; echo -n \$temp | xclip -sel clip;}" >> ~/.bashrc
    echo "encrypt(){ tar -czf - \$1 | openssl enc -e -aes256 -pbkdf2 -out \$(echo -n \$1 | sed 's/\/$//').tar.gz.enc; }" >> ~/.bashrc
    echo 'decrypt(){ openssl enc -d -aes256 -pbkdf2 -in $1 | tar -xvzf -; }' >> ~/.bashrc
    echo "alias rot13=\"tr 'A-Za-z' 'N-ZA-Mn-za-m'\"" >> ~/.bashrc
    echo 'alias allports="sudo nmap -v -sS -p- -n -T4 -oN AllPorts.txt"' >> ~/.bashrc
    echo 'alias allportsUDP="sudo nmap -v -sU -p- -n -oN AllPortsUDP.txt"' >> ~/.bashrc
    echo 'alias portsDepth="sudo nmap -sC -sV -n -T4 -oN PortsDepth.txt -p"' >> ~/.bashrc
    echo 'alias vulns="sudo nmap --script vuln -n -T4 -oN VulnsPorts.txt -p"' >> ~/.bashrc
    echo 'certificatesDomain(){ echo | openssl s_client -connect $1:443  | openssl x509 -noout -text | grep DNS | sed "s/,/\n/g"; }' >> ~/.bashrc
    echo 'alias fixVBox="sudo killall -HUP VBoxClient; VBoxClient --clipboard; VBoxClient --draganddrop; VBoxClient --seamless; VBoxClient --vmsvga"' >> ~/.bashrc
else
    echo Nope\n\n
fi
echo 

echo "THM"
echo =====
if [[ ! $thm_vpn_path == "" ]]; then
    echo Setting VPN...
    mkdir ~/Documents/THM
    ln -s $(dirname $thm_vpn_path) ~/Documents/THM
    echo "alias thm=\"sudo openvpn $thm_vpn_path\"" >> ~/.bashrc
    
else
    echo Nope\n\n
fi

echo "HTB"
echo =====
if [[ ! $htb_vpn_path == "" ]]; then
    echo Setting VPN...
    mkdir ~/Documents/HTB
    ln -s $(dirname $htb_vpn_path) ~/Documents/HTB
    echo "alias htb=\"sudo openvpn $htb_vpn_path\"" >> ~/.bashrc
else
    echo Nope\n\n
fi

echo "WORDLISTS"
echo ===========
echo Unzipping rockyou...
cd /usr/share/wordlists/
sudo gzip -d rockyou.txt.gz

echo "Adding more wordlists"
echo "---------------------"
if [[ $wordlists == "true" ]]; then
    WORDLIST_PATH=/usr/share/wordlists/Marmeus/
    echo Adding .git to directory-list-2.3-medium.txt
    sudo sed -i '1s/^/.git\n/' /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
    
    echo Downloading TOP domains
    sudo git clone -q https://github.com/rbsec/dnscan.git /usr/share/wordlists/TopDomais
    
    echo Downloading SecLists
    sudo git clone -q https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
    
    echo Active Directory 
    sudo git clone -q https://github.com/Cryilllic/Active-Directory-Wordlists.git /usr/share/wordlists/Active-Directory
    
    echo Kerberos Users List 
    sudo git clone -q https://github.com/attackdebris/kerberos_enum_userlists /usr/share/wordlists/kerberos_enum_userlists

    sudo mkdir $WORDLIST_PATH

    echo Movin SQLi Auth Bypass - Master List
    sudo mv $KALI_BOOSTER_PATH/Assets/Wordlists/SQLi $WORDLIST_PATH

    echo Moving XSS Payloads
    sudo mv $KALI_BOOSTER_PATH/Assets/Wordlists/XSS $WORDLIST_PATH

    echo Moving LFI payloads
    sudo mv $KALI_BOOSTER_PATH/Assets/Wordlists/LFI $WORDLIST_PATH

    echo Moving RCE payloads
    sudo mv $KALI_BOOSTER_PATH/Assets/Wordlists/RCE $WORDLIST_PATH

    echo Moving Open Redirect payloads
    sudo mv $KALI_BOOSTER_PATH/Assets/Wordlists/Open_redirect.txt $WORDLIST_PATH

    echo Moving Filename extensions
    sudo mv $KALI_BOOSTER_PATH/Assets/Wordlists/Filename_extensions.txt $WORDLIST_PATH

    echo Moving JWT secrets list
    sudo mv $KALI_BOOSTER_PATH/Assets/Wordlists/JWT_secrets.txt $WORDLIST_PATH
else
    echo Nope\n\n
fi

echo "HACK FONT"
echo ===========
echo Installing Hack font...
cd /tmp/
wget -q https://github.com/source-foundry/Hack/releases/download/v3.003/Hack-v3.003-ttf.zip -O Hack-font.zip
unzip Hack-font.zip >/dev/null
sudo mv ttf/ /usr/share/fonts/

echo "TOOLS"
echo =======

if [[ $tools == "true" ]]; then
    mkdir -p ~/Tools/Web/
    
    echo Installing FFUZ...
    wget -q https://github.com/ffuf/ffuf/releases/download/v1.3.1/ffuf_1.3.1_linux_amd64.tar.gz -O /tmp/FFUZ.tar.gz
    cd /tmp/
    tar -xvzf ./FFUZ.tar.gz >/dev/null
    sudo cp ./ffuf /usr/bin/
   
    echo Installing bypass-url-parser...
    git clone -q https://github.com/laluka/bypass-url-parser.git ~/Tools/Web/bypass-url-parser
    cd ~/Tools/Web/bypass-url-parser
    virtualenv -p python3 .py3
    source .py3/bin/activate
    pip install -q -r requirements.txt 2>&1 >/dev/null
    deactivate 
    
    echo Installing dontgo403...
    git clone -q https://github.com/devploit/dontgo403 ~/Tools/Web/dontgo403; 
    cd ~/Tools/Web/dontgo403; 
    go get 2>&1 >/dev/null
    go build 2>&1 >/dev/null
    
    echo Installing forbidden...
    git clone -q https://github.com/ivan-sincek/forbidden ~/Tools/Web/forbidden
    cd ~/Tools/Web/forbidden/src/
    pip3 install -q -r requirements.txt 2>&1 >/dev/null
    
    echo Installing byp4xx...
    git clone https://github.com/lobuhi/byp4xx.git ~/Tools/Web/byp4xx
    cd ~/Tools/Web/byp4xx
    chmod u+x byp4xx.py

    echo Installing httpx...
    cd /tmp/
    wget -q $(curl -sq https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep -E 'https.*_linux_amd64.zip' | cut -d '"' -f 4) -O httpx.zip; 
    unzip -q httpx.zip; 
    sudo mv httpx /usr/bin/

    echo Installing rustscan...
    wget -q https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb -O rustscan.deb
    sudo apt-get -qqy install /tmp/rustscan.deb 2>&1 >/dev/null

    echo Installing Impacket...
    sudo git clone -q https://github.com/SecureAuthCorp/impacket.git /opt/impacket
    cd /opt/impacket
    pip3 install -q -r /opt/impacket/requirements.txt 2>&1 >/dev/null
    cd /opt/impacket/ && sudo python3 ./setup.py install 2>&1 >/dev/null
    
    #echo Installing Volatility 2...
    #sudo apt-get -qq install yara python2.7-dev -y
    #sudo git clone -q https://github.com/volatilityfoundation/volatility.git /opt/volatility
    #cd /opt/volatility
    #sudo python setup.py install 2>&1 >/dev/null
    #echo Volatility 2: distorm plugin...
    #sudo git clone -q https://github.com/gdabah/distorm.git
    #cd distorm
    #sudo python2.7 setup.py build install 2>&1 >/dev/null
    #echo Volatility 2: pycrypto  plugin...
    #wget -q https://ftp.dlitz.net/pub/dlitz/crypto/pycrypto/pycrypto-2.6.1.tar.gz
    #tar -xvzf pycrypto-2.6.1.tar.gz >/dev/null
    #cd pycrypto-2.6.1
    #sudo python2.7 setup.py build install 2>&1 >/dev/null
    #   
    #   
    #echo Installing Volatility 3
    #sudo git clone -q  https://github.com/volatilityfoundation/volatility3.git /opt/volatility3
    #cd /opt/volatility3
    #sudo python3 setup.py build 2>&1 >/dev/null
    #sudo python3 setup.py install 2>&1 >/dev/null
    #sudo pip3 install -q -r requirements.txt 2>&1 >/dev/null

    
    echo Installing JWT_TOOL...
    sudo git clone -q https://github.com/ticarpi/jwt_tool /opt/jwt_tool
    cd /opt/jwt_tool
    sudo python3 -m pip install -q termcolor cprint pycryptodomex requests 2>&1 >/dev/null
    echo 'alias jwt_tool="python3 /opt/jwt_tool/jwt_tool.py"' >> ~/.bashrc
    
    echo Installing Windows Exploit Suggester...
    sudo wget -q https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py -O /opt/windows-exploit-suggester.py
    pip2.7 install -q xlrd==1.2.0
    echo 'alias windows-exploit-suggester="python2.7 /opt/windows-exploit-suggester.py"' >> ~/.bashrc
    
    echo Installing EVIL-WINRM...
    sudo gem install evil-winrm 2>&1 >/dev/null
    
    echo Installing STEGSEEK...
    wget -q https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb -O /tmp/stegseek.deb
    sudo apt-get -qq install /tmp/stegseek.deb 
    
    echo Installing STEGO-TOOLKIT...
    sudo docker pull dominicbreuker/stego-toolkit >/dev/null
    echo 'alias stego-toolkit="echo 'WIKI: https://github.com/DominicBreuker/stego-toolkit'; sudo docker run -v $(pwd):/data -it dominicbreuker/stego-toolkit:latest /bin/bash"' >> ~/.bashrc
    
    echo Installing Java decompiler >/dev/null
    sudo wget -q https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar -O /opt/javaDecompiler.jar
    echo 'alias javaDecompiler="java -jar /opt/javaDecompiler.jar &>/dev/null &"' >> ~/.bashrc
    
    echo Installing KERBRUTE...
    sudo wget -q https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O /usr/bin/kerbrute
    sudo chmod +x /usr/bin/kerbrute
    
    echo Installing GIT-DUMPER...
    sudo pip install -q git-dumper 2>&1 >/dev/null
    
    
    echo Installing VS CODE...
    cd /tmp
    wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
    sudo install -o root -g root -m 755 packages.microsoft.gpg /etc/apt/trusted.gpg.d/
    sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
    rm -f packages.microsoft.gpg
    sudo apt-get -qq install apt-transport-https
    sudo apt-get -qq update
    sudo apt-get -qq install code -y 
else
    echo Nope\n\n
fi

echo "UTILITIES"
echo ===========
if [[ ! $utilities_path == "" ]]; then
    cd $KALI_BOOSTER_PATH
    echo Populating utilities at $utilities_path
    mkdir $utilities_path
    cp -r ./Assets/MaliciousImages/ ~/Pictures/
    unzip -o -P "Documents" -d "~/Documents/" ./Assets/Documents.zip
    cp -r ./Assets/HTMLs ~/.
    cd $utilities_path
    wget -q https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O LinEnum.sh
    wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O linpeas.sh
    wget -q https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O linux-exploit-suggester.sh
    wget -q https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/Release/winPEASany.exe -O winPEASany.exe 
    wget -q https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe -O winPEASx64.exe
    wget -q https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/x86/Release/winPEASx86.exe -O winPEASx86.exe
    wget -q https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat -O winPEAS.bat
    wget -q https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O ~/UTILS/pspy32; chmod +x pspy32
    wget -q https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -O ~/UTILS/pspy64; chmod +x pspy64
    wget -q https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1 -O PowerUp.ps1
    wget -q https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -O PowerView.ps1
    wget -q https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1 -O Sherlock.ps1
    wget -q https://gist.githubusercontent.com/joswr1ght/22f40787de19d80d110b37fb79ac3985/raw/50008b4501ccb7f804a61bc2e1a3d1df1cb403c4/easy-simple-php-webshell.php -O sws.php
    wget -q https://download.sysinternals.com/files/ProcessMonitor.zip -O ProcessMonitor.zip
    wget -q https://download.sysinternals.com/files/AccessChk.zip -O AccessChk.zip
    wget -q https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1 -O Invoke-Rubeus.ps1
    wget -q https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1 -O Invoke-Kerberoast.ps1
else
    echo Nope\n\n
fi

echo Adding hashcat rules
echo ====================
sudo mkdir /opt/HashcatRules/
sudo wget -q https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule -O /opt/HashcatRules/OneRuleToRuleThemAll.rule
sudo wget -q https://raw.githubusercontent.com/kaonashi-passwords/Kaonashi/refs/heads/master/masks/kaonashi.hcmask -O /opt/HashcatRules/kaonashi.hcmask


echo ######################################################################
echo                           REINICIANDO
echo ######################################################################
echo -n "3," && sleep 1 && echo -n "2," && sleep 1 && echo -n "1..." && sleep 1 && echo BOOOM && sudo reboot
