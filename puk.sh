#!/bin/bash

# Color
N="\033[0m"
BD="\033[1m"
R="\033[0;31m"
G="\033[0;32m"
B="\033[0;34m"
Y="\033[0;33m"
C="\033[0;36m"
P="\033[0;35m"
LR="\033[1;31m"
LG="\033[1;32m"
LB="\033[1;34m"
RB="\033[41;37m"
GB="\033[42;37m"
BB="\033[44;37m"

# Notification
OK="[ ${LG}OK${N} ]"
ERROR="[ ${LR}ERROR${N} ]"
INFO="[ ${C}INFO${N} ]"

# Source
repo="https://raw.githubusercontent.com/skynetcenter/ubuntu-vpn/main/"

# Check Services
check_run() {
	if [[ "$(systemctl is-active $1)" == "active" ]]; then
		echo -e "${OK} Service $1 is running${N}"
		sleep 1
	else
		echo -e "${ERROR} Service $1 is not running${N}\n"
		exit 1
	fi
}
check_screen() {
	if screen -ls | grep -qw $1; then
		echo -e "${OK} Service $1 is running${N}"
		sleep 1
	else
		echo -e "${ERROR} Service $1 is not running${N}\n"
		exit 1
	fi
}
check_install() {
	if [[ 0 -eq $? ]]; then
		echo -e "${OK} Package $1 is installed${N}"
		sleep 1
	else
		echo -e "${ERROR} Package $1 is not installed${N}\n"
		exit 1
	fi
}

clear

# Check Environment
os_check() {
	source '/etc/os-release'
	if [[ "${ID}" != "ubuntu" && $(echo "${VERSION_ID}") != "20.04" ]]; then
		echo -e "${ERROR} Autoscript only supported on Ubuntu 20.04${N}\n"
		exit 1
	fi
}
echo -e "${INFO} ${B}Checking environment ...${N}"
sleep 1
if [[ $EUID -ne 0 ]]; then
	echo -e "${ERROR} Autoscript must be run as root${N}\n"
	exit 1
fi
apt update > /dev/null 2>&1
apt install -y virt-what > /dev/null 2>&1
if ! [[ "$(virt-what)" == "kvm" || "$(virt-what)" == "hyperv" ]]; then
	echo -e "${ERROR} Autoscript only supported on KVM virtualization${N}\n"
	exit 1
fi
os_check

# Update Packages
echo -e "${INFO} ${B}Updating packages ...${N}"
sleep 1
apt update > /dev/null 2>&1
apt upgrade -y > /dev/null 2>&1
apt autoremove -y > /dev/null 2>&1

# Install Dependencies
echo -e "${INFO} ${B}Installing autoscript dependencies ...${N}"
apt install -y systemd curl wget screen cmake zip unzip vnstat tar openssl git uuid-runtime > /dev/null 2>&1
check_install "systemd curl wget screen cmake unzip vnstat tar openssl git uuid-runtime"

# Optimize Settings
echo -e "${INFO} ${B}Optimizing settings ...${N}"
sleep 1
sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
echo -e "* soft nofile 65536
* hard nofile 65536" >> /etc/security/limits.conf
locale-gen en_US > /dev/null 2>&1

# Set Timezone
echo -e "${INFO} ${B}Set timezone Asia/Kuala_Lumpur GMT +08 ...${N}"
sleep 1
ln -sf /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime
systemctl start systemd-timesyncd
date

# Disable IPv6
echo -e "${INFO} ${B}Disabling IPv6 ...${N}"
sleep 1
sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1 > /dev/null 2>&1
echo -e "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1

# Enable BBR
echo -e "Select congestion control or press enter to select default"
echo -e " [1] BBR (default)"
echo -e " [2] BBRPlus"
echo -e "Select: \c"
read tcp
case $tcp in
1)
  tcp="bbr"
  ;;
2)
  tcp="bbrplus"
  ;;
*)
  tcp="bbr"
  ;;
esac
echo -e "Select queue algorithm or press enter to select default"
echo -e " [1] FQ (default)"
echo -e " [2] FQ-Codel"
echo -e " [3] FQ-PIE"
echo -e " [4] Cake"
echo -e "Select: \c"
read queue
case $queue in
1)
  queue="fq"
  ;;
2)
  queue="fq_codel"
  ;;
3)
  queue="fq_pie"
  ;;
4)
  queue="cake"
  ;;
*)
  queue="fq"
  ;;
esac
echo -e "Enable ECN or press enter to select default"
echo -e " [1] OFF (default)"
echo -e " [2] ON"
echo -e " [3] Inbound request only"
echo -e "Select: \c"
read ecn
case $ecn in
1)
  ecn="0"
  ;;
2)
  ecn="1"
  ;;
3)
  ecn="2"
  ;;
*)
  ecn="0"
  ;;
esac
echo -e "${INFO} ${B}Enabling ${tcp} + ${queue} ...${N}"
sleep 1
sysctl -w net.ipv4.tcp_congestion_control=$tcp > /dev/null 2>&1
echo "net.ipv4.tcp_congestion_control = $tcp" >> /etc/sysctl.conf
sysctl -w net.core.default_qdisc=$queue > /dev/null 2>&1
echo "net.core.default_qdisc = $queue" >> /etc/sysctl.conf
sysctl -w net.ipv4.tcp_ecn=$ecn > /dev/null 2>&1
echo "net.ipv4.tcp_ecn = $ecn" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1

# Reset Iptables
echo -e "${INFO} ${B}Resetting Iptables ...${N}"
sleep 1
apt install -y iptables-persistent > /dev/null 2>&1
check_install iptables-persistent
ufw disable > /dev/null 2>&1
iptables-save | awk '/^[*]/ { print $1 } 
                     /^:[A-Z]+ [^-]/ { print $1 " ACCEPT" ; }
                     /COMMIT/ { print $0; }' | iptables-restore

# Configure Cron
if [ $(dpkg-query -W -f='${Status}' cron 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
	echo -e "${INFO} ${B}Installing Cron ...${N}"
	sleep 1
	apt install -y cron > /dev/null 2>&1
	check_install cron
fi
echo -e "${INFO} ${B}Configuring Cron ...${N}"
sleep 1
mkdir /metavpn
wget -O /metavpn/cron.daily "${repo}files/cron.daily" > /dev/null 2>&1
chmod +x /metavpn/cron.daily
(crontab -l; echo "0 6 * * * /metavpn/cron.daily") | crontab -

# Configure SSH
echo -e "${INFO} ${B}Configuring SSH ...${N}"
sleep 1
echo "" > /etc/issue.net
echo "       ▒█▀▄▀█ ▒█▀▀▀ ▀▀█▀▀ ░█▀▀█ ▒█░░▒█ ▒█▀▀█ ▒█▄░▒█" >> /etc/issue.net
echo "       ▒█▒█▒█ ▒█▀▀▀ ░▒█░░ ▒█▄▄█ ░▒█▒█░ ▒█▄▄█ ▒█▒█▒█" >> /etc/issue.net
echo "       ▒█░░▒█ ▒█▄▄▄ ░▒█░░ ▒█░▒█ ░░▀▄▀░ ▒█░░░ ▒█░░▀█" >> /etc/issue.net
echo "       ==========A C C E S S  S E R V E R==========" >> /etc/issue.net
echo "" >> /etc/issue.net
sed -i "s/#Banner none/Banner \/etc\/issue.net/g" /etc/ssh/sshd_config
mkdir /metavpn/ssh
touch /metavpn/ssh/ssh-clients.txt
systemctl restart ssh
check_run ssh

# Install Dropbear
echo -e "${INFO} ${B}Installing Dropbear ...${N}"
sleep 1
apt install -y dropbear > /dev/null 2>&1
check_install dropbear
echo -e "${INFO} ${B}Configuring Dropbear ...${N}"
sleep 1
sed -i "s/NO_START=1/NO_START=0/g" /etc/default/dropbear
sed -i "s/DROPBEAR_PORT=22/DROPBEAR_PORT=85/g" /etc/default/dropbear
echo -e "/bin/false" >> /etc/shells
wget -O /etc/dropbear_issue.net "${repo}files/dropbear_issue.net" > /dev/null 2>&1
sed -i 's+DROPBEAR_BANNER=""+DROPBEAR_BANNER="/etc/dropbear_issue.net"+g' /etc/default/dropbear
systemctl restart dropbear
check_run dropbear

# Install Stunnel
echo -e "${INFO} ${B}Installing Stunnel ...${N}"
sleep 1
apt install -y stunnel4 > /dev/null 2>&1
check_install stunnel4
echo -e "${INFO} ${B}Configuring Stunnel ...${N}"
sleep 1
sed -i "s/ENABLED=0/ENABLED=1/g" /etc/default/stunnel4
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -sha256 -subj "/CN=Meta VPN/emailAddress=admin@metavpn.tk/O=Upcloud Ltd/OU=Meta VPN/C=MY" -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem > /dev/null 2>&1
wget -O /etc/stunnel/stunnel.conf "${repo}files/stunnel.conf" > /dev/null 2>&1
systemctl restart stunnel4
check_run stunnel4

# Install OpenVPN
echo -e "${INFO} ${B}Installing OpenVPN ...${N}"
sleep 1
apt install -y openvpn > /dev/null 2>&1
check_install openvpn
echo -e "${INFO} ${B}Configuring OpenVPN ...${N}"
sleep 1
wget "${repo}files/openvpn/EasyRSA-3.0.8.tgz" > /dev/null 2>&1
tar xvf EasyRSA-3.0.8.tgz > /dev/null 2>&1
mv EasyRSA-3.0.8 /etc/openvpn/easy-rsa
cp /etc/openvpn/easy-rsa/vars.example /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_COUNTRY\t"US"/set_var EASYRSA_REQ_COUNTRY\t"MY"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_PROVINCE\t"California"/set_var EASYRSA_REQ_PROVINCE\t"Wilayah Persekutuan"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_CITY\t"San Francisco"/set_var EASYRSA_REQ_CITY\t"Kuala Lumpur"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_ORG\t"Copyleft Certificate Co"/set_var EASYRSA_REQ_ORG\t\t"Upcloud Ltd"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_EMAIL\t"me@example.net"/set_var EASYRSA_REQ_EMAIL\t"admin@metavpn.tk"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_OU\t\t"My Organizational Unit"/set_var EASYRSA_REQ_OU\t\t"Meta VPN"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_CA_EXPIRE\t3650/set_var EASYRSA_CA_EXPIRE\t3650/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_CERT_EXPIRE\t825/set_var EASYRSA_CERT_EXPIRE\t3650/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_CN\t\t"ChangeMe"/set_var EASYRSA_REQ_CN\t\t"Meta VPN"/g' /etc/openvpn/easy-rsa/vars
cd /etc/openvpn/easy-rsa
./easyrsa --batch init-pki > /dev/null 2>&1
./easyrsa --batch build-ca nopass > /dev/null 2>&1
./easyrsa gen-dh > /dev/null 2>&1
./easyrsa build-server-full server nopass > /dev/null 2>&1
cd
mkdir /etc/openvpn/key
cp /etc/openvpn/easy-rsa/pki/issued/server.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn/key/
wget -O /etc/openvpn/server-udp.conf "${repo}files/openvpn/server-udp.conf" > /dev/null 2>&1
wget -O /etc/openvpn/server-tcp.conf "${repo}files/openvpn/server-tcp.conf" > /dev/null 2>&1
sed -i "s/#AUTOSTART="all"/AUTOSTART="all"/g" /etc/default/openvpn
echo -e "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1
rm EasyRSA-3.0.8.tgz
iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE
systemctl start openvpn@server-udp
systemctl start openvpn@server-tcp
systemctl enable openvpn@server-udp > /dev/null 2>&1
systemctl enable openvpn@server-tcp > /dev/null 2>&1
check_run openvpn@server-udp
check_run openvpn@server-tcp

# Configure OpenVPN Client
echo -e "${INFO} ${B}Configuring OpenVPN client ...${N}"
sleep 1
mkdir /metavpn/openvpn
wget -O /metavpn/openvpn/client-udp.ovpn "${repo}files/openvpn/client-udp.ovpn" > /dev/null 2>&1
wget -O /metavpn/openvpn/client-tcp.ovpn "${repo}files/openvpn/client-tcp.ovpn" > /dev/null 2>&1
sed -i "s/xx/$ip/g" /metavpn/openvpn/client-udp.ovpn
sed -i "s/xx/$ip/g" /metavpn/openvpn/client-tcp.ovpn
echo -e "\n<ca>" >> /metavpn/openvpn/client-tcp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /metavpn/openvpn/client-tcp.ovpn
echo -e "</ca>" >> /metavpn/openvpn/client-tcp.ovpn
echo -e "\n<ca>" >> /metavpn/openvpn/client-udp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /metavpn/openvpn/client-udp.ovpn
echo -e "</ca>" >> /metavpn/openvpn/client-udp.ovpn

# Install Squid
echo -e "${INFO} ${B}Installing Squid ...${N}"
sleep 1
apt install -y squid > /dev/null 2>&1
check_install squid
wget -O /etc/squid/squid.conf "${repo}files/squid.conf" > /dev/null 2>&1
sed -i "s/xx/$domain/g" /etc/squid/squid.conf
sed -i "s/ip/$ip/g" /etc/squid/squid.conf
systemctl restart squid
check_run squid

# Install Open HTTP Puncher
echo -e "${INFO} ${B}Installing OHP server ...${N}"
sleep 1
apt install -y python > /dev/null 2>&1
check_install python
wget -O /usr/bin/ohpserver "${repo}files/ohpserver" > /dev/null 2>&1
chmod +x /usr/bin/ohpserver
screen -AmdS ohp-dropbear ohpserver -port 3128 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:85
screen -AmdS ohp-openvpn ohpserver -port 8000 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:1194
check_screen ohp-dropbear
check_screen ohp-openvpn

# Install BadVPN UDPGW
echo -e "${INFO} ${B}Installing BadVPN UDPGW ...${N}"
sleep 1
wget -O badvpn.zip "${repo}files/badvpn.zip" > /dev/null 2>&1
unzip badvpn.zip > /dev/null 2>&1
mkdir badvpn-master/build-badvpn
cd badvpn-master/build-badvpn
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null 2>&1
make install > /dev/null 2>&1
cd
rm -rf badvpn-master
rm -f badvpn.zip
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
check_screen badvpn

# Install Xray
echo -e "${INFO} ${B}Installing Xray ...${N}"
sleep 1
rm -f /etc/apt/sources.list.d/nginx.list
apt install -y lsb-release gnupg2 > /dev/null 2>&1
check_install lsb-release gnupg2
echo "deb http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add - > /dev/null 2>&1
apt update > /dev/null 2>&1
apt install -y lsof libpcre3 libpcre3-dev zlib1g-dev libssl-dev jq > /dev/null 2>&1
check_install "lsof libpcre3 libpcre3-dev zlib1g-dev libssl-dev jq"
mkdir -p /usr/local/bin
curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install > /dev/null 2>&1
check_install xray
echo $domain > /usr/local/etc/xray/domain
wget -O /usr/local/etc/xray/xtls.json "${repo}files/xray/xray_xtls.json" > /dev/null 2>&1
wget -O /usr/local/etc/xray/ws.json "${repo}files/xray/xray_ws.json" > /dev/null 2>&1
sed -i "s/xx/${domain}/g" /usr/local/etc/xray/ws.json
echo -e "${INFO} ${B}Installing Nginx ...${N}"
sleep 1
if ! command -v nginx > /dev/null 2>&1; then
	apt install -y nginx > /dev/null 2>&1
fi
check_install nginx
echo -e "${INFO} ${B}Configuring Nginx ...${N}"
sleep 1
rm -rf /etc/nginx/conf.d
mkdir -p /etc/nginx/conf.d
wget -O /etc/nginx/conf.d/${domain}.conf "${repo}files/xray/web.conf" > /dev/null 2>&1
sed -i "s/xx/${domain}/g" /etc/nginx/conf.d/${domain}.conf
nginxConfig=$(systemctl status nginx | grep loaded | awk '{print $3}' | tr -d "(;")
sed -i "/^ExecStart=.*/i ExecStartPost=/bin/sleep 0.1" $nginxConfig
systemctl daemon-reload
systemctl restart nginx
systemctl enable nginx > /dev/null 2>&1
rm -rf /var/www/html
mkdir -p /var/www/html/css
wget -O /var/www/html/index.html "${repo}files/web/index.html" > /dev/null 2>&1
wget -O /var/www/html/css/style.css "${repo}files/web/style.css" > /dev/null 2>&1
nginxUser=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $2}')
nginxGroup=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $3}')
chown -R ${nginxUser}:${nginxGroup} /var/www/html
find /var/www/html/ -type d -exec chmod 750 {} \;
find /var/www/html/ -type f -exec chmod 640 {} \;
echo -e "${INFO} ${B}Configuring Xray ...${N}"
sleep 1
signedcert=$(xray tls cert -domain="$domain" -name="Meta VPN" -org="Upcloud Ltd" -expire=87600h)
echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee /usr/local/etc/xray/self_signed_cert.pem > /dev/null 2>&1
echo $signedcert | jq '.key[]' | sed 's/\"//g' > /usr/local/etc/xray/self_signed_key.pem
openssl x509 -in /usr/local/etc/xray/self_signed_cert.pem -noout
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_cert.pem
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_key.pem
mkdir /metavpn/xray
touch /metavpn/xray/xray-clients.txt
curl -sL https://get.acme.sh | bash > /dev/null 2>&1
"$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt > /dev/null 2>&1
systemctl restart nginx
if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --webroot "/var/www/html" -k ec-256 --force > /dev/null 2>&1; then
	echo -e "SSL certificate generated"
	sleep 1
	if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /metavpn/xray/xray.crt --keypath /metavpn/xray/xray.key --reloadcmd "systemctl restart xray@xtls" --ecc --force > /dev/null 2>&1; then
		echo -e "SSL certificate installed"
		sleep 1
	fi
else
	echo -e "${ERROR} Invalid installing and configuring SSL certificate${N}\n"
	exit 1
fi
chown -R nobody.nogroup /metavpn/xray/xray.crt
chown -R nobody.nogroup /metavpn/xray/xray.key
systemctl daemon-reload
systemctl restart nginx
systemctl restart xray@xtls
systemctl restart xray@ws
systemctl enable xray@xtls > /dev/null 2>&1
systemctl enable xray@ws > /dev/null 2>&1
check_run nginx
check_run xray@xtls
check_run xray@ws
(crontab -l;echo "0 * * * * echo '# Xray-XTLS access log (Script by Meta VPN)' > /var/log/xray/access-xtls.log") | crontab -
(crontab -l;echo "0 * * * * echo '# Xray-WS access log (Script by Meta VPN)' > /var/log/xray/access-ws.log") | crontab -

# Install WireGuard
echo -e "${INFO} ${B}Installing WireGuard ...${N}"
sleep 1
apt install -y wireguard resolvconf qrencode > /dev/null 2>&1
check_install "wireguard resolvconf qrencode"
server_priv_key=$(wg genkey)
server_pub_key=$(echo "${server_priv_key}" | wg pubkey)
echo -e "ip=${ip}
server_priv_key=${server_priv_key}
server_pub_key=${server_pub_key}" > /etc/wireguard/params
source /etc/wireguard/params
echo -e "[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = ${server_priv_key}
PostUp = sleep 1; iptables -A FORWARD -i eth0 -o wg0 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i eth0 -o wg0 -j ACCEPT; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE" >> /etc/wireguard/wg0.conf
systemctl start wg-quick@wg0
systemctl enable wg-quick@wg0 > /dev/null 2>&1
mkdir /metavpn/wireguard
touch /metavpn/wireguard/wireguard-clients.txt
check_run wg-quick@wg0

# Install Speedtest CLI
echo -e "${INFO} ${B}Installing Speedtest CLI ...${N}"
sleep 1
wget -O speedtest.tgz "https://install.speedtest.net/app/cli/ookla-speedtest-1.1.1-linux-$(uname -m).tgz" > /dev/null 2>&1
tar xvf speedtest.tgz -C /usr/bin/ speedtest > /dev/null 2>&1
check_install speedtest
rm -f speedtest.tgz

# Install Fail2Ban
echo -e "${INFO} ${B}Installing Fail2Ban ...${N}"
sleep 1
apt install -y fail2ban > /dev/null 2>&1
check_install fail2ban
systemctl restart fail2ban
check_run fail2ban

# Install DDOS Deflate
echo -e "${INFO} ${B}Installing DDOS Deflate ...${N}"
sleep 1
apt install -y dnsutils tcpdump dsniff grepcidr net-tools > /dev/null 2>&1
check_install "dnsutils tcpdump dsniff grepcidr net-tools"
wget -O ddos.zip "${repo}files/ddos-deflate.zip" > /dev/null 2>&1
unzip ddos.zip > /dev/null 2>&1
cd ddos-deflate
chmod +x install.sh
./install.sh > /dev/null 2>&1
cd
rm -rf ddos.zip ddos-deflate
check_run ddos

# Configure rc.local
echo -e "${INFO} ${B}Checking for rc.local service ...${N}"
sleep 1
systemctl status rc-local > /dev/null 2>&1
if [[ 0 -ne $? ]]; then
	echo -e "${INFO} ${B}Installing rc.local ...${N}"
	sleep 1
	wget -O /etc/systemd/system/rc-local.service "${repo}files/rc-local.service" > /dev/null 2>&1
	echo -e "${INFO} ${B}Configuring rc.local ...${N}"
	sleep 1
	wget -O /etc/rc.local "${repo}files/rc.local" > /dev/null 2>&1
	chmod +x /etc/rc.local
	systemctl start rc-local
	systemctl enable rc-local > /dev/null 2>&1
	check_run rc-local
else
	echo -e "${INFO} ${B}Configuring rc.local ...${N}"
	sleep 1
	wget -O /etc/rc.local "${repo}files/rc.local" > /dev/null 2>&1
	systemctl start rc-local
	systemctl enable rc-local > /dev/null 2>&1
	check_run rc-local
fi

# Save Iptables
echo -e "${INFO} ${B}Saving Iptables ...${N}"
sleep 1
systemctl stop wg-quick@wg0
iptables-save > /metavpn/iptables.rules
systemctl start wg-quick@wg0

# Configure Menu
echo -e "${INFO} ${B}Configuring menu ...${N}"
sleep 1
wget -O /usr/bin/menu "${repo}files/menu/menu.sh" > /dev/null 2>&1
wget -O /usr/bin/ssh-vpn-script "${repo}files/menu/ssh-vpn-script.sh" > /dev/null 2>&1
wget -O /usr/bin/xray-script "${repo}files/menu/xray-script.sh" > /dev/null 2>&1
wget -O /usr/bin/wireguard-script "${repo}files/menu/wireguard-script.sh" > /dev/null 2>&1
wget -O /usr/bin/check-script "${repo}files/menu/check-script.sh" > /dev/null 2>&1
wget -O /usr/bin/nench-script "${repo}files/menu/nench-script.sh" > /dev/null 2>&1
wget -O /usr/bin/stream-script "${repo}files/menu/stream-script.sh" > /dev/null 2>&1
chmod +x /usr/bin/{menu,ssh-vpn-script,xray-script,wireguard-script,check-script,nench-script,stream-script}

# Reboot
rm -f /root/autoscript.sh
cat /dev/null > ~/.bash_history
echo -e "clear
cat /dev/null > ~/.bash_history
history -c" >> ~/.bash_logout
echo -e ""
echo -e "${OK} Autoscript installation completed${N}"
echo -e ""
read -n 1 -r -s -p "Press enter to reboot"
echo -e "\n"
reboot
