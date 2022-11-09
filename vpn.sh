#!/bin/bash
# //====================================================
# //	System Request:Debian 9+/Ubuntu 18.04+/20+
# //	Author:	bhoikfostyahya
# //	Dscription: Xray Menu Management
# //	email: admin@bhoikfostyahya.com
# //  telegram: https://t.me/bhoikfost_yahya
# //====================================================

# // font color configuration | BHOIKFOST YAHYA AUTOSCRIPT
Green="\e[92;1m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
gray="\e[1;30m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}[OKAY]${Font}"
ERROR="${Red}[ERROR]${Font}"
apt install jq -y

https://wss-multi.yha.my.id/tool_configurasi/tools.sh
# // configuration GET | BHOIKFOST YAHYA AUTOSCRIPT
HOSTING="https://wss-multi.yha.my.id/"
HOSTING_XRAY="${HOSTING}/xray/"
HOSTING_SSH="${HOSTING}/ssh/"
HOSTING_SSHWS="${HOSTING}/sshws/"
HOSTING_TOOL="${HOSTING}/tool_configurasi/"
IMP="wget -q -O"
LOCAL_DATE="/usr/bin/"
domain="$(cat /etc/xray/domain)"
myhost_html="https://raw.githubusercontent.com/rullpqh/Autoscript-vps/main/fodder/"
${IMP} ${LOCAL_DATE}infosc "${HOSTING_TOOL}info.sh" && chmod +x ${LOCAL_DATE}infosc


export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID
green='\e[92;1m'
NC='\e[0m'
country=ID
state=Indonesia
locality=none
organization=none
organizationalunit=none
commonname=none
email=admin@bhoikfostyahya
domain="$(cat /etc/xray/domain)"
curl -sS https://wss-multi.yha.my.id/ssh/password | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password
chmod +x /etc/pam.d/common-password
cd
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local


# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config



wget -q /usr/bin/badvpn-udpgw "https://wss-multi.yha.my.id/ssh/newudpgw"
chmod +x /usr/bin/badvpn-udpgw
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500' /etc/rc.local

# setting port ssh
cd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g'
# /etc/ssh/sshd_config
sed -i '/Port 22/a Port 500' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 40000' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 51443' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 58080' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 200' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port 22/g' /etc/ssh/sshd_config
/etc/init.d/ssh restart



sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/ssh restart
/etc/init.d/dropbear restart

cd
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 222
connect = 127.0.0.1:22

[dropbear]
accept = 777
connect = 127.0.0.1:109

[ws-stunnel]
accept = 2096
connect = 700

[openvpn]
accept = 442
connect = 127.0.0.1:1194

END

# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart


wget -q -O /usr/local/bin/ws-dropbear https://wss-multi.yha.my.id/sshws/dropbear-ws.py && chmod +x /usr/local/bin/ws-stunnel
wget -q -O /etc/systemd/system/ws-stunnel.service https://wss-multi.yha.my.id/sshws/ws-stunnel.service && chmod +x /etc/systemd/system/ws-stunnel.service
systemctl daemon-reload
systemctl enable ws-stunnel.service
systemctl start ws-stunnel.service
systemctl restart ws-stunnel.service

${IMP} ${LOCAL_DATE}usernew "${HOSTING_SSH}usernew.sh" && chmod +x ${LOCAL_DATE}usernew
judge "Installed successfully add SSH + OVPN"

${IMP} ${LOCAL_DATE}trial "${HOSTING_SSH}trial.sh" && chmod +x ${LOCAL_DATE}trial
judge "Installed successfully trial SSH + OVPN"

${IMP} ${LOCAL_DATE}renew "${HOSTING_SSH}renew.sh" && chmod +x ${LOCAL_DATE}renew
judge "Installed successfully renew SSH + OVPN"

${IMP} ${LOCAL_DATE}remove "${HOSTING_SSH}hapus.sh" && chmod +x ${LOCAL_DATE}remove
judge "Installed successfully remove SSH + OVPN"

${IMP} ${LOCAL_DATE}cek "${HOSTING_SSH}cek.sh" && chmod +x ${LOCAL_DATE}cek
judge "Installed successfully check SSH + OVPN"

${IMP} ${LOCAL_DATE}member "${HOSTING_SSH}member.sh" && chmod +x ${LOCAL_DATE}member
judge "Installed successfully member SSH + OVPN"

${IMP} ${LOCAL_DATE}delete "${HOSTING_SSH}delete.sh" && chmod +x ${LOCAL_DATE}delete
judge "Installed successfully delete SSH + OVPN"

${IMP} ${LOCAL_DATE}autokill "${HOSTING_SSH}autokill.sh" && chmod +x ${LOCAL_DATE}autokill
judge "Installed successfully autokill SSH + OVPN"

${IMP} ${LOCAL_DATE}ceklim "${HOSTING_SSH}ceklim.sh" && chmod +x ${LOCAL_DATE}ceklim
judge "Installed successfully ceklim SSH + OVPN"


${IMP} ${LOCAL_DATE}sshws "${HOSTING_SSH}sshws.sh" && chmod +x ${LOCAL_DATE}sshws
judge "Installed successfully SSH WEBSOCKET "

${IMP} ${LOCAL_DATE}sshws-true "${HOSTING_SSH}sshws-true.sh" && chmod +x ${LOCAL_DATE}sshws-true
judge "Installed successfully SSH WEBSOCKET ENABLE/DISABLE"




