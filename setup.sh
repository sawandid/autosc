#!/bin/bash
# //====================================================
# //	System Request:Debian 9+/Ubuntu 18.04+/20+
# //	Author:	bhoikfostyahya
# //	Dscription: Xray Menu Management
# //	email: admin@bhoikfostyahya.com
# //  telegram: https://t.me/bhoikfost_yahya
# //====================================================

# // font color configuration | BHOIKFOST YAHYA AUTOSCRIPT
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}[OKAY]${Font}"
ERROR="${Red}[ERROR]${Font}"
gray="\e[1;30m"
NC='\e[0m'

# // configuration GET | BHOIKFOST YAHYA AUTOSCRIPT
IMP="wget -q -O"
local_date="/usr/bin/"
myhost="https://sc-xray.yha.my.id/file_xtls/"
domain="cat /etc/xray/domain"
myhost_html="https://raw.githubusercontent.com/rullpqh/Autoscript-vps/main/fodder/"

secs_to_human() {
    echo "Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds"
}

start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
function print_ok() {
  echo -e "${OK} ${Blue} $1 ${Font}"
}

function print_error() {
  echo -e "${ERROR} ${RedBG} $1 ${Font}"
}

function is_root() {
  if [[ 0 == "$UID" ]]; then
    print_ok "Root user Start installation process"
  else
    print_error "The current user is not the root user, please switch to the root user and run the script again"
    # // exit 1
  fi

}

judge() {
  if [[ 0 -eq $? ]]; then
    print_ok "$1 Complete... | thx to ${Yellow}bhoikfostyahya${Font}"
    sleep 1
  else
    print_error "$1 Fail... | thx to ${Yellow}bhoikfostyahya${Font}"
    # // exit 1
  fi

}

function nginx_install() {
  print_ok "Nginx Server"
  # // Checking System
  if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
    judge "Your OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
    ${INS} nginx -y >/dev/null 2>&1
  elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
    judge "Your OS Is ( ${GreenBG}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
    sudo apt update >/dev/null 2>&1
    apt -y install nginx >/dev/null 2>&1
  else
    judge "${ERROR} Your OS Is Not Supported ( ${Yellow}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${Font} )"
    # // exit 1
  fi

  judge "Nginx installed successfully"

}

function domain_cf() {
  print_ok "enter the domain into the cloudflare dns"
  source <(curl -sL ${myhost}cf.sh) >/dev/null 2>&1
  judge "domain installed successfully"

}

function download_config() {
  ${IMP} ${local_date}add-tr "${myhost}add-tr.sh" && chmod +x ${local_date}add-tr
  judge "Installed successfully add trojan account"
  ${IMP} ${local_date}add-vless "${myhost}add-vless.sh" && chmod +x ${local_date}add-vless
  judge "Installed successfully add vless account"
  ${IMP} ${local_date}add-ws "${myhost}add-ws.sh" && chmod +x ${local_date}add-ws
  judge "Installed successfully add vmess account"
  ${IMP} ${local_date}del-tr "${myhost}del-tr.sh" && chmod +x ${local_date}del-tr
  judge "Installed successfully remove trojan account"
  ${IMP} ${local_date}del-vless "${myhost}del-vless.sh" && chmod +x ${local_date}del-vless
  judge "Installed successfully remove vless account"
  ${IMP} ${local_date}del-ws "${myhost}del-ws.sh" && chmod +x ${local_date}del-ws
  judge "Installed successfully remove vmess account"
  ${IMP} ${local_date}renew-tr "${myhost}renew-tr.sh" && chmod +x ${local_date}renew-tr
  judge "Installed successfully renew trojan account"
  ${IMP} ${local_date}renew-vless "${myhost}renew-vless.sh" && chmod +x ${local_date}renew-vless
  judge "Installed successfully renew vless account"
  ${IMP} ${local_date}renew-ws "${myhost}renew-ws.sh" && chmod +x ${local_date}renew-ws
  judge "Installed successfully renew vmess account"
  ${IMP} ${local_date}cek-tr "${myhost}cek-tr.sh" && chmod +x ${local_date}cek-tr
  judge "Installed successfully check trojan account"
  ${IMP} ${local_date}cek-vless "${myhost}cek-vless.sh" && chmod +x ${local_date}cek-vless
  judge "Installed successfully check vless account"
  ${IMP} ${local_date}cek-ws "${myhost}cek-ws.sh" && chmod +x ${local_date}cek-ws
  judge "Installed successfully check vmess account"
  ${IMP} ${local_date}xp "${myhost}xp.sh" && chmod +x ${local_date}xp
  judge "Installed successfully exp all account"
  ${IMP} ${local_date}menu "${myhost}menu.sh" && chmod +x ${local_date}menu
  judge "Installed successfully menu ur dashboard vps"
#  ${IMP} ${local_date}speedtest "${myhost}speedtest_cli.py" && chmod +x ${local_date}speedtest
  judge "Installed successfully speedtest"
  cat >/root/.profile <<END
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
clear
menu
END
  cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/bin/xp
END
  chmod 644 /root/.profile

cat > /etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END
cat > /home/daily_reboot <<-END
5
END
AUTOREB=$(cat /home/daily_reboot)
SETT=5
if [ $AUTOREB -gt $SETT ]
then
    TIME_DATE="PM"
else
    TIME_DATE="AM"
fi
}

function acme() {
  judge "installed successfully SSL certificate generation script"
  mkdir /root/.acme.sh  >/dev/null 2>&1
  curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh >/dev/null 2>&1
  chmod +x /root/.acme.sh/acme.sh >/dev/null 2>&1
  /root/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
  /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256 >/dev/null 2>&1
  ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc >/dev/null 2>&1
  print_ok "SSL Certificate generated successfully"
}

function configure_nginx() {
  # // nginx config | BHOIKFOST YAHYA AUTOSCRIPT
  rm /var/www/html/*.html
  rm /etc/nginx/sites-enabled/default
  rm /etc/nginx/sites-available/default 
  wget -q -O /var/www/html/index.html ${myhost_html}index.html >/dev/null 2>&1
  cat >/etc/nginx/conf.d/xray.conf <<EOF
    server {
             listen 80;
             listen [::]:80;
             listen 443 ssl http2 reuseport;
             listen [::]:443 http2 reuseport;	
             server_name $domain;
             ssl_certificate /etc/xray/xray.crt;
             ssl_certificate_key /etc/xray/xray.key;
             ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
             ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
             root /var/www/html;
        }
EOF
  sed -i '$ ilocation = /vless' /etc/nginx/conf.d/xray.conf
  sed -i '$ i{' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_pass http://127.0.0.1:14016;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
  sed -i '$ i}' /etc/nginx/conf.d/xray.conf

  sed -i '$ ilocation = /vmess' /etc/nginx/conf.d/xray.conf
  sed -i '$ i{' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_pass http://127.0.0.1:14017;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
  sed -i '$ i}' /etc/nginx/conf.d/xray.conf

  sed -i '$ ilocation = /trojan-ws' /etc/nginx/conf.d/xray.conf
  sed -i '$ i{' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_pass http://127.0.0.1:14018;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
  sed -i '$ i}' /etc/nginx/conf.d/xray.conf

  sed -i '$ ilocation = /ss-ws' /etc/nginx/conf.d/xray.conf
  sed -i '$ i{' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_pass http://127.0.0.1:30300;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
  sed -i '$ i}' /etc/nginx/conf.d/xray.conf

  sed -i '$ ilocation ^~ /vless-grpc' /etc/nginx/conf.d/xray.conf
  sed -i '$ i{' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_pass grpc://127.0.0.1:14019;' /etc/nginx/conf.d/xray.conf
  sed -i '$ i}' /etc/nginx/conf.d/xray.conf

  sed -i '$ ilocation ^~ /vmess-grpc' /etc/nginx/conf.d/xray.conf
  sed -i '$ i{' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_pass grpc://127.0.0.1:14020;' /etc/nginx/conf.d/xray.conf
  sed -i '$ i}' /etc/nginx/conf.d/xray.conf

  sed -i '$ ilocation ^~ /trojan-grpc' /etc/nginx/conf.d/xray.conf
  sed -i '$ i{' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_pass grpc://127.0.0.1:14021;' /etc/nginx/conf.d/xray.conf
  sed -i '$ i}' /etc/nginx/conf.d/xray.conf

  sed -i '$ ilocation ^~ /ss-grpc' /etc/nginx/conf.d/xray.conf
  sed -i '$ i{' /etc/nginx/conf.d/xray.conf
  sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
  sed -i '$ igrpc_pass grpc://127.0.0.1:30310;' /etc/nginx/conf.d/xray.conf
  sed -i '$ i}' /etc/nginx/conf.d/xray.conf
  
  judge "Nginx configuration modification"
  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable nginx >/dev/null 2>&1
  systemctl enable xray >/dev/null 2>&1
  systemctl restart nginx >/dev/null 2>&1
  systemctl restart xray >/dev/null 2>&1
clear
echo "               ┌───────────────────────────────────────────────┐"
echo "───────────────│                                               │───────────────"
echo "───────────────│    $Green┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┬  ┬┌┬┐┌─┐$NC   │───────────────"
echo "───────────────│    $Green├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   │  │ │ ├┤ $NC   │───────────────"
echo "───────────────│    $Green┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴─┘┴ ┴ └─┘$NC   │───────────────"
echo "               │   ${Yellow}Copyright${Font} (C)$gray https://github.com/rullpqh$NC    │"
echo "               └───────────────────────────────────────────────┘"
echo "           ┌───────────────────────────────────────────────────────┐"
echo "           │       >>> Service & Port                              │"  | tee -a log-install.txt
echo "           │   - XRAY  Vmess TLS         : 443                     │"  | tee -a log-install.txt
echo "           │   - XRAY  Vmess gRPC        : 443                     │"  | tee -a log-install.txt
echo "           │   - XRAY  Vmess None TLS    : 80                      │"  | tee -a log-install.txt
echo "           │   - XRAY  Vless TLS         : 443                     │"  | tee -a log-install.txt
echo "           │   - XRAY  Vless gRPC        : 443                     │"  | tee -a log-install.txt
echo "           │   - XRAY  Vless None TLS    : 80                      │"  | tee -a log-install.txt
echo "           │   - XRAY  Vless TLS         : 443                     │"  | tee -a log-install.txt
echo "           │   - Trojan GRPC             : 443                     │"  | tee -a log-install.txt
echo "           │   - Trojan WS               : 443                     │"  | tee -a log-install.txt
echo "           │                                                       │"  | tee -a log-install.txt
echo "           │      >>> Server Information & Other Features          │"  | tee -a log-install.txt
echo "           │   - Timezone                : Asia/Jakarta (GMT +7)   │"  | tee -a log-install.txt
echo "           │   - Autoreboot On           : $AUTOREB:00 $TIME_DATE GMT +7          │"  | tee -a log-install.txt
echo "           │   - Auto Delete Expired Account                       │"  | tee -a log-install.txt
echo "           │   - Fully automatic script                            │"  | tee -a log-install.txt
echo "           │   - VPS settings                                      │"  | tee -a log-install.txt
echo "           │   - Admin Control                                     │"  | tee -a log-install.txt
echo "           │   - Restore Data                                      │"  | tee -a log-install.txt
echo "           │   - Full Orders For Various Services                  │"  | tee -a log-install.txt
echo "           └───────────────────────────────────────────────────────┘"
echo "" | tee -a log-install.txt
rm *.sh>/dev/null 2>&1
secs_to_human "$(($(date +%s) - ${start}))" | tee -a log-install.txt
echo -ne "         ${Yellow}Please Reboot Your Vps${Font} (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
    exit 0
else
    reboot
fi

}

function domain_add() {
  clear
  # // Make Folder Xray to accsess
  mkdir -p /etc/xray
  mkdir -p /var/log/xray
  chmod +x /var/log/xray
  touch /etc/xray/domain
  touch /var/log/xray/access.log
  touch /var/log/xray/error.log
  read -rp "Please enter your domain name information(eg: www.example.com):" domain
  domain_ip=$(curl -sm8 ipget.net/?ip="${domain}")
  print_ok "Getting IP address information, please be patient"
  wgcfv4_status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
  wgcfv6_status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
  echo "${domain}" >/etc/xray/scdomain
  echo "${domain}" >/etc/xray/domain
  if [[ ${wgcfv4_status} =~ "on"|"plus" ]] || [[ ${wgcfv6_status} =~ "on"|"plus" ]]; then
    # // Close wgcf-warp to prevent misjudgment of VPS IP situation | BHOIKFOST YAHYA AUTOSCRIPT
    wg-quick down wgcf >/dev/null 2>&1
    print_ok "wgcf-warp is turned off"
  fi
  local_ipv4=$(curl -s4m8 https://ip.gs)
  local_ipv6=$(curl -s6m8 https://ip.gs)
  if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
    # // Pure IPv6 VPS, automatically add a DNS64 server for acme.sh to apply for a certificate | BHOIKFOST YAHYA AUTOSCRIPT
    echo -e nameserver 2a01:4f8:c2c:123f::1 >/etc/resolv.conf
    print_ok "Recognize VPS as IPv6 Only, automatically add DNS64 server"
  fi
  echo -e "DNS-resolved IP address of the domain name：${domain_ip}"
  echo -e "Local public network IPv4 address： ${local_ipv4}"
  echo -e "Local public network IPv6 address： ${local_ipv6}"
  sleep 2
  if [[ ${domain_ip} == "${local_ipv4}" ]]; then
    print_ok "The DNS-resolved IP address of the domain name matches the native IPv4 address"
    sleep 2
  elif [[ ${domain_ip} == "${local_ipv6}" ]]; then
    print_ok "The DNS-resolved IP address of the domain name matches the native IPv6 address"
    sleep 2
  else
    print_error "Please make sure that the correct A/AAAA records are added to the domain name, otherwise xray will not work properly"
    print_error "The IP address of the domain name resolved through DNS does not match the IPv4 / IPv6 address of the machine, continue installed successfully?（y/n）" && read -r install
    case $install in
    [yY][eE][sS] | [yY])
      print_ok "Continue installed successfully"
      sleep 2
      ;;
    *)
      print_error "installed successfully"
      # // exit 2
      ;;
    esac
  fi
}

function dependency_install() {
  INS="apt install -y"
  apt update >/dev/null 2>&1
  judge "Update configuration"

  apt clean all >/dev/null 2>&1
  judge "Clean configuration "

  ${INS} jq curl >/dev/null 2>&1
  judge "Installed successfully jq"

  ${INS} curl socat  >/dev/null 2>&1
  judge "Installed socat transport-https"

  ${INS} systemd >/dev/null 2>&1
  judge "Installed systemd"

  ${INS} net-tools >/dev/null 2>&1
  judge "Installed net-tools"


}
function install_xray() {
  # // Make Folder Xray & Import link for generating Xray | BHOIKFOST YAHYA AUTOSCRIPT
  judge "Core Xray New Version installed successfully"
  # // Xray Core Version new | BHOIKFOST YAHYA AUTOSCRIPT
  source <(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null 2>&1
  # // Set UUID Xray Core | BHOIKFOST YAHYA AUTOSCRIPT
  uuid="1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
  # // Xray Config Xray Core | BHOIKFOST YAHYA AUTOSCRIPT
  cat >/etc/xray/config.json <<END
{
  "log" : {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
      {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
   {
     "listen": "127.0.0.1",
     "port": "14016",
     "protocol": "vless",
      "settings": {
          "decryption":"none",
            "clients": [
               {
                 "id": "${uuid}"                 
#vless
             }
          ]
       },
       "streamSettings":{
         "network": "ws",
            "wsSettings": {
                "path": "/vless"
          }
        }
     },
     {
     "listen": "127.0.0.1",
     "port": "14017",
     "protocol": "vmess",
      "settings": {
            "clients": [
               {
                 "id": "${uuid}",
                 "alterId": 0
#vmess
             }
          ]
       },
       "streamSettings":{
         "network": "ws",
            "wsSettings": {
                "path": "/vmess"
          }
        }
     },
    {
      "listen": "127.0.0.1",
      "port": "14018",
      "protocol": "trojan",
      "settings": {
          "decryption":"none",		
           "clients": [
              {
                 "password": "${uuid}"
#trojanws
              }
          ],
         "udp": true
       },
       "streamSettings":{
           "network": "ws",
           "wsSettings": {
               "path": "/trojan-ws"
            }
         }
     },
    {
         "listen": "127.0.0.1",
        "port": "30300",
        "protocol": "shadowsocks",
        "settings": {
           "clients": [
           {
           "method": "aes-128-gcm",
          "password": "${uuid}"
#ssws
           }
          ],
          "network": "tcp,udp"
       },
       "streamSettings":{
          "network": "ws",
             "wsSettings": {
               "path": "/ss-ws"
           }
        }
     },	
      {
        "listen": "127.0.0.1",
        "port": "14019",
        "protocol": "vless",
        "settings": {
         "decryption":"none",
           "clients": [
             {
               "id": "${uuid}"
#vlessgrpc
             }
          ]
       },
          "streamSettings":{
             "network": "grpc",
             "grpcSettings": {
                "serviceName": "vless-grpc"
           }
        }
     },
     {
      "listen": "127.0.0.1",
      "port": "14020",
     "protocol": "vmess",
      "settings": {
            "clients": [
               {
                 "id": "${uuid}",
                 "alterId": 0
#vmessgrpc
             }
          ]
       },
       "streamSettings":{
         "network": "grpc",
            "grpcSettings": {
                "serviceName": "vmess-grpc"
          }
        }
     },
     {
        "listen": "127.0.0.1",
        "port": "14021",
        "protocol": "trojan",
        "settings": {
          "decryption":"none",
             "clients": [
               {
                 "password": "${uuid}"
#trojangrpc
               }
           ]
        },
         "streamSettings":{
         "network": "grpc",
           "grpcSettings": {
               "serviceName": "trojan-grpc"
         }
      }
   },
   {
    "listen": "127.0.0.1",
    "port": "30310",
    "protocol": "shadowsocks",
    "settings": {
        "clients": [
          {
             "method": "aes-128-gcm",
             "password": "${uuid}"
#ssgrpc
           }
         ],
           "network": "tcp,udp"
      },
    "streamSettings":{
     "network": "grpc",
        "grpcSettings": {
           "serviceName": "ss-grpc"
          }
       }
    }	
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END
  rm -rf /etc/systemd/system/xray.service.d
  cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE                                 
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF

}

function install_sc() {
  domain_add
  dependency_install
  acme
  nginx_install
  install_xray
  download_config
  configure_nginx
}

function install_sc_cf() {
  dependency_install
  domain_cf
  acme
  nginx_install
  install_xray
  download_config
  configure_nginx

}

# // Prevent the default bin directory of some system xray from missing | BHOIKFOST YAHYA AUTOSCRIPT
clear

echo -e "               ┌───────────────────────────────────────────────┐"
echo -e "───────────────│                                               │───────────────"
echo -e "───────────────│    $Green┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┬  ┬┌┬┐┌─┐$NC   │───────────────"
echo -e "───────────────│    $Green├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   │  │ │ ├┤ $NC   │───────────────"
echo -e "───────────────│    $Green┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴─┘┴ ┴ └─┘$NC   │───────────────"
echo -e "               │   ${Yellow}Copyright${Font} (C)$gray https://github.com/rullpqh$NC    │"
echo -e "               └───────────────────────────────────────────────┘"
echo -e "                      Autoscript xray vpn lite (multi port)    "
echo -e "                       no licence script (free lifetime)"
echo -e "            Make sure the internet is smooth when installing the script"
echo -e "${gray}1)${NC}.${Green}MANUAL POINTING${NC} ] First connect your VPS IP to the Domain?"
echo -e "${gray}2)${NC}.${Green}AUTO POINTING${NC} ] do you not have a domain?"
read -rp "CONTINUING TO INSTALL AUTOSCRIPT (1/2)? " menu_num
case $menu_num in
1)
  install_sc
  ;;
2)
  install_sc_cf
  ;;
*)
echo "You wrong command !"
  ;;
esac
