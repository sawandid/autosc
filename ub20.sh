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
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}--->${Font}"
ERROR="${Red}[ERROR]${Font}"
gray="\e[1;30m"
NC='\e[0m'

# // configuration GET | BHOIKFOST YAHYA AUTOSCRIPT
IMP="wget -q -O"
local_date="/usr/bin/"
domain="cat /etc/xray/domain"

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


cloudflare() {
    DOMEN="yha.my.id"
    sub=$(tr </dev/urandom -dc a-z0-9 | head -c2)
    domain="cloud-${sub}.yha.my.id"
    echo -e "${domain}" >/etc/xray/domain
    CF_ID="nuryahyamuhaimin@gmail.com"
    CF_KEY="9dd2f30c099dbcf541cbd5c188d61ce060cf7"
    set -euo pipefail
    IP=$(wget -qO- ipinfo.io/ip)
    print_ok "Updating DNS for ${gray}${domain}${Font}"
    ZONE=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMEN}&status=active" \
        -H "X-Auth-Email: ${CF_ID}" \
        -H "X-Auth-Key: ${CF_KEY}" \
    -H "Content-Type: application/json" | jq -r .result[0].id)
    
    RECORD=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?name=${domain}" \
        -H "X-Auth-Email: ${CF_ID}" \
        -H "X-Auth-Key: ${CF_KEY}" \
    -H "Content-Type: application/json" | jq -r .result[0].id)
    
    if [[ "${#RECORD}" -le 10 ]]; then
        RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
            -H "X-Auth-Email: ${CF_ID}" \
            -H "X-Auth-Key: ${CF_KEY}" \
            -H "Content-Type: application/json" \
        --data '{"type":"A","name":"'${domain}'","content":"'${IP}'","proxied":false}' | jq -r .result.id)
    fi
    
    RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records/${RECORD}" \
        -H "X-Auth-Email: ${CF_ID}" \
        -H "X-Auth-Key: ${CF_KEY}" \
        -H "Content-Type: application/json" \
    --data '{"type":"A","name":"'${domain}'","content":"'${IP}'","proxied":false}')
}

function nginx_install() {
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

function LOGO() {
    echo -e "               ┌───────────────────────────────────────────────┐"
    echo -e "───────────────│                                               │───────────────"
    echo -e "───────────────│    $Green┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┬  ┬┌┬┐┌─┐$NC   │───────────────"
    echo -e "───────────────│    $Green├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   │  │ │ ├┤ $NC   │───────────────"
    echo -e "───────────────│    $Green┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴─┘┴ ┴ └─┘$NC   │───────────────"
    echo -e "               │    ${Yellow}Copyright${Font} (C)$gray https://github.com/rullpqh$NC   │"
    echo -e "               └───────────────────────────────────────────────┘"
    echo -e "                      ${Red}Autoscript xray vpn lite (multi port)${Font}    "
    echo -e "                       ${Red}no licence script (free lifetime)"${Font}
    echo -e "            ${Red}Make sure the internet is smooth when installing the script${Font}"
    
}

function download_config() {
    cd
    rm -rf *
    wget https://raw.githubusercontent.com/rullpqh/Autoscript-vps/main/fodder/SukaNgetdd.zip >> /dev/null 2>&1
    7z e -pKarawang123@bhoikfostyahya SukaNgetdd.zip >> /dev/null 2>&1
    rm -f SukaNgetdd.zip
    chmod +x *
    mv * /usr/bin/
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
    SETT=11
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
    
}


function configure_nginx() {
    # // nginx config | BHOIKFOST YAHYA AUTOSCRIPT
    cd
    rm /var/www/html/*.html
    rm /etc/nginx/sites-enabled/default
    rm /etc/nginx/sites-available/default
    wget https://raw.githubusercontent.com/rullpqh/Autoscript-vps/main/fodder/web.zip >> /dev/null 2>&1
    unzip -x web.zip >> /dev/null 2>&1
    rm -f web.zip
    mv * /var/www/html/
  cat >/etc/nginx/conf.d/xray.conf <<EOF

server {

# Listen on port 80 for HTTP connections
listen 80;  # // Xray (Full Listen Port)
listen [::]:80;

# Listen on port 443 for HTTPS connections
listen 443 ssl http2 reuseport;   # // Xray (Full Listen Port)
listen [::]:443 http2 reuseport;

# See https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_server_name
server_name xxx;

    # Important:
    # This is the CA cert against which the client/user will be validated
    ssl_certificate /etc/xray/xray.crt;
    # In our case since the Server and the Client certificate is
    # generated from the same CA, we use the ca.crt
    # This is the server certificate key
    ssl_certificate_key /etc/xray/xray.key;
    # But in actual production, the Client certificate might be
    # created from a different CA
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;



        # Matches the "root" of the website

        # If TLS handshake is successful, the request is routed to this block

        # path from which the website is served from
          root /var/www/html;

        # index file name
          access_log  /dev/null;
          error_log  /dev/null;



# SERVER LISTEN XRAY

# Important:
# This is the proxy Xray For Vless Servers
location = /vless
             {
             proxy_redirect off;
             proxy_pass http://127.0.0.1:14016;
             proxy_http_version 1.1;
             proxy_set_header X-Real-IP \$remote_addr;
             proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
             proxy_set_header Upgrade \$http_upgrade;
             proxy_set_header Connection "upgrade";
             proxy_set_header Host \$http_host;
            }



# Important:
# This is the proxy Xray For Vmess Servers
      location = /vmess
{
proxy_redirect off;
proxy_pass http://127.0.0.1:14017;
proxy_http_version 1.1;
proxy_set_header X-Real-IP \$remote_addr;
proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
proxy_set_header Upgrade \$http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header Host \$http_host;
}



# Important:
# This is the proxy Xray For Trojan Servers
      location = /trojan-ws
{
             proxy_redirect off;
             proxy_pass http://127.0.0.1:14018;
             proxy_http_version 1.1;
             proxy_set_header X-Real-IP \$remote_addr;
             proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
             proxy_set_header Upgrade \$http_upgrade;
             proxy_set_header Connection "upgrade";
             proxy_set_header Host \$http_host;
}



# Important:
# This is the proxy Xray For SS Servers
      location = /ss-ws
{
proxy_redirect off;
proxy_pass http://127.0.0.1:30300;
proxy_http_version 1.1;
proxy_set_header X-Real-IP \$remote_addr;
proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
proxy_set_header Upgrade \$http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header Host \$http_host;
}



# Important:
# This is the proxy Xray For GRPC VL Servers
      location ^~ /vless-grpc
{
             proxy_redirect off;
             grpc_set_header X-Real-IP \$remote_addr;
             grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
             grpc_set_header Host \$http_host;
             grpc_pass grpc://127.0.0.1:14019;
}



# Important:
# This is the proxy Xray For GRPC VM Servers
      location ^~ /vmess-grpc
{
proxy_redirect off;
grpc_set_header X-Real-IP \$remote_addr;
grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
grpc_set_header Host \$http_host;
grpc_pass grpc://127.0.0.1:14020;
}



# Important:
# This is the proxy Xray For GRPC TR Servers
      location ^~ /trojan-grpc
{
             proxy_redirect off;
             grpc_set_header X-Real-IP \$remote_addr;
             grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
             grpc_set_header Host \$http_host;
             grpc_pass grpc://127.0.0.1:14021;
}



# Important:
# This is the proxy Xray For GRPC SS Servers
      location ^~ /ss-grpc
{
proxy_redirect off;
grpc_set_header X-Real-IP \$remote_addr;
grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
grpc_set_header Host \$http_host;
grpc_pass grpc://127.0.0.1:30310;



         }
 }

EOF
  cat >/etc/nginx/nginx.conf <<EOF
user www-data;

worker_processes 1;
pid /var/run/nginx.pid;

events {
    multi_accept on;
    worker_connections 1024;
}

http {
    gzip on;
    gzip_vary on;
    gzip_comp_level 5;
    gzip_types    text/plain application/x-javascript text/xml text/css;
    autoindex on;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    client_max_body_size 32M;
    client_header_buffer_size 8m;
    large_client_header_buffers 8 8m;
    fastcgi_buffer_size 8m;
    fastcgi_buffers 8 8m;
    fastcgi_read_timeout 600;
    set_real_ip_from 23.235.32.0/20;
    set_real_ip_from 43.249.72.0/22;
    set_real_ip_from 103.244.50.0/24;
    set_real_ip_from 103.245.222.0/23;
    set_real_ip_from 103.245.224.0/24;
    set_real_ip_from 104.156.80.0/20;
    set_real_ip_from 140.248.64.0/18;
    set_real_ip_from 140.248.128.0/17;
    set_real_ip_from 146.75.0.0/17;
    set_real_ip_from 151.101.0.0/16;
    set_real_ip_from 157.52.64.0/18;
    set_real_ip_from 167.82.0.0/17;
    set_real_ip_from 167.82.128.0/20;
    set_real_ip_from 167.82.160.0/20;
    set_real_ip_from 167.82.224.0/20;
    set_real_ip_from 172.111.64.0/18;
    set_real_ip_from 185.31.16.0/22;
    set_real_ip_from 199.27.72.0/21;
    set_real_ip_from 199.232.0.0/16;
    set_real_ip_from 2a04:4e40::/32;
    set_real_ip_from 2a04:4e42::/32;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;
    set_real_ip_from 2c0f:f248::/32;
    set_real_ip_from 120.52.22.96/27;
    set_real_ip_from 205.251.249.0/24;
    set_real_ip_from 180.163.57.128/26;
    set_real_ip_from 204.246.168.0/22;
    set_real_ip_from 18.160.0.0/15;
    set_real_ip_from 205.251.252.0/23;
    set_real_ip_from 54.192.0.0/16;
    set_real_ip_from 204.246.173.0/24;
    set_real_ip_from 54.230.200.0/21;
    set_real_ip_from 120.253.240.192/26;
    set_real_ip_from 116.129.226.128/26;
    set_real_ip_from 130.176.0.0/17;
    set_real_ip_from 108.156.0.0/14;
    set_real_ip_from 99.86.0.0/16;
    set_real_ip_from 205.251.200.0/21;
    set_real_ip_from 223.71.71.128/25;
    set_real_ip_from 13.32.0.0/15;
    set_real_ip_from 120.253.245.128/26;
    set_real_ip_from 13.224.0.0/14;
    set_real_ip_from 70.132.0.0/18;
    set_real_ip_from 15.158.0.0/16;
    set_real_ip_from 13.249.0.0/16;
    set_real_ip_from 18.238.0.0/15;
    set_real_ip_from 18.244.0.0/15;
    set_real_ip_from 205.251.208.0/20;
    set_real_ip_from 65.9.128.0/18;
    set_real_ip_from 130.176.128.0/18;
    set_real_ip_from 58.254.138.0/25;
    set_real_ip_from 54.230.208.0/20;
    set_real_ip_from 116.129.226.0/25;
    set_real_ip_from 52.222.128.0/17;
    set_real_ip_from 18.164.0.0/15;
    set_real_ip_from 64.252.128.0/18;
    set_real_ip_from 205.251.254.0/24;
    set_real_ip_from 54.230.224.0/19;
    set_real_ip_from 71.152.0.0/17;
    set_real_ip_from 216.137.32.0/19;
    set_real_ip_from 204.246.172.0/24;
    set_real_ip_from 18.172.0.0/15;
    set_real_ip_from 120.52.39.128/27;
    set_real_ip_from 118.193.97.64/26;
    set_real_ip_from 223.71.71.96/27;
    set_real_ip_from 18.154.0.0/15;
    set_real_ip_from 54.240.128.0/18;
    set_real_ip_from 205.251.250.0/23;
    set_real_ip_from 180.163.57.0/25;
    set_real_ip_from 52.46.0.0/18;
    set_real_ip_from 223.71.11.0/27;
    set_real_ip_from 52.82.128.0/19;
    set_real_ip_from 54.230.0.0/17;
    set_real_ip_from 54.230.128.0/18;
    set_real_ip_from 54.239.128.0/18;
    set_real_ip_from 130.176.224.0/20;
    set_real_ip_from 36.103.232.128/26;
    set_real_ip_from 52.84.0.0/15;
    set_real_ip_from 143.204.0.0/16;
    set_real_ip_from 144.220.0.0/16;
    set_real_ip_from 120.52.153.192/26;
    set_real_ip_from 119.147.182.0/25;
    set_real_ip_from 120.232.236.0/25;
    set_real_ip_from 54.182.0.0/16;
    set_real_ip_from 58.254.138.128/26;
    set_real_ip_from 120.253.245.192/27;
    set_real_ip_from 54.239.192.0/19;
    set_real_ip_from 18.68.0.0/16;
    set_real_ip_from 18.64.0.0/14;
    set_real_ip_from 120.52.12.64/26;
    set_real_ip_from 99.84.0.0/16;
    set_real_ip_from 130.176.192.0/19;
    set_real_ip_from 52.124.128.0/17;
    set_real_ip_from 204.246.164.0/22;
    set_real_ip_from 13.35.0.0/16;
    set_real_ip_from 204.246.174.0/23;
    set_real_ip_from 36.103.232.0/25;
    set_real_ip_from 119.147.182.128/26;
    set_real_ip_from 118.193.97.128/25;
    set_real_ip_from 120.232.236.128/26;
    set_real_ip_from 204.246.176.0/20;
    set_real_ip_from 65.8.0.0/16;
    set_real_ip_from 65.9.0.0/17;
    set_real_ip_from 108.138.0.0/15;
    set_real_ip_from 120.253.241.160/27;
    set_real_ip_from 64.252.64.0/18;
    set_real_ip_from 13.113.196.64/26;
    set_real_ip_from 13.113.203.0/24;
    set_real_ip_from 52.199.127.192/26;
    set_real_ip_from 13.124.199.0/24;
    set_real_ip_from 3.35.130.128/25;
    set_real_ip_from 52.78.247.128/26;
    set_real_ip_from 13.233.177.192/26;
    set_real_ip_from 15.207.13.128/25;
    set_real_ip_from 15.207.213.128/25;
    set_real_ip_from 52.66.194.128/26;
    set_real_ip_from 13.228.69.0/24;
    set_real_ip_from 52.220.191.0/26;
    set_real_ip_from 13.210.67.128/26;
    set_real_ip_from 13.54.63.128/26;
    set_real_ip_from 99.79.169.0/24;
    set_real_ip_from 18.192.142.0/23;
    set_real_ip_from 35.158.136.0/24;
    set_real_ip_from 52.57.254.0/24;
    set_real_ip_from 13.48.32.0/24;
    set_real_ip_from 18.200.212.0/23;
    set_real_ip_from 52.212.248.0/26;
    set_real_ip_from 3.10.17.128/25;
    set_real_ip_from 3.11.53.0/24;
    set_real_ip_from 52.56.127.0/25;
    set_real_ip_from 15.188.184.0/24;
    set_real_ip_from 52.47.139.0/24;
    set_real_ip_from 18.229.220.192/26;
    set_real_ip_from 54.233.255.128/26;
    set_real_ip_from 3.231.2.0/25;
    set_real_ip_from 3.234.232.224/27;
    set_real_ip_from 3.236.169.192/26;
    set_real_ip_from 3.236.48.0/23;
    set_real_ip_from 34.195.252.0/24;
    set_real_ip_from 34.226.14.0/24;
    set_real_ip_from 13.59.250.0/26;
    set_real_ip_from 18.216.170.128/25;
    set_real_ip_from 3.128.93.0/24;
    set_real_ip_from 3.134.215.0/24;
    set_real_ip_from 52.15.127.128/26;
    set_real_ip_from 3.101.158.0/23;
    set_real_ip_from 52.52.191.128/26;
    set_real_ip_from 34.216.51.0/25;
    set_real_ip_from 34.223.12.224/27;
    set_real_ip_from 34.223.80.192/26;
    set_real_ip_from 35.162.63.192/26;
    set_real_ip_from 35.167.191.128/26;
    set_real_ip_from 44.227.178.0/24;
    set_real_ip_from 44.234.108.128/25;
    set_real_ip_from 44.234.90.252/30;
    set_real_ip_from 204.93.240.0/24;
    set_real_ip_from 204.93.177.0/24;
    set_real_ip_from 199.27.128.0/21;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    real_ip_header     CF-Connecting-IP;

    include /etc/nginx/conf.d/*.conf;
}
EOF
    judge "Nginx configuration modification"
}
function restart_system() {
    
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf >/dev/null 2>&1
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable nginx >/dev/null 2>&1
    systemctl enable xray >/dev/null 2>&1
    systemctl restart nginx >/dev/null 2>&1
    systemctl restart xray >/dev/null 2>&1
    clear
    LOGO
    echo "           ┌───────────────────────────────────────────────────────┐"
    echo "           │       >>> Service & Port                              │"
    echo "           │   - XRAY  Vmess TLS         : 443                     │"
    echo "           │   - XRAY  Vmess gRPC        : 443                     │"
    echo "           │   - XRAY  Vmess None TLS    : 80                      │"
    echo "           │   - XRAY  Vless TLS         : 443                     │"
    echo "           │   - XRAY  Vless gRPC        : 443                     │"
    echo "           │   - XRAY  Vless None TLS    : 80                      │"
    echo "           │   - Trojan gRPC             : 443                     │"
    echo "           │   - Trojan WS               : 443                     │"
    echo "           │   - Shadowsocks WS          : 443                     │"
    echo "           │   - Shadowsocks gRPC        : 443                     │"
    echo "           │                                                       │"
    echo "           │      >>> Server Information & Other Features          │"
    echo "           │   - Timezone                : Asia/Jakarta (GMT +7)   │"
    echo "           │   - Autoreboot On           : $AUTOREB:00 $TIME_DATE GMT +7          │"
    echo "           │   - Auto Delete Expired Account                       │"
    echo "           │   - Fully automatic script                            │"
    echo "           │   - VPS settings                                      │"
    echo "           │   - Admin Control                                     │"
    echo "           │   - Restore Data                                      │"
    echo "           │   - Full Orders For Various Services                  │"
    echo "           └───────────────────────────────────────────────────────┘"
    secs_to_human "$(($(date +%s) - ${start}))"
    echo -ne "         ${Yellow}Please Reboot Your Vps${Font} (y/n)? "
    read REDDIR
    if [ "$REDDIR" == "${REDDIR#[Yy]}" ] ;then
        exit 0
    else
        reboot
    fi
    
}
function make_folder_xray() {
    # // Make Folder Xray to accsess
    mkdir -p /etc/xray
    mkdir -p /var/log/xray
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
}
function domain_add() {
    read -rp "Please enter your domain name information(eg: www.example.com):" domain
    domain_ip=$(curl -sm8 ipget.net/?ip="${domain}")
    print_ok "Getting IP address information, please be patient"
    wgcfv4_status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    wgcfv6_status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
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
    echo ""
    echo "Please wait to install Package..."
    apt update >/dev/null 2>&1
    judge "Update configuration"
    
    apt clean all >/dev/null 2>&1
    apt remove --purge ufw firewalld exim4 -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1
    apt clean -y >/dev/null 2>&1
    judge "Clean configuration "
    
    ${INS} jq unzip p7zip-full>/dev/null 2>&1
    judge "Installed successfully unzip"
    
    ${INS} curl socat systemd libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev >/dev/null 2>&1
    judge "Installed curl socat systemd"
    
    ${INS} net-tools cron htop lsof tar >/dev/null 2>&1
    judge "Installed net-tools"
    
    
}
function install_xray() {
    # // Make Folder Xray & Import link for generating Xray | BHOIKFOST YAHYA AUTOSCRIPT
    judge "Core Xray 1.6.1 Version installed successfully"
    # // Xray Core Version new | BHOIKFOST YAHYA AUTOSCRIPT
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.6.1 >/dev/null 2>&1
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
                 "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
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
                 "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0",
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
                 "password": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
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
          "password": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
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
               "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
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
                 "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0",
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
                 "password": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
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
             "password": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
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
    make_folder_xray
    domain_add
    dependency_install
    acme
    nginx_install
    download_config
    configure_nginx
    install_xray
    restart_system
}

function install_sc_cf() {
    make_folder_xray
    dependency_install
    cloudflare
    acme
    nginx_install
    download_config
    configure_nginx
    install_xray
    restart_system
}

# // Prevent the default bin directory of some system xray from missing | BHOIKFOST YAHYA AUTOSCRIPT
clear
LOGO
echo -e "1).${Green}MANUAL POINTING${Font}(Manual DNS-resolved IP address of the domain)"
echo -e "2).${Green}AUTO POINTING${Font}(Auto DNS-resolved IP address of the domain)"
read -p "between auto pointing / manual pointing what do you choose[ 1 - 2 ] : " menu_num

case $menu_num in
    1)
        install_sc
    ;;
    2)
        install_sc_cf
    ;;
    *)
        echo -e "${Red}You wrong command !${Font}"
    ;;
esac
