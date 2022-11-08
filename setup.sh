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

# // configuration GET | BHOIKFOST YAHYA AUTOSCRIPT
IMP="wget -q -O"
local_date="/usr/bin/"
myhost="https://sc-xray.yha.my.id/file_xtls/"
domain="cat /etc/xray/domain"
myhost_html="https://raw.githubusercontent.com/rullpqh/Autoscript-vps/main/fodder/"


#TES
HOSTING="https://wss-multi.yha.my.id/"
HOSTING_XRAY="${HOSTING}/xray/"
HOSTING_SSH="${HOSTING}/ssh/"
HOSTING_SSHWS="${HOSTING}/sshws/"
HOSTING_TOOL="${HOSTING}/tool_configurasi/"
IMP="wget -q -O"
LOCAL_DATE="/usr/bin/"


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
        exit 1
    fi
    
}

judge() {
    if [[ 0 -eq $? ]]; then
        print_ok "$1 Complete... | thx to ${Yellow}bhoikfostyahya${Font}"
        sleep 1
    else
        print_error "$1 Fail... | thx to ${Yellow}bhoikfostyahya${Font}"
        exit 1
    fi
    
}

function nginx_install() {
    print_ok "Nginx Server"
    # // Checking System
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        echo -e "${OK} Your OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${Font} )"
        sleep 1
        sudo add-apt-repository ppa:ondrej/nginx -y
        apt update
        ${INS} nginx -y
        ${INS} python3-certbot-nginx -y
        elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        echo -e "${OK} Your OS Is ( ${GreenBG}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${Font} )"
        sleep 1
        ${INS} gnupg2 ca-certificates lsb-release -y
        echo "deb http://nginx.org/packages/mainline/debian $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
        echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx
        curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key
        sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
        sudo apt update
        apt -y install nginx
        apt --fix-broken install
    else
        echo -e "${ERROR} Your OS Is Not Supported ( ${Yellow}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${Font} )"
        exit 1
    fi
    
    judge "Nginx installed successfully"
    
}

function domain_cf() {
    print_ok "enter the domain into the cloudflare dns"
    source <(curl -sL ${myhost}cf.sh)
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
    curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash && apt-get install speedtest
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
    
}

function acme() {
    judge "installed successfully SSL certificate generation script"
    mkdir /root/.acme.sh
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    print_ok "SSL Certificate generated successfully"
}

function configure_nginx() {
    # // nginx config | BHOIKFOST YAHYA AUTOSCRIPT
    rm /var/www/html/*.html
    rm /etc/nginx/sites-enabled/default
    rm /etc/nginx/sites-available/default
    wget -q -O /var/www/html/index.html ${myhost_html}index.html
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
    
    sed -i '$ ilocation /' /etc/nginx/conf.d/xray.conf
    sed -i '$ i{' /etc/nginx/conf.d/xray.conf
    sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
    sed -i '$ iproxy_pass http://127.0.0.1:700;' /etc/nginx/conf.d/xray.conf
    sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
    sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
    sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
    sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
    sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
    sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
    sed -i '$ i}' /etc/nginx/conf.d/xray.conf
    
    judge "Nginx configuration modification"
    systemctl daemon-reload
    systemctl enable nginx
    systemctl restart nginx
    systemctl restart xray
    systemctl enable ws-dropbear.service
    systemctl start ws-dropbear.service
    systemctl restart ws-dropbear.service
    systemctl enable ws-stunnel.service
    systemctl start ws-stunnel.service
    systemctl restart ws-stunnel.service
    cd
    clear
    judge "waiting reboot ur vps"
    sleep 5
    reboot
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
    apt update
    judge "Update configuration"
    
    apt clean all
    judge "Clean configuration "
    
    ${INS} jq curl
    judge "Installed successfully jq"
    
    ${INS} curl
    judge "Installed successfully unzip"
    
    ${INS} curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y
    judge "Installed socat transport-https"
    
    ${INS} socat cron bash-completion ntpdate -y
    judge "Installed ntpdate"
    
    ntpdate pool.ntp.org
    judge "Pool.ntp.org configuration "
    
    ${INS} net-tools -y
    judge "Installed net-tools"
    
    ${INS} curl pwgen openssl netcat cron -y
    judge "Installed openssl netcat"
    
}

function install_xray() {
    # // Make Folder Xray & Import link for generating Xray | BHOIKFOST YAHYA AUTOSCRIPT
    judge "Core Xray Version 1.5.8 installed successfully"
    # // Xray Core Version new | BHOIKFOST YAHYA AUTOSCRIPT
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.5.8
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

function install_ssh() {
    apt install stunnel4 -y
    apt install squid3 -y
    apt install dropbear -y
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g'
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
    wget -q -O /usr/local/bin/ws-dropbear https://wss-multi.yha.my.id/sshws/dropbear-ws.py && chmod +x /usr/local/bin/ws-dropbear
    wget -q -O /usr/local/bin/ws-stunnel https://wss-multi.yha.my.id/sshws/ws-stunnel && chmod +x /usr/local/bin/ws-stunnel
    wget -q -O /etc/systemd/system/ws-dropbear.service https://wss-multi.yha.my.id/sshws/service-wsdropbear && chmod +x /etc/systemd/system/ws-dropbear.service
    wget -q -O /etc/systemd/system/ws-stunnel.service https://wss-multi.yha.my.id/sshws/ws-stunnel.service && chmod +x /etc/systemd/system/ws-stunnel.service
    # // DOWNLOAD SSH
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
    
    ${IMP} ${LOCAL_DATE}xp "${HOSTING_SSH}xp.sh"&& chmod +x ${LOCAL_DATE}xp
    judge "Installed successfully exp all account"
    
    # // DOWNLOAD XRAY
    ${IMP} ${LOCAL_DATE}add-tr "${HOSTING_XRAY}add-tr.sh" && chmod +x ${LOCAL_DATE}add-tr
    judge "Installed successfully add trojan account"
    
    ${IMP} ${LOCAL_DATE}add-vless "${HOSTING_XRAY}add-vless.sh" && chmod +x ${LOCAL_DATE}add-vless
    judge "Installed successfully add vless account"
    
    ${IMP} ${LOCAL_DATE}add-ws "${HOSTING_XRAY}add-ws.sh" && chmod +x ${LOCAL_DATE}add-ws
    judge "Installed successfully add vmess account"
    
    ${IMP} ${LOCAL_DATE}add-ss "${HOSTING_XRAY}add-ss.sh" && chmod +x ${LOCAL_DATE}add-ss
    judge "Installed successfully add ss account"
    
    ${IMP} ${LOCAL_DATE}del-tr "${HOSTING_XRAY}del-tr.sh" && chmod +x ${LOCAL_DATE}del-tr
    judge "Installed successfully remove trojan account"
    
    ${IMP} ${LOCAL_DATE}del-vless "${HOSTING_XRAY}del-vless.sh" && chmod +x ${LOCAL_DATE}del-vless
    judge "Installed successfully remove vless account"
    
    ${IMP} ${LOCAL_DATE}del-ws "${HOSTING_XRAY}del-ws.sh" && chmod +x ${LOCAL_DATE}del-ws
    judge "Installed successfully remove vmess account"
    
    ${IMP} ${LOCAL_DATE}del-ss "${HOSTING_XRAY}del-ss.sh" && chmod +x ${LOCAL_DATE}del-ss
    judge "Installed successfully remove ss account"
    
    ${IMP} ${LOCAL_DATE}renew-tr "${HOSTING_XRAY}renew-tr.sh" && chmod +x ${LOCAL_DATE}renew-tr
    judge "Installed successfully renew trojan account"
    
    ${IMP} ${LOCAL_DATE}renew-vless "${HOSTING_XRAY}renew-vless.sh" && chmod +x ${LOCAL_DATE}renew-vless
    judge "Installed successfully renew vless account"
    
    ${IMP} ${LOCAL_DATE}renew-ws "${HOSTING_XRAY}renew-ws.sh" && chmod +x ${LOCAL_DATE}renew-ws
    judge "Installed successfully renew vmess account"
    
    ${IMP} ${LOCAL_DATE}renew-ss "${HOSTING_XRAY}renew-ss.sh" && chmod +x ${LOCAL_DATE}renew-ss
    judge "Installed successfully renew ss account"
    
    ${IMP} ${LOCAL_DATE}cek-tr "${HOSTING_XRAY}cek-tr.sh" && chmod +x ${LOCAL_DATE}cek-tr
    judge "Installed successfully check trojan account"
    
    ${IMP} ${LOCAL_DATE}cek-vless "${HOSTING_XRAY}cek-vless.sh" && chmod +x ${LOCAL_DATE}cek-vless
    judge "Installed successfully check vless account"
    
    ${IMP} ${LOCAL_DATE}cek-ws "${HOSTING_XRAY}cek-ws.sh" && chmod +x ${LOCAL_DATE}cek-ws
    judge "Installed successfully check vmess account"
    
    ${IMP} ${LOCAL_DATE}cek-ss "${HOSTING_XRAY}cek-ss.sh" && chmod +x ${LOCAL_DATE}cek-ss
    judge "Installed successfully check ss account"
    
    
    # // DOWNLOAD TOOL
    ${IMP} ${LOCAL_DATE}add-host "${HOSTING_TOOL}add-host.sh" && chmod +x ${LOCAL_DATE}add-host
    judge "Installed successfully change domain vps"
    
    ${IMP} ${LOCAL_DATE}menu "${HOSTING_XRAY}menu.sh" && chmod +x ${LOCAL_DATE}menu
    judge "Installed successfully menu ur dashboard vps"
    
    ${IMP} ${LOCAL_DATE}speedtest "${HOSTING_TOOL}speedtest_cli.py" && chmod +x ${LOCAL_DATE}speedtest
    judge "Installed successfully speedtest vps"
    
    ${IMP} ${LOCAL_DATE}running "${HOSTING_TOOL}running.sh" && chmod +x ${LOCAL_DATE}running
    judge "Installed successfully menu running"
    
    ${IMP} ${LOCAL_DATE}banner "${HOSTING_TOOL}banner.sh" && chmod +x ${LOCAL_DATE}banner
    judge "Installed successfully menu ur banner vps"
    
    ${IMP} ${LOCAL_DATE}crt "${HOSTING_XRAY}crt.sh" && chmod +x ${LOCAL_DATE}crt
    judge "Installed successfully crt ssl vps"
    
    ${IMP} ${LOCAL_DATE}cekusage "${HOSTING_XRAY}cekusage.sh" && chmod +x ${LOCAL_DATE}cekusage
    judge "Installed successfully cekusage xray vps"
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
    
    
    
}

function install_sc() {
    domain_add
    dependency_install
    acme
    nginx_install
    install_xray
    #download_config
    configure_nginx
    install_ssh
}

function install_sc_cf() {
    dependency_install
    domain_cf
    acme
    nginx_install
    install_xray
    #download_config
    configure_nginx
    install_ssh
    
}

# // Prevent the default bin directory of some system xray from missing | BHOIKFOST YAHYA AUTOSCRIPT
red='\e[1;31m'
green='\e[0;32m'
tyblue='\e[1;36m'
NC='\e[0m'
echo -e "$green┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┬  ┬┌┬┐┌─┐$NC"
echo -e "$green├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   │  │ │ ├┤ $NC"
echo -e "$green┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴─┘┴ ┴ └─┘$NC"
echo -e "[ ${red}INFO${NC} ] Autoscript xray vpn lite (multi port)"
echo -e "[ ${red}INFO${NC} ] no licence script (free lifetime)"
echo -e "[ ${red}INFO${NC} ] Make sure the internet is smooth when installing the script"
echo -e "${tyblue}[1]${NC}.${green}MANUAL POINTING${NC} ] First connect your VPS IP to the Domain? please click num 1"
echo -e "${tyblue}[2]${NC}.${green}AUTO POINTING${NC} ] do you not have a domain? please click num 2"
read -rp "CONTINUING TO INSTALL AUTOSCRIPT (1/2)? " menu_num
case $menu_num in
    1)
        install_sc
    ;;
    2)
        install_sc_cf
    ;;
    *)
        exit
    ;;
esac
