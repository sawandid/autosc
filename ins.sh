#!/bin/bash
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
gray="\e[1;30m"
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

info() {
    # // Prevent the default bin directory of some system from missing | BHOIKFOST YAHYA AUTOSCRIPT
    red='\e[1;31m'
    green='\e[0;32m'
    tyblue='\e[1;36m'
    Yellow="\033[33m"
    Font="\033[0m"
    gray="\e[1;30m"
    NC='\e[0m'
    echo -e "               ┌───────────────────────────────────────────────┐"
    echo -e "───────────────│                                               │ ───────────────"
    echo -e "───────────────│    $green┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┬  ┬┌┬┐┌─┐$NC   │ ───────────────"
    echo -e "───────────────│    $green├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   │  │ │ ├┤ $NC   │ ───────────────"
    echo -e "───────────────│    $green┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴─┘┴ ┴ └─┘$NC   │ ───────────────"
    echo -e "               │   ${Yellow}Copyright${Font} (C)|$gray https://github.com/rullpqh$NC    │"
    echo -e "               └───────────────────────────────────────────────┘"
    echo -e "                      Autoscript xray vpn lite (multi port)    "
    echo -e "                       no licence script (free lifetime)"
    echo -e "            Make sure the internet is smooth when installing the script"
    
}

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
        # // exit 2
    fi
    
}

judge() {
    if [[ 0 -eq $? ]]; then
        print_ok "$1 Complete... | thx to ${Yellow}bhoikfostyahya${Font}"
        sleep 1
    else
        print_error "$1 Fail... | thx to ${Yellow}bhoikfostyahya${Font}"
        # // exit 2
    fi
    
}

domain_add() {
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


domain_cf() {
    print_ok "enter the domain into the cloudflare dns"
    source <(curl -sL ${myhost}cf.sh)
    judge "domain installed successfully"
    
}
clear
info
echo -e "1).${Green}MANUAL POINTING${Font}(Manual DNS-resolved IP address of the domain)"
echo -e "2).${Green}AUTO POINTING${Font}(Auto DNS-resolved IP address of the domain)"
read -p "between auto pointing / manual pointing what do you choose[ 1 - 2 ] : " DOCOMO
case $DOCOMO in
    1)
        clear
        domain_add
    ;;
    2)
        clear
        domain_cf
    ;;
    *)
esac


secs_to_human() {
    echo "Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds"
}

start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1


clear
info
${IMP} https://wss-multi.yha.my.id/tools.sh;chmod +x tools.sh;./tools.sh
clear
info
${IMP} https://wss-multi.yha.my.id/ssh/ssh-vpn.sh && chmod +x ssh-vpn.sh && screen -S ssh-vpn ./ssh-vpn.sh
clear
info
${IMP} https://wss-multi.yha.my.id/xray/ins-xray.sh && chmod +x ins-xray.sh && ./ins-xray.sh
clear
info
${IMP} https://wss-multi.yha.my.id/sshws/insshws.sh && chmod +x insshws.sh && ./insshws.sh
clear

cat> /root/.profile << END
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
chmod 644 /root/.profile

if [ -f "/root/log-install.txt" ]; then
    rm /root/log-install.txt > /dev/null 2>&1
fi
if [ -f "/etc/afak.conf" ]; then
    rm /etc/afak.conf > /dev/null 2>&1
fi
if [ ! -f "/etc/log-create-user.log" ]; then
    echo "Log All Account " > /etc/log-create-user.log
fi
history -c
AUTOSCRIPT_VERSION=$( curl -sS https://wss-multi.yha.my.id/versi  )
echo $AUTOSCRIPT_VERSION > /opt/.ver
AUTOREB=$(cat /home/re_otm)
b=11
if [ $AUTOREB -gt $b ]
then
    TIME_DATE="PM"
else
    TIME_DATE="AM"
fi
curl -sS ifconfig.me > /etc/myipvps
clear
info
echo "┌───────────────────────────────────────────────────────┐"
echo "│   >>> ${RedBG}Service & Port${Font}                                   │"  | tee -a log-install.txt
echo "│   - OpenSSH                 : 22                      │"  | tee -a log-install.txt
echo "│   - SSH Websocket           : 80 [OFF]                │"  | tee -a log-install.txt
echo "│   - SSH SSL Websocket       : 443                     │"  | tee -a log-install.txt
echo "│   - Stunnel4                : 447, 777                │"  | tee -a log-install.txt
echo "│   - Dropbear                : 109, 143                │"  | tee -a log-install.txt
echo "│   - Badvpn                  : 7100-7900               │"  | tee -a log-install.txt
echo "│   - Nginx                   : 81                      │"  | tee -a log-install.txt
echo "│   - XRAY  Vmess TLS         : 443                     │"  | tee -a log-install.txt
echo "│   - XRAY  Vmess None TLS    : 80                      │"  | tee -a log-install.txt
echo "│   - XRAY  Vless TLS         : 443                     │"  | tee -a log-install.txt
echo "│   - XRAY  Vless None TLS    : 80                      │"  | tee -a log-install.txt
echo "│   - Trojan GRPC             : 443                     │"  | tee -a log-install.txt
echo "│   - Trojan WS               : 443                     │"  | tee -a log-install.txt
echo "│   - Sodosok WS/GRPC         : 443                     │"  | tee -a log-install.txt
echo "│                                                       │"  | tee -a log-install.txt
echo "│   >>> ${RedBG}Server Information & Other Features${Font}             │"  | tee -a log-install.txt
echo "│   - Timezone                : Asia/Jakarta (GMT +7)   │"  | tee -a log-install.txt
echo "│   - Fail2Ban                : [ON]                    │"  | tee -a log-install.txt
echo "│   - Dflate                  : [ON]                    │"  | tee -a log-install.txt
echo "│   - IPtables                : [ON]                    │"  | tee -a log-install.txt
echo "│   - Auto-Reboot             : [ON]                    │"  | tee -a log-install.txt
echo "│   - IPv6                    : [OFF]                   │"  | tee -a log-install.txt
echo "│   - Autoreboot On           : $AUTOREB:00 $TIME_DATE GMT +7    │"  | tee -a log-install.txt
echo "│   - Autobackup Data                                   │"  | tee -a log-install.txt
echo "│   - AutoKill Multi Login User                         │"  | tee -a log-install.txt
echo "│   - Auto Delete Expired Account                       │"  | tee -a log-install.txt
echo "│   - Fully automatic script                            │"  | tee -a log-install.txt
echo "│   - VPS settings                                      │"  | tee -a log-install.txt
echo "│   - Admin Control                                     │"  | tee -a log-install.txt
echo "│   - Change port                                       │"  | tee -a log-install.txt
echo "│   - Restore Data                                      │"  | tee -a log-install.txt
echo "│   - Full Orders For Various Services                  │"  | tee -a log-install.txt
echo "└───────────────────────────────────────────────────────┘"
echo ""
echo "" | tee -a log-install.txt
rm tools.sh>/dev/null 2>&1
rm ssh-vpn.sh>/dev/null 2>&1
rm ins-xray.sh>/dev/null 2>&1
secs_to_human "$(($(date +%s) - ${start}))" | tee -a log-install.txt
echo -e "
"
echo -ne "[ ${yell}WARNING${NC} ] Silahkan Reboot Ulang Vps Anda ? (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
    exit 0
else
    reboot
fi

