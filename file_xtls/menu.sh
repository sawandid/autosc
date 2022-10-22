#!/bin/bash
clear
# COLOR VALIDATION
RED='\033[0;31m'
NC='\033[0m'
gray="\e[1;30m"
GREEN='\033[0;32m'
grenbo="\e[92;1m"
ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )
CITY=$(curl -s ipinfo.io/city )
WKT=$(curl -s ipinfo.io/timezone )
IPVPS=$(curl -s ipv4.icanhazip.com )
domain="(cat /etc/xray/domain)"
vmess=$(systemctl status xray | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
vless=$(systemctl status xray | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
trojan=$(systemctl status xray | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
nginx=$( systemctl status nginx | grep Active | awk '{print $3}' | sed 's/(//g' | sed 's/)//g' )
	cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo )
	cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
	freq=$( awk -F: ' /cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo )
	tram=$( free -m | awk 'NR==2 {print $2}' )
	swap=$( free -m | awk 'NR==4 {print $2}' )
	up=$(uptime|awk '{ $1=$2=$(NF-6)=$(NF-5)=$(NF-4)=$(NF-3)=$(NF-2)=$(NF-1)=$NF=""; print }')
#systm status
if [[ $nginx == "run" ]]; then
   status_nginx="${RED}Not Active${NC}"
else
   status_nginx="${grenbo}Online${NC}"
    fi
if [[ $vmess == "run" ]]; then 
   status_vmess="${RED}Not Active${NC}"
else
   status_vmess=" ${grenbo}Online${NC} "
   fi
if [[ $vless == "run" ]]; then 
   status_vless="${RED}Not Active${NC}"
else
   status_vless=" ${grenbo}Online${NC} "
   fi
if [[ $trojan == "run" ]]; then 
   status_trojan="${RED}Not Active${NC}" 
else
   status_trojan=" ${grenbo}Online${NC} "
   fi  


echo -e "███████████████████████████████████████████████████████████"
echo -e "██▀▄─██▄─██─▄█─▄─▄─█─▄▄─█─▄▄▄▄█─▄▄▄─█▄─▄▄▀█▄─▄█▄─▄▄─█─▄─▄─█"
echo -e "██─▀─███─██─████─███─██─█▄▄▄▄─█─███▀██─▄─▄██─███─▄▄▄███─███"
echo -e "▀▄▄▀▄▄▀▀▄▄▄▄▀▀▀▄▄▄▀▀▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▄▄▄▀▀▀▀▄▄▄▀▀"
echo -e "███████████████████████ \e[032;1mCPU Model:\e[0m \e[1;32m$cname\e[0m"
echo -e "█▄─▄███▄─▄█─▄─▄─█▄─▄▄─█ \e[032;1mTotal Amount Of RAM:\e[0m \e[1;32m$tram MB\e[0m"
echo -e "██─██▀██─████─████─▄█▀█ \e[032;1mIsp Name:\e[0m \e[1;32m$ISP\e[0m"
echo -e "▀▄▄▄▄▄▀▄▄▄▀▀▄▄▄▀▀▄▄▄▄▄▀ \e[033;1mIp VPS:\e[0m \e[1;32m$IPVPS\e[0m"
echo -e "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ \e[033;1mDomain:\e[0m: \e[1;32m$( cat /etc/xray/domain )\e[0m"  
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e " Vmess Status: $status_vmess  Trojan Status: $status_trojan"
echo -e " VLess Status: $status_vless  Nginx Status: $status_nginx"     
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e " [${grenbo}1${NC}]  ${RED}• ${NC}Creating a Vmess Account$NC$gray(add-ws)$NC"
echo -e " [${grenbo}2${NC}]  ${RED}• ${NC}Delete Vmess Account$NC$gray(del-ws)$NC"
echo -e " [${grenbo}3${NC}]  ${RED}• ${NC}Renew Vmess Account$NC$gray(renew-ws)$NC"  
echo -e " [${grenbo}4${NC}]  ${RED}• ${NC}Check Vmess login Account$NC$gray(cek-ws)$NC"  
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e " [${grenbo}5${NC}]  ${RED}• ${NC}Creating a Vless Account$NC$gray(add-vless)$NC"  
echo -e " [${grenbo}6${NC}]  ${RED}• ${NC}Delete Vless Account$NC$gray(del-vless)$NC"
echo -e " [${grenbo}7${NC}]  ${RED}• ${NC}Renew Vless Account$NC$gray(renew-vless)$NC"
echo -e " [${grenbo}8${NC}]  ${RED}• ${NC}Check Vless login Account$NC$gray(cek-vless)$NC"  
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e " [${grenbo}9${NC}]  ${RED}• ${NC}Creating a Trojan Account$NC$gray(add-tr)$NC"
echo -e " [${grenbo}10${NC}] ${RED}• ${NC}Delete Trojan Account$NC$gray(del-tr)$NC"  
echo -e " [${grenbo}11${NC}] ${RED}• ${NC}Renew Trojan Account$NC$gray(renew-tr)$NC"  
echo -e " [${grenbo}12${NC}] ${RED}• ${NC}Check Trojan login Account$NC$gray(cek-tr)$NC"  
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e " [${grenbo}13${NC}]${RED}• ${NC}Server Speedtest$NC$gray(speedtest)$NC"
echo -e " [${grenbo}14${NC}]${RED}• ${NC}Reboot server$NC$gray(reboot)$NC"
  read -p "Select From Options [ 1 - 14 ] : " menu
case $menu in
1)
clear
add-ws
;;
2)
clear
del-ws
;;
3)
clear
renew-ws
;;
4)
clear
cek-ws
;;
5)
clear
add-vless
;;
6)
clear
del-vless
;;
7)
clear
renew-vless
;;
8)
clear
cek-vless
;;
9)
clear
add-tr
;;
10)
clear
del-tr
;;
11)
clear
renew-tr
;;
12)
clear
cek-tr
;;
13)
clear
speedtest
;;
14)
reboot
exit
;;
*)
clear
menu
;;
esac
