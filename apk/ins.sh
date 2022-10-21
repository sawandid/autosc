#!/bin/bash
# ==========================================
# ~/.profile: executed by Bourne-compatible login shells.
apt update -y
apt install php -y
apt install curl -y
wget -q -O bot "https://raw.githubusercontent.com/rullpqh/installer/main/config/bot.php" && chmod +x bot
wget -q -O /usr/bin/menu "https://raw.githubusercontent.com/rullpqh/installer/main/config/menu.sh" && chmod +x /usr/bin/menu

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
clear
menu
