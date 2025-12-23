#!/usr/bin/env bash

# Credit Dwizy22 / Project

# Anjaii

# Thanks To:
# PR_Aiman ( Testing )
# Rerechan02 ( Donatur & Owner )
# Farell Aditya ( Bot Dev & Encryption )
# Dinda Putri Cindyani ( - )

# Collor
BIBlack='\033[1;90m'
BIGreen='\033[1;92m'
BIYellow='\033[1;93m'
BIWhite='\033[1;97m'
BILime='\e[38;5;155m'
NC='\033[0m'


# ==============================================================
url_izin='https://raw.githubusercontent.com/dwiexe/izin-ipp/refs/heads/main/ipvpss.txt'

ip_vps=$(curl -s ipinfo.io/ip)

izin=$(curl -s "$url_izin")

if [[ -n "$izin" ]]; then
  found=false
  while IFS= read -r line; do

    nama=$(echo "$line" | awk '{print $2}')
    ipvps=$(echo "$line" | awk '{print $3}')
    tanggal=$(echo "$line" | awk '{print $5}')

    if [[ "$ipvps" == "$ip_vps" ]]; then
      found=true
      echo "Nama VPS: $nama"
      echo "IP VPS: $ipvps"
      echo "Tanggal Kadaluwarsa: $tanggal"

      tanggal_kadaluwarsa=$(date -d "$tanggal" +%Y-%m-%d)
      tanggal_sekarang=$(date +%Y-%m-%d)

      if [[ "$tanggal_sekarang" > "$tanggal_kadaluwarsa" || "$tanggal_sekarang" == "$tanggal_kadaluwarsa" ]]; then
        clear
        echo "VPS telah expired!"
        exit 1
      else
      clear
      echo "VPS masih aktif."
      fi
      break
    fi
  done <<< "$izin"

  if [[ "$found" == false ]]; then
    clear
    echo "IP VPS tidak ditemukan dalam izin.txt"
    exit 1
  fi
else
  echo "Konten izin.txt tidak berhasil didapatkan dari URL"
  exit 1
fi

clear
read -p "Input Domain: " domain
#read -p "Input Nameserver: " nsdomain

#Resolv
echo -e "nameserver 1.1.1.1" >> /etc/resolv.conf

# Memperbaiki Port Default Login SSH
cd /etc/ssh
find . -type f -name "*sshd_config*" -exec sed -i 's|#Port 22|Port 22|g' {} +
echo -e "Port 3303" >> sshd_config
cd
systemctl daemon-reload
systemctl restart ssh
systemctl restart sshd

# Non Interactive
export DEBIAN_FRONTEND=noninteractive
apt update

# Package
apt install socat -y
apt install jq -y
apt install wget curl -y
apt install binutils -y
apt install zip -y
apt install unzip -y
apt install certbot -y
apt install gnupg -y
apt install openssl -y
apt install bc -y
apt install lsof -y
apt install htop -y
apt install gzip -y
apt install bzip2 -y
apt install cron -y
apt install lolcat -y
apt install ruby -y
gem install lolcat
apt install gcc -y
apt install clang -y
apt install vnstat -y
apt install sqlite3 -y
apt install wireguard -y
apt install wireguard-tools -y
apt install lsb-release
apt install net-tools -y
apt install iptables -y
apt install nethogs -y
apt install nodejs -y
apt install acct -y
sudo apt install -y php-fpm php-cli php-json jq curl sqlite3
apt install haproxy -y
rm -f /etc/haproxy/haproxy.cfg


# Package Lain
apt-get install build-essential autoconf libtool libssl-dev libpcre3-dev libev-dev asciidoc xmlto automake -y
apt-get install software-properties-common -y
apt install shadowsocks-libev -y
apt install simple-obfs -y

clear
# Melakukan Pengambilan File Database
#wget -O /m.zip "https://github.com/Farell-VPN/.dump/releases/download/1.0.3/citlali.zip"
wget -q -O /m.zip "https://codeberg.org/dwiexe/scvps/raw/branch/main/main.zip"
cd /
yes A | unzip m.zip
rm -f /m.zip

# Melakukan Permision
chmod +x /usr/local/bin/*
chmod +x /usr/local/rere/*
chmod +x /usr/local/rere/api/vps/*
chmod +x /usr/local/rere/api/*
chmod +x /usr/local/xray-new/*
chmod +x /usr/local/xray-old/*
chmod +x /usr/local/v2ray/*
chmod +x /etc/funny/json/*
chmod +x /etc/funny/default/sslh/*
chmod +x /etc/funny/nginx/*
chmod +x /etc/funny/slowdns/*
chmod +x /etc/funny/websocket/*
chmod +x /etc/funny/udp-custom/*

# Memperbaiki Service X-Ray
apt install sudo -y
sudo chown -R root:root /var/log/xray/
chmod -R 750 /var/log/xray/
systemctl daemon-reload
systemctl enable xray-ws xray-hu xray-grpc xray-xhttp xray-tcp
systemctl start xray-ws xray-hu xray-grpc xray-xhttp xray-tcp
systemctl enable udp-custom
systemctl start udp-custom

# Installasi Dropbear
apt install dropbear -y
clear
DROPBEAR_BIN="/usr/sbin/dropbear"
DROPBEAR_LIB="/usr/lib/dropbear"
DROPBEAR_CONFIG="/etc/dropbear"
DROPBEAR_MAN="/usr/share/man/man8/dropbear.8.gz"
DROPBEAR_URL="https://matt.ucc.asn.au/dropbear/releases"
clear
# Install Dropbear 2019
DROPBEAR_VERSION="2019.78"
# Hentikan Dropbear jika berjalan
if systemctl stop dropbear || service dropbear stop; then
    echo -e "${BIGreen}Dropbear dihentikan.${BIWhite}"
else
    echo -e "${BIRed}Gagal menghentikan Dropbear.${BIWhite}"
fi
clear
if [ -f "$DROPBEAR_BIN" ]; then
    echo -e "${BIGreen}Backup versi lama Dropbear...${BIWhite}"
    cp $DROPBEAR_BIN /usr/sbin/dropbear.bak
fi
rm -f $DROPBEAR_BIN $DROPBEAR_LIB/* $DROPBEAR_CONFIG/* $DROPBEAR_MAN
clear
# Install dependensi
apt-get update && apt-get install -y build-essential zlib1g-dev wget || yum groupinstall "Development Tools" -y && yum install zlib-devel wget -y
clear
# Download Dropbear
echo -e "${BIGreen}Mengunduh Dropbear versi $DROPBEAR_VERSION...${BIWhite}"
wget --no-check-certificate -O dropbear.tar.bz2 "$DROPBEAR_URL/dropbear-$DROPBEAR_VERSION.tar.bz2"
# Ekstrak file
tar -xjf dropbear.tar.bz2
cd "dropbear-$DROPBEAR_VERSION" || exit
clear
./configure --prefix=/usr && make && make install
clear
mv /usr/bin/dropbear $DROPBEAR_BIN
mkdir -p $DROPBEAR_LIB
mkdir -p $DROPBEAR_CONFIG
if [ -f "/usr/share/man/man8/dropbear.8.gz" ]; then
    mv /usr/share/man/man8/dropbear.8.gz $DROPBEAR_MAN
else
    echo -e "${BIYellow}File man tidak ditemukan.${BIWhite}"
fi

clear
# Buat ulang key
rm -f /etc/dropbear/dropbear_rsa_host_key
rm -f /etc/dropbear/dropbear_dss_host_key
rm -f /etc/dropbear/dropbear_ecdsa_host_key
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
dropbearkey -t dss -f /etc/dropbear/dropbear_dss_host_key
dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key
chmod 600 /etc/dropbear/dropbear_rsa_host_key
chmod 600 /etc/dropbear/dropbear_dss_host_key
chmod 600 /etc/dropbear/dropbear_ecdsa_host_key
clear
if systemctl start dropbear || service dropbear start; then
    echo -e "${BIGreen}Dropbear berhasil dimulai.${BIWhite}"
else
    echo -e "${BIRed}Gagal memulai Dropbear.${BIWhite}"
fi
clear
if dropbear -V; then
    echo -e "${BIGreen}Dropbear versi $DROPBEAR_VERSION telah terinstal.${BIWhite}"
else
    echo -e "${BIRed}Verifikasi gagal, Dropbear mungkin tidak terinstal dengan benar.${BIWhite}"
fi
clear
cd ..
rm -rf dropbear.tar.bz2 "dropbear-$DROPBEAR_VERSION"
# Pesan akhir
echo -e "${BIWhite}──────────────────────────────────────────${NC}"
echo -e "${BIGreen}Dropbear version $DROPBEAR_VERSION installed successfully!${NC}"
rm /etc/default/dropbear
rm /etc/issue.net
cat> /etc/issue.net << END
</strong> <p style="text-align:center"><b> <br><font color="#00FFE2"<br>┏━━━━━━━━━━━━━━━┓<br> RERECHAN STORE<br>┗━━━━━━━━━━━━━━━┛<br></font><br><font color="#00FF00"></strong> <p style="text-align:center"><b> <br><font color="#00FFE2">क═══════क⊹⊱✫⊰⊹क═══════क</font><br><font color='#FFFF00'><b> ★ [ ༆Hʸᵖᵉʳ᭄W̺͆E̺͆L̺͆C̺͆O̺͆M̺͆E̺͆
T̺͆O̺͆ M̺͆Y̺͆ S̺͆E̺͆R̺͆V̺͆E̺͆R̺͆ V͇̿I͇̿P͇̿ ] ★ </b></font><br><font color="#FFF00">ℝ𝕖𝕣𝕖𝕔𝕙𝕒𝕟 𝕊𝕥𝕠𝕣𝕖</font><br> <font color="#FF00FF">❖Ƭʜᴇ No DDOS</font><br> <font color="#FF0000">❖Ƭʜᴇ No Torrent</font><br> <font color="#FFB1C2">❖Ƭʜᴇ No Bokep </font><br> <font color="#FFFFFF">❖Ƭʜᴇ No Hacking</font><br>
<font color="#00FF00">❖Ƭʜᴇ No Mining</font><br> <font color="#00FF00">➳ᴹᴿ᭄ Oder / Trial :
https://wa.me/6283120684925 </font><br>
<font color="#00FFE2">क═══════क⊹⊱✫⊰⊹क═══════क</font><br></font><br><font color="FFFF00">❖Ƭʜᴇ WHATSAPP GRUP => https://chat.whatsapp.com/LlJmbvSQ2DsHTA1EccNGoO</font><br>
END
cat>  /etc/default/dropbear << END
# All configuration by FN Project / Rerechan02
# Dinda Putri Cindyani
# disabled because OpenSSH is installed
# change to NO_START=0 to enable Dropbear
NO_START=0
# the TCP port that Dropbear listens on
DROPBEAR_PORT=111

# any additional arguments for Dropbear
DROPBEAR_EXTRA_ARGS="-p 109 -p 69 "

# specify an optional banner file containing a message to be
# sent to clients before they connect, such as "/etc/issue.net"
DROPBEAR_BANNER="/etc/issue.net"

# RSA hostkey file (default: /etc/dropbear/dropbear_rsa_host_key)
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"

# DSS hostkey file (default: /etc/dropbear/dropbear_dss_host_key)
#DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"

# ECDSA hostkey file (default: /etc/dropbear/dropbear_ecdsa_host_key)
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"

# Receive window size - this is a tradeoff between memory and
# network performance
DROPBEAR_RECEIVE_WINDOW=65536
END
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
clear
systemctl daemon-reload
/etc/init.d/dropbear restart
clear

curl ipinfo.io/org > /root/.isp
curl ipinfo.io/region > /root/.region
curl ipinfo.io/ip > /root/.ip

# Menjalankan SSH WebSocket
systemctl daemon-reload
systemctl enable multiplex
systemctl start multiplex
systemctl enable ws-stunnel
systemctl start ws-stunnel
systemctl enable ws-dual
systemctl start ws-dual

# Melakukan Enable Pada SSLH
apt install sslh -y
systemctl daemon-reload
systemctl enable sslh
systemctl start sslh

# Menyalakan Dukungan Video Call, Telefon & Gaming
systemctl daemon-reload
systemctl enable badvpn-7100
systemctl restart badvpn-7100
systemctl enable badvpn-7200
systemctl restart badvpn-7200
systemctl enable badvpn-7300
systemctl restart badvpn-7300
systemctl enable badvpn-7400
systemctl restart badvpn-7400
systemctl enable badvpn-7500
systemctl restart badvpn-7500
systemctl enable badvpn-7600
systemctl restart badvpn-7600
systemctl enable badvpn-7700
systemctl restart badvpn-7700
systemctl enable badvpn-7800
systemctl restart badvpn-7800
systemctl enable badvpn-7900
systemctl restart badvpn-7900

# Menyimpan Data Domain & NS Domain
echo "$domain" > /etc/xray/domain
#echo "$nsdomain" > /etc/funny/slowdns/nsdomain

#Install OpenVPN
https://github.com/FN-Rere02/.-/releases/download/v1.0/sslh
[[ -e $(which curl) ]] && grep -q "1.1.1.1" /etc/resolv.conf || { 
    echo "nameserver 1.1.1.1" | cat - /etc/resolv.conf >> /etc/resolv.conf.tmp && mv /etc/resolv.conf.tmp /etc/resolv.conf
}

clear
red='\e[1;31m'
green='\e[0;32m'
blue='\e[0;34m'
cyan='\e[0;36m'
cyanb='\e[46m'
white='\e[037;1m'
grey='\e[1;36m'
NC='\e[0m'
# ==================================================
# Lokasi Hosting Penyimpan autoscript
# hosting="https://scvps.rerechanstore.eu.org"
domain=$(cat /etc/xray/domain)

# var installation
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";
ANU=$(ip -o $ANU -4 route show to default | awk '{print $5}');

# Install OpenVPN dan Easy-RSA
apt install openvpn -y
apt install openvpn easy-rsa -y
apt install unzip -y
apt install openssl iptables iptables-persistent -y
mkdir -p /etc/openvpn/server/easy-rsa/
cd /etc/openvpn/
wget -q https://github.com/FN-Rerechan02/arsip/raw/main/vpn.zip
unzip vpn.zip
rm -f vpn.zip
chown -R root:root /etc/openvpn/server/easy-rsa/

cd
mkdir -p /usr/lib/openvpn/
cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so

# nano /etc/default/openvpn
sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn

# restart openvpn dan cek status openvpn
systemctl enable --now openvpn-server@server-tcp-1194
systemctl enable --now openvpn-server@server-udp-2200
/etc/init.d/openvpn restart
/etc/init.d/openvpn status

# aktifkan ip4 forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

# Buat config client TCP 1194
cat > /etc/openvpn/client-tcp-1194.ovpn <<-END
client
dev tun
proto tcp
setenv FRIENDLY_NAME "Beginner TCP"
remote xxxxxxxxx 1194
http-proxy xxxxxxxxx 3128
resolv-retry infinite
route-method exe
auth-user-pass
auth-nocache
nobind
persist-key
persist-tun
comp-lzo
verb 3
END

sed -i $MYIP2 /etc/openvpn/client-tcp-1194.ovpn;

# Buat config client UDP 2200
cat > /etc/openvpn/client-udp-2200.ovpn <<-END
client
dev tun
proto udp
setenv FRIENDLY_NAME "Beginner UDP"
remote xxxxxxxxx 3128
resolv-retry infinite
route-method exe
auth-user-pass
auth-nocache
nobind
persist-key
persist-tun
comp-lzo
verb 3
END

sed -i $MYIP2 /etc/openvpn/client-udp-2200.ovpn;

cd
# pada tulisan xxx ganti dengan alamat ip address VPS anda
/etc/init.d/openvpn restart

# masukkan certificatenya ke dalam config client TCP 1194
echo '<ca>' >> /etc/openvpn/client-tcp-1194.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/client-tcp-1194.ovpn
echo '</ca>' >> /etc/openvpn/client-tcp-1194.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( TCP 1194 )
cp /etc/openvpn/client-tcp-1194.ovpn /var/www/html/client-tcp-1194.ovpn

# masukkan certificatenya ke dalam config client UDP 2200
echo '<ca>' >> /etc/openvpn/client-udp-2200.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/client-udp-2200.ovpn
echo '</ca>' >> /etc/openvpn/client-udp-2200.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( UDP 2200 )
cp /etc/openvpn/client-udp-2200.ovpn /var/www/html/client-udp-2200.ovpn

    # Membuat arsip ZIP dari konfigurasi
    cd /var/www/html/
    zip FN-Project.zip client-tcp-1194.ovpn client-udp-2200.ovpn > /dev/null 2>&1
    cd

    # Membuat halaman HTML untuk mengunduh konfigurasi
    cat <<'EOF' > /var/www/html/index.html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>OVPN Config Download</title>
  <meta name="description" content="Server" />
  <meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" />
  <meta name="theme-color" content="#000000" />
  <link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      font-family: 'Courier New', monospace;
      background-color: #f6f8fa;
      padding: 2em;
      color: #333;
    }
    h5 {
      font-weight: bold;
      color: #0366d6;
    }
    p, a {
      font-size: 16px;
      line-height: 1.6;
    }
    .badge {
      background-color: #0366d6;
      color: white;
    }
    .container {
      background-color: white;
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 1px 3px rgba(27,31,35,.12), 0 8px 24px rgba(27,31,35,.1);
    }
    .list-group-item {
      border: none;
      padding-left: 0;
      font-family: 'Courier New', monospace;
    }
    a {
      text-decoration: none;
      color: #0366d6;
    }
    a:hover {
      text-decoration: underline;
    }
    ul {
      list-style-type: none;
      padding: 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <h5>Config List</h5>
    <ul>
      <li class="list-group-item d-flex justify-content-between align-items-center">
        <p>TCP <span class="badge">Android/iOS/PC/Modem</span></p>
        <a href="https://IP-ADDRESS/fn/client-tcp-1194.ovpn">Download</a>
      </li>
      <li class="list-group-item d-flex justify-content-between align-items-center">
        <p>UDP <span class="badge">Android/iOS/PC/Modem</span></p>
        <a href="https://IP-ADDRESS/fn/client-udp-2200.ovpn">Download</a>
      </li>
      <li class="list-group-item d-flex justify-content-between align-items-center">
        <p>ALL.zip <span class="badge">Android/iOS/PC/Modem</span></p>
        <a href="https://IP-ADDRESS/fn/FN-Project.zip">Download</a>
      </li>
    </ul>
  </div>
</body>
</html>
EOF

    sed -i "s|IP-ADDRESS|$domain|g" /var/www/html/index.html
    
#firewall untuk memperbolehkan akses UDP dan akses jalur TCP

iptables -t nat -I POSTROUTING -s 10.6.0.0/24 -o $ANU -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.7.0.0/24 -o $ANU -j MASQUERADE
iptables-save > /etc/iptables.up.rules
chmod +x /etc/iptables.up.rules

iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# Restart service openvpn
systemctl daemon-reload
systemctl enable openvpn
systemctl start openvpn
/etc/init.d/openvpn restart

# Membuat File Zip OVPN
cd /var/www/html
zip openvpn.zip *.ovpn
cd

#Squid Proxy
apt install sudo -y
wget -q https://raw.githubusercontent.com/serverok/squid-proxy-installer/master/squid3-install.sh -O squid3-install.sh
sudo bash squid3-install.sh
rm -f squid3-install.sh

if [ -f /etc/squid/squid.conf ]; then
  cd /etc/squid
  find . -type f -name "*squid.conf*" -exec sed -i 's|http_access allow password|http_access allow all|g' {} +
  systemctl daemon-reload
  systemctl restart squid
elif [ -f /etc/squid3/squid.conf ]; then
  cd /etc/squid3
  find . -type f -name "*squid.conf*" -exec sed -i 's|http_access allow password|http_access allow all|g' {} +
  systemctl daemon-reload
  systemctl restart squid3
else
  echo "Konfigurasi squid tidak ditemukan di /etc/squid maupun /etc/squid3"
fi

#Setup Open HTTP Puncher
# Download File Ohp
cd /usr/local/bin
wget -q -O ohpserver "https://github.com/Farell-VPN/Backend-ssh/releases/download/1.0/ohpserver"
chmod +x ohpserver
cd

# Installing Service
# SSH OHP Port 8181
cat > /etc/systemd/system/ohp-ssh.service << END
[Unit]
Description=SSH OHP Redirection Service
Documentation=https://t.me/farell_aditya_ardian
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/ohpserver -port 8181 -proxy 127.0.0.1:3128 -tunnel 127.0.0.1:22
Restart=on-failure
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
END

# Dropbear OHP 8282
cat > /etc/systemd/system/ohp-dropbear.service << END
[Unit]]
Description=Dropbear OHP Redirection Service
Documentation=https://https://t.me/farell_aditya_ardian
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/ohpserver -port 8282 -proxy 127.0.0.1:3128 -tunnel 127.0.0.1:109
Restart=on-failure
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
END

# OpenVPN OHP 8383
cat > /etc/systemd/system/ohp-openvpn.service << END
[Unit]]
Description=OpenVPN OHP Redirection Service
Documentation=https://t.me/farell_aditya_ardian
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/ohpserver -port 8383 -proxy 127.0.0.1:3128 -tunnel 127.0.0.1:1194
Restart=on-failure
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload
systemctl enable ohp-ssh
systemctl restart ohp-ssh
systemctl enable ohp-dropbear
systemctl restart ohp-dropbear
systemctl enable ohp-openvpn
systemctl restart ohp-openvpn
#------------------------------
printf 'INSTALLATION COMPLETED !\n'
sleep 0.5
clear

# Delete script
history -c
rm -f /root/*.sh
rm -f /root/install
rm -f /root/*install*
rm -f "$0"

# Setup Socks5 Proxy Server
sudo apt install dante-server curl -y
sudo touch /var/log/danted.log
sudo chown root:root /var/log/danted.log
primary_interface=$(ip route | grep default | awk '{print $5}')
sudo bash -c "cat <<EOF > /etc/danted.conf
logoutput: /var/log/danted.log
internal: 0.0.0.0 port = 1080
external: $primary_interface
method: username
user.privileged: root
client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect error
}
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect error
}
EOF"
sudo sed -i '/\[Service\]/a ReadWriteDirectories=/var/log' /usr/lib/systemd/system/danted.service
sudo systemctl daemon-reload
sudo systemctl restart danted
sudo systemctl enable danted

#Server konfigurasi ShadowSocks
echo "Konfigurasi Server."
cat > /etc/shadowsocks-libev/config.json <<END
{   
    "server":"0.0.0.0",
    "server_port":8488,
    "password":"tes",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
}
END
systemctl enable shadowsocks-libev.service
systemctl start shadowsocks-libev.service
echo "Konfigurasi Server OBFS."
cat > /etc/shadowsocks-libev.json <<END
{
    "server":"127.0.0.1",
    "server_port":8388,
    "local_port":1080,
    "password":"",
    "timeout":60,
    "method":"chacha20-ietf-poly1305",
    "mode":"tcp_and_udp",
    "fast_open":true,
    "plugin":"/usr/bin/obfs-local",
    "plugin_opts":"obfs=tls;failover=127.0.0.1:1443;fast-open"
}
END
chmod +x /etc/shadowsocks-libev.json
echo -e "">>"/etc/shadowsocks-libev/akun.conf"
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 2443:3543 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 2443:3543 -j ACCEPT
iptables-save > /etc/iptables.up.rules
ip6tables-save > /etc/ip6tables.up.rules
    
# Mengganti semua domain & nsdomain
cd /etc/funny/nginx

cd /etc/systemd/system

# Stop Port HTTP 80
port=$(lsof -i:80 | awk '{print $1}')
systemctl stop apache2
systemctl disable apache2
pkill $port

#apt install nginx -y

# Manual Nginx
apt update && apt install -y build-essential libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev curl wget gnupg2 ca-certificates lsb-release && \
cd /usr/local/src && \
curl -O http://nginx.org/download/nginx-1.18.0.tar.gz && \
tar zxvf nginx-1.18.0.tar.gz && cd nginx-1.18.0 && \
./configure --prefix=/etc/nginx \
            --sbin-path=/usr/sbin/nginx \
            --conf-path=/etc/nginx/nginx.conf \
            --pid-path=/run/nginx.pid \
            --lock-path=/var/lock/nginx.lock \
            --with-http_ssl_module \
            --with-http_v2_module \
            --with-http_gzip_static_module \
            --with-http_stub_status_module \
            --with-http_realip_module \
            --with-threads \
            --with-pcre && \
make && make install

# Cek apakah nginx terpasang dan versinya 1.18.0
if nginx -V 2>&1 | grep -q 'nginx/1.18.0'; then
  echo "[OK] Nginx 1.18.0 berhasil terinstall."
  # Buat systemd service
  cat > /etc/systemd/system/nginx.service <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=network.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s quit
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
mkdir -p /var/log/nginx
touch /var/log/nginx/error.log
chmod 755 /var/log/nginx/error.log

#  systemctl daemon-reexec
#  systemctl enable nginx
  echo "[OK] Service Nginx berhasil dibuat dan di-enable."
else
  echo "[!!] Gagal menginstall Nginx 1.18.0, fallback ke APT..."
  rm -rf /etc/nginx /usr/sbin/nginx /etc/systemd/system/nginx.service
  apt install nginx -y
fi


echo -e "include /etc/funny/nginx/fn.conf;" > /etc/nginx/nginx.conf

systemctl daemon-reload
systemctl restart dnstt

systemctl stop nginx
yes Y | certbot certonly --standalone --preferred-challenges http --agree-tos --email dindaputri@rerechanstore.eu.org -d $domain 
cp /etc/letsencrypt/live/$domain/fullchain.pem /etc/xray/xray.crt
cp /etc/letsencrypt/live/$domain/privkey.pem /etc/xray/xray.key
cd /etc/xray
chmod 644 /etc/xray/xray.key
chmod 644 /etc/xray/xray.crt
echo -e "" >> /etc/haproxy/haproxy.cfg
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/funny.pem
chmod 755 /etc/haproxy/funny.pem
systemctl enable haproxy
systemctl start haproxy

# menyimpan Domain
sed -i "s|server_name fn.com;|server_name $domain;|" /etc/funny/nginx/main.conf
sed -i "s|server_name fn.com;|server_name $domain;|" /etc/funny/nginx/website.conf

wget -q https://github.com/dharak36/Xray-core/releases/download/v1.0.0/xray.linux.64bit
mv xray.linux.64bit /usr/local/bin/xray
chmod +x /usr/local/bin/xray

cp /usr/local/bin/xray /usr/local/rere/
chmod +x /usr/local/rere/xray

echo -e "
0 0 * * * root echo -n > /var/log/xray/access.log
0 0 * * * root echo -n > /var/log/xray/ws.log
0 0 * * * root echo -n > /var/log/xray/upgrade.log
0 0 * * * root echo -n > /var/log/xray/tcp.log
0 0 * * * root echo -n > /var/log/xray/grpc.log
0 0 * * * root echo -n > /var/log/xray/xhttp.log
*/15 * * * * root echo -n > /var/log/xray/error.log
*/15 * * * * root echo -n > /var/log/syslog
*/15 * * * * root echo -n > /var/log/auth.log
*/15 * * * * root echo -n > /var/log/auth
*/15 * * * * root echo -n > /var/log/daemon.log
*/15 * * * * root echo -n > /var/log/nginx/error.log
*/15 * * * * root /usr/local/rere/xp-ssh
*/15 * * * * root /usr/local/rere/xp-xray-ws
*/15 * * * * root /usr/local/rere/xp-xray-grpc
*/15 * * * * root /usr/local/rere/xp-xray-hu
*/15 * * * * root /usr/local/rere/xp-xray-xhttp
*/15 * * * * root /usr/local/rere/xp-xray-tcp
*/15 * * * * root /usr/local/rere/xp-noobz
*/15 * * * * root /usr/local/rere/xp-ss
*/15 * * * * root /usr/local/rere/zivpn-expired
*/15 * * * * root /usr/local/rere/limit-ip-ssh
*/15 * * * * root /usr/local/rere/limit-ip-xray-ws
*/15 * * * * root /usr/local/rere/limit-ip-xray-hu
*/15 * * * * root /usr/local/rere/limit-ip-xray-grpc
*/15 * * * * root /usr/local/rere/limit-ip-xray-xhttp
*/15 * * * * root /usr/local/rere/limit-ip-xray-tcp
*/15 * * * * root /usr/local/rere/limit-quota-xray-ws
*/15 * * * * root /usr/local/rere/limit-quota-xray-hu
*/15 * * * * root /usr/local/rere/limit-quota-xray-grpc
*/15 * * * * root /usr/local/rere/limit-quota-xray-xhttp
*/15 * * * * root /usr/local/rere/limit-quota-xray-tcp
0 0,1,3,5,6,9,11,12,13,15,17,18,21,23 * * * root /usr/local/rere/backup
*/5 * * * * root echo -n > /var/log/v2ray/access.log
*/5 * * * * root echo -n > /var/log/v2ray/error.log
" >> /etc/crontab

# Setup NoobzVPNS
clear

mkdir -p /etc/noobzvpns
cd /etc/noobzvpns
rm -fr *
cat > /etc/noobzvpns/config.toml <<EOF
[tcp_plain]
local_host = ["1"]

[tcp_ssl]
tls_version = "AUTO"
key_pem = "/etc/noobzvpns/key.pem"
cert_pem = "/etc/noobzvpns/cert.pem"

[client]
ip_version = "AUTO"
tcp_initial_timeout = 30
resolv_conf = "/etc/resolv.conf"
identifier = "fn-project"
banner = "You are connected to noobzvpn-server"
tcp_http_response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

[remote]
tcp_connect_timeout = 30
tcp_idle_timeout = 900
udp_connect_timeout = 30
udp_idle_timeout = 60
udp_dns_timeout = 10

[database]
database_monitor_timer = 10
device_timeout = 5

[runtime]
worker_threads = 0
EOF

echo -e "-----BEGIN CERTIFICATE-----
MIIELzCCAxegAwIBAgIUGhIZwEA/0IFP3KURL29AIiUVcSgwDQYJKoZIhvcNAQEL
BQAwgaYxCzAJBgNVBAYTAklEMRIwEAYDVQQIDAlJbmRvbmVzaWExEDAOBgNVBAcM
B0pha2FydGExGjAYBgNVBAoMEU5vb2J6LUlEIFNvZnR3YXJlMRowGAYDVQQLDBFO
b29iei1JRCBTb2Z0d2FyZTERMA8GA1UEAwwITm9vYnotSUQxJjAkBgkqhkiG9w0B
CQEWF2Nob2xpZXp0enVsaXpAZ21haWwuY29tMB4XDTI1MDIxNzAyMTQ1OVoXDTM5
MTIwMTAyMTQ1OVowgaYxCzAJBgNVBAYTAklEMRIwEAYDVQQIDAlJbmRvbmVzaWEx
EDAOBgNVBAcMB0pha2FydGExGjAYBgNVBAoMEU5vb2J6LUlEIFNvZnR3YXJlMRow
GAYDVQQLDBFOb29iei1JRCBTb2Z0d2FyZTERMA8GA1UEAwwITm9vYnotSUQxJjAk
BgkqhkiG9w0BCQEWF2Nob2xpZXp0enVsaXpAZ21haWwuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj1AAhxDEwUrut651O6gtF+FfTZg2nal8bysR
0mY7jfnZxlgFG2ifwsC+i0opQz0PKTBivWmixFRlrFOcLWill5Ppb0dqnZVKrjDQ
/BzG3xtwu55uvlqdc4mOjiSKq0wv8bj5q15VG6CW4XFn6SLoj9EwMBxfODUrDHta
y2NWuBmOaitOXBnPH+lMdoFMFgP6vX2afZyc0fFZuLs309OUp0FhwWfEZuR5ZWza
bPmzsOaRE6SW2aCEd2gh/iN0h1cg+rLtERvVqMsKGvkyBKFrTdmqKGjxxUTs9ic7
bbc+8NXErJ1tz6Bcx23sMysotCv5CszbtOijvl7VbmEPIj8ndQIDAQABo1MwUTAd
BgNVHQ4EFgQUaAErMBPSu92aFASB7/Ee+D9wrfgwHwYDVR0jBBgwFoAUaAErMBPS
u92aFASB7/Ee+D9wrfgwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAGBZRPPkldO451WpDEHXbM5fbgEd8NMcwgVXmzwHhCR+mNlEsSvUgKvTjdXYF
C+QF9ySl9lbv67Ux81RIRGQeHRP3i6y2sGRvhzYgGsFo2HRrVaNElVgYfsF0yCuv
f2v8C4Fv6YD20lsv0VJnCUydJxUnd0W7jKFLtz/lbT3UWR7QoUbUClGVkFVzLjI9
YJo3I2le4qQdGVa8v95IPHVjn2a70ZW7yWu4rxy4vGW2TTeDU9Ea8LxCFxTUqdw7
ssgXqSbj0rQ0RYJX25wlx1M76SRMZrwExDdVMfElKYdCiaWwxeR4Ah2jRzWUIODD
QMxYIXQ+zecXfw9WjrPLcIS1Fg==
-----END CERTIFICATE-----" > cert.pem
echo -e "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCPUACHEMTBSu63
rnU7qC0X4V9NmDadqXxvKxHSZjuN+dnGWAUbaJ/CwL6LSilDPQ8pMGK9aaLEVGWs
U5wtaKWXk+lvR2qdlUquMND8HMbfG3C7nm6+Wp1ziY6OJIqrTC/xuPmrXlUboJbh
cWfpIuiP0TAwHF84NSsMe1rLY1a4GY5qK05cGc8f6Ux2gUwWA/q9fZp9nJzR8Vm4
uzfT05SnQWHBZ8Rm5HllbNps+bOw5pETpJbZoIR3aCH+I3SHVyD6su0RG9Woywoa
+TIEoWtN2aooaPHFROz2Jztttz7w1cSsnW3PoFzHbewzKyi0K/kKzNu06KO+XtVu
YQ8iPyd1AgMBAAECggEABaDM8ID4VSX584U6reXYJYKwkTXL2Uu9awk8OTDSIGyC
QK+WvcGRWp7irMo0DiOw+3teuVUTcxXka0zaSo88R5Rju77IgVlKVkZtAqWnqr3j
Yr7hVwDsg4vQqSTmvDzw+hN7XJ9HBN985WwkekuoafN7arxGggjWgLY8ddXYI0Ew
olaBWBUUTC1+l86LOgMIeV65lhHbRvMRF+tQxA0L/8fG+ktkNXCg0OTFmWnVQQZv
wtQ0FVJc8se6k3DHFm5xLYPtiGciS+yYFxhNUvo8DjlmIG0gD0x4TZSGhqI3v3aS
hYl/Kpx1PbqK7E1J+iGOzRv/uzsaJrluvytF/i628QKBgQDDApSKHAW2cyDqUPwN
z8Vxpn+jpbngVvnS2LCS1xrYhKwpTYR1yxYZiljkGeQmdnKFDAKvXAgyIb57SoXl
Zyqcc7UWlh85QYj3T8yQsIHJM3ggJ3C3WfqZ/cAJPUj+tm5YgsZtlH7eTYjpi2Yr
JdSdvUfOL7FMGw5qIRdXS4aEEQKBgQC8IkW1cjEm/09uU3XF4/I/JYtCe4mUlsh5
rCeFWHKbR2Hx8v5JbaU4SoVHfrtFFHz4bvsb4bZu0Ts1cWkjSLQHZ1N5GVHVURzr
6JogC4hXrpCNLeDUjIJJ0IJwaf9CRiipP9hGEfCL9cabxgLH2jrqiq+qNLC6JrM3
ZUHYHqoBJQKBgQCjR1DJxqa92e2wY3h3tASUoRz0D3nvrcNlWAuYF0UiDwv7VS1Y
V1+8qMq+yjLuRXSjk6fX3g36s6hCoOY1askR0AvKyo2AKjAdKpKUf0VcCp1FBuDo
lA0wzHbzBX5Nzr/bmju8Wn5TccX2DcLQ088O+AHcULB5kZnjIKvjaphJkQKBgBSB
S8W9/3t3okmtEQ4TjSiyx93kJxep44nXaKtQ+5TPD+7WBD8uky5yeNpVBsY9uG0/
c2ETldW4OlLV3Ja66txPt7pgNxof8B4KSRorB54+6YRptrKT6fNvpXfpJagsi2v/
CGyCsgwfKpl52H293GQJ36GWgpiXdTsZbzbGCNN9AoGAApM6gxL+rcNBMCpaWEI5
82Pi/uhvraAcw+eMBEKPYrqD+1TKhreE+IaDbhpvThnFiFdTWQ3i56dmQniyuwpb
i2PWbaQBPbagKNZTbLkL+NBKaFdsosONPrpPBSG8KDan0fkDLF2FZRKkBSEhGE3C
UBZ21BoShXaSFL8ctilQp18=
-----END PRIVATE KEY-----" > key.pem

wget -q -O /usr/bin/noobzvpns "https://github.com/noobz-id/noobzvpns/raw/master/noobzvpns.x86-64"
chmod +x /usr/bin/noobzvpns

echo -e "[Unit]
Description=NoobzVpn-Server
Wants=network-online.target
After=network.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
User=root
Type=simple
TimeoutStopSec=1
LimitNOFILE=infinity
ExecStart=/usr/bin/noobzvpns start-server

[Install]
WantedBy=multi-user.target
" > /etc/systemd/system/noobzvpns.service

chmod +x /etc/noobzvpns/*
cd

systemctl daemon-reload
systemctl enable noobzvpns
systemctl start noobzvpns


systemctl daemon-reload
systemctl enable nginx
systemctl start nginx
systemctl enable quota
systemctl restart quota
systemctl restart cron
systemctl enable v2ray
systemctl start v2ray
systemctl restart v2ray
clear

# Service Limit Quota
systemctl daemon-reload
systemctl start quota-ws
systemctl start quota-hu
systemctl start quota-xhttp
systemctl start quota-tcp
systemctl start quota-grpc

systemctl enable quota-ws
systemctl enable quota-hu
systemctl enable quota-xhttp
systemctl enable quota-tcp
systemctl enable quota-grpc

# Restart main port
systemctl daemon-reload
systemctl restart haproxy

#Backup Setup
curl https://rclone.org/install.sh | bash
printf "q\n" | rclone config
rm -fr /root/.config/rclone/rclone.conf
cat > /root/.config/rclone/rclone.conf <<EOL
[rerechan]
type = drive
scope = drive
use_trash = false
metadata_owner = read,write
metadata_permissions = read,write
metadata_labels = read,write
token = {"access_token":"ya29.a0AZYkNZgbRJZcQjDt_mqZ6fyNmTfWkQYc8mzf6SyfR0Wk16YR3RUCuQf4hMol3izLaj43Q1R85EqCKNO0yrY2igEuactxcaZPhscBz1UJM8HhO5VT05Om4wG96mdVT4iyPQJ91vnIjr6tGMFGc6Ieh1-N4aYKOc-4dqY4xp0JaCgYKARcSARESFQHGX2MikSBSmHt3K5WTimMhqcm8jQ0175","token_type":"Bearer","refresh_token":"1//0gy_QhkW2lmAaCgYIARAAGBASNwF-L9Ircw-lb7lBdaev_Pq_ml4hZcnSJ1r4mHs3jnj4HFZ7e6a2RQPLAsJa1DBuHesE4MkVRbg","expiry":"2025-04-13T02:20:19.628115625Z"}


EOL
cd /root
echo -e "PATH=/usr/local/rere:$PATH" >> /root/.bashrc
source /root/.bashrc
echo -e "source /root/.bashrc\ninfo" >> /root/.profile
touch /root/.system

clear
id1="6389176425"
token1="6230907878:AAExag4j8lRsJbMdAIv6T9STI1g6kp_Vq68"
URL="https://api.telegram.org/bot$token1/sendMessage"
TIME=$(date)
TEXT="
<code>────────────────────</code>
<b>NOTIFICATIONS INSTALL AutoScript</b>
<code>────────────────────</code>
<code>user   : </code><code>$nama</code>
<code>ID     : </code><code>Premium FN Project</code>
<code>Domain : </code><code>$domain</code>
<code>Date   : </code><code>$TIME</code>
<code>Ip vps : </code><code>$(cat /root/.ip)</code>
<code>────────────────────</code>
<i>Automatic Notification from Github</i>
"

curl -s -X POST $URL -d "chat_id=$id1&text=$TEXT&parse_mode=html"
clear
echo -e ""
echo -e "Success Install Script On Server"
sleep 5
reboot
