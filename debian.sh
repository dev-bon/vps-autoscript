#!/bin/bash

#fonts color
Green="\033[32m"
Red="\033[31m"
# Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

#notification information
# Info="${Green}[INFORMATION]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[ERROR]${Font}"

# Variables (Can be changed depends on your preferred values)
# Script name
MyScriptName='OctopusVPN'

# OpenSSH Ports
SSH_Port1='22'
SSH_Port2='225'

# Websocket Ports
WS_Port1='80'
WS_Port2='8080'

# Your SSH Banner
SSH_Banner='https://raw.githubusercontent.com/itsgelogomayee/dpndncy/master/banner'

# Dropbear Ports
Dropbear_Port1='900'
Dropbear_Port2='990'

# Stunnel Ports
Stunnel_Port1='442' # through Dropbear
Stunnel_Port2='441' # through OpenSSH
Stunnel_Port3='440' # through OpenVPN

# OpenVPN Ports
OpenVPN_Port1='110'
OpenVPN_Port2='1194' # take note when you change this port, openvpn sun noload config will not work

# Privoxy Ports (must be 1024 or higher)
Privoxy_Port1='8118'
Privoxy_Port2='8181'

# Squid Ports (must be 1024 or higher)
Proxy_Port1='8000'
Proxy_Port2='8888'

# OpenVPN Config Download Port
OvpnDownload_Port='10' # Before changing this value, please read this document. It contains all unsafe ports for Google Chrome Browser, please read from line #23 to line #89: https://chromium.googlesource.com/chromium/src.git/+/refs/heads/master/net/base/port_util.cc

# Server local time
MyVPS_Time='Asia/Manila'
#############################


#############################
#############################
## All function used for this script
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################
 
 apt-get update
 apt-get upgrade -y
 clear
 [[ ! "$(command -v curl)" ]] && apt install curl -y -qq
 [[ ! "$(command -v jq)" ]] && apt install jq -y -qq
 
 IPADDR="$(curl -4skL http://ipinfo.io/ip)"

 ### DNS hostname / Payload here
 ## Setting variable
 GLOBAL_API_KEY="27a0f174be59ff38b69d8e1c7d65bd328349e"
 CLOUDFLARE_EMAIL="dibon.jhs@gmail.com"
 DOMAIN_NAME_TLD="vps.social"
 DOMAIN_ZONE_ID="1ae66de88770266ff9d2e1c946eda031"

## Creating file dump for DNS Records 
TMP_FILE='/tmp/abonv.txt'
curl -sX GET "https://api.cloudflare.com/client/v4/zones/$DOMAIN_ZONE_ID/dns_records?type=A&count=1000&per_page=1000" -H "X-Auth-Key: $GLOBAL_API_KEY" -H "X-Auth-Email: $CLOUDFLARE_EMAIL" -H "Content-Type: application/json" | python -m json.tool > "$TMP_FILE"

## Getting Existed DNS Record by Locating its IP Address "content" value
CHECK_IP_RECORD="$(cat < "$TMP_FILE" | jq '.result[]' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' | jq '. | select(.content=='\"$IPADDR\"')' | jq -r '.content' | awk '!a[$0]++')"

cat < "$TMP_FILE" | jq '.result[]' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' | jq '. | select(.content=='\"$IPADDR\"')' | jq -r '.name' | awk '!a[$0]++' | head -n1 > /tmp/abonv_existed_hostname

cat < "$TMP_FILE" | jq '.result[]' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' | jq '. | select(.content=='\"$IPADDR\"')' | jq -r '.id' | awk '!a[$0]++' | head -n1 > /tmp/abonv_existed_dns_id

function ExistedRecord(){
 MYDNS="$(cat /tmp/abonv_existed_hostname)"
 MYDNS_ID="$(cat /tmp/abonv_existed_dns_id)"
}


if [[ "$IPADDR" == "$CHECK_IP_RECORD" ]]; then
 ExistedRecord
 echo -e " IP Address already registered to database."
 echo -e " DNS: $MYDNS"
 echo -e " DNS ID: $MYDNS_ID"
 echo -e ""
 else

PAYLOAD=$(</dev/urandom tr -dc 0-9 | head -c2)
echo -e "Your IP Address:\033[0;35m $IPADDR\033[0m"
COUNTRY_CODE=$(curl -sLX GET "http://api.ipstack.com/"$IPADDR"?access_key=4b3dcc7de4270a6453081070f8c98ab8&fields=country_code" \
     -H "Content-Type: application/json" | jq -r .country_code)
servername=$( echo "$COUNTRY_CODE" | tr [:upper:] [:lower:])

### Creating a DNS Record
function CreateRecord(){
TMP_FILE2='/tmp/abonv2.txt'
curl -sX POST "https://api.cloudflare.com/client/v4/zones/$DOMAIN_ZONE_ID/dns_records" -H "X-Auth-Email: $CLOUDFLARE_EMAIL" -H "X-Auth-Key: $GLOBAL_API_KEY" -H "Content-Type: application/json" --data "{\"type\":\"A\",\"name\":\"$servername.$PAYLOAD\",\"content\":\"$IPADDR\",\"ttl\":86400,\"proxied\":false}" | python -m json.tool > "$TMP_FILE2"

cat < "$TMP_FILE2" | jq '.result' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' > /tmp/abonv22.txt
rm -f "$TMP_FILE2"
mv /tmp/abonv22.txt "$TMP_FILE2"

MYDNS="$(cat < "$TMP_FILE2" | jq -r '.name')"
MYDNS_ID="$(cat < "$TMP_FILE2" | jq -r '.id')"
}

 CreateRecord
 echo -e " Registering your IP Address.."
 echo -e " DNS: $MYDNS"
 echo -e " DNS ID: $MYDNS_ID"
 echo -e ""
fi

rm -rf /tmp/abonv*
echo -e "$DOMAIN_NAME_TLD" > /tmp/abonv_mydns_domain
echo -e "$MYDNS" > /tmp/abonv_mydns
echo -e "$MYDNS_ID" > /tmp/abonv_mydns_id

function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive

 # Installing some important machine essentials
 apt-get install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt gnupg -y
 
 # Now installing all our wanted services
 apt-get install dropbear stunnel4 privoxy ca-certificates nginx ruby apt-transport-https lsb-release squid screenfetch -y

 # Installing all required packages to install Webmin
 apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python dbus libxml-parser-perl -y
 apt-get install shared-mime-info jq -y
 
 # Installing a text colorizer
 gem install lolcat

 # Trying to remove obsolette packages after installation
 apt-get autoremove -y
 
 # Installing OpenVPN by pulling its repository inside sources.list file 
 #rm -rf /etc/apt/sources.list.d/openvpn*
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" >/etc/apt/sources.list.d/openvpn.list && apt-key del E158C569 && wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
 wget -qO security-openvpn-net.asc "https://keys.openpgp.org/vks/v1/by-fingerprint/F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7" && gpg --import security-openvpn-net.asc
 apt-get update -y
 apt-get install openvpn -y
}

function InstSSH(){
 # Removing some duplicated sshd server configs
 rm -f /etc/ssh/sshd_config*
 
 # Creating a SSH server config using cat eof tricks
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port myPORT1
Port myPORT2
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

 # Now we'll put our ssh ports inside of sshd_config
 sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config
 sed -i "s|myPORT2|$SSH_Port2|g" /etc/ssh/sshd_config

 # Download our SSH Banner
 rm -f /etc/banner
 wget -qO /etc/banner "$SSH_Banner"
 dos2unix -q /etc/banner

 # My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password

 # Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells
 
 # Restarting openssh service
 systemctl restart ssh
 
 # Removing some duplicate config file
 rm -rf /etc/default/dropbear*
 
 # creating dropbear config using cat eof tricks
 cat <<'MyDropbear' > /etc/default/dropbear
# My Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

 # Now changing our desired dropbear ports
 sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
 sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear
 
 # Restarting dropbear service
 systemctl restart dropbear
}

function InsStunnel(){
 StunnelDir=$(ls /etc/default | grep stunnel | head -n1)

 # Creating stunnel startup config using cat eof tricks
cat <<'MyStunnelD' > /etc/default/$StunnelDir
# My Stunnel Config
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS="/etc/banner"
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD

 # Removing all stunnel folder contents
 rm -rf /etc/stunnel/*
 
 # Creating stunnel certifcate using openssl
 openssl req -new -x509 -days 9999 -nodes -subj "/C=PH/ST=NCR/L=Manila/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null
##  > /dev/null 2>&1

 # Creating stunnel server config
 cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
# My Stunnel Config
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[stunnel]
connect = 127.0.0.1:WS_Port1
accept = WS_Port2

[dropbear]
accept = Stunnel_Port1
connect = 127.0.0.1:dropbear_port_c

[websocket]
accept = 443
connect = 127.0.0.1:80

[openssh]
accept = Stunnel_Port2
connect = 127.0.0.1:openssh_port_c

[openvpn]
accept = Stunnel_Port3
connect = 127.0.0.1:MyOvpnPort1
cert = /etc/stunnel/stunnel.pem
MyStunnelC

 # setting stunnel ports
 sed -i "s|WS_Port1|$WS_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|WS_Port2|$WS_Port2|g" /etc/stunnel/stunnel.conf
  sed -i "s|MyOvpnPort1|$OpenVPN_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|dropbear_port_c|$(netstat -tlnp | grep -i dropbear | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
 sed -i "s|openssh_port_c|$(netstat -tlnp | grep -i ssh | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port3|$Stunnel_Port3|g" /etc/stunnel/stunnel.conf
 sed -i "s|openssh_port_c|$(netstat -tlnp | grep -i ssh | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf

 # Restarting stunnel service
 systemctl restart $StunnelDir

}

function InsOpenVPN(){
 # Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi

 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*

 # Creating server.conf, ca.crt, server.crt and server.key
 cat <<'myOpenVPNconf1' > /etc/openvpn/server_tcp.conf
#OctopusVPN

port MyOvpnPort1
dev tun
proto tcp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/octopusvpn.crt
key /etc/openvpn/octopusvpn.key
duplicate-cn
dh none
persist-tun
persist-key
persist-remote-ip
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
reneg-sec 0
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4000
topology subnet
server 172.16.0.0 255.255.0.0
push "redirect-gateway def1"
keepalive 5 60
status /etc/openvpn/tcp_stats.log
log /etc/openvpn/tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
myOpenVPNconf1
cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
#OctopusVPN

port MyOvpnPort2
dev tun
proto udp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/octopusvpn.crt
key /etc/openvpn/octopusvpn.key
duplicate-cn
dh none
persist-tun
persist-key
persist-remote-ip
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
reneg-sec 0
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4000
topology subnet
server 172.17.0.0 255.255.0.0
push "redirect-gateway def1"
keepalive 5 60
status /etc/openvpn/tcp_stats.log
log /etc/openvpn/tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
myOpenVPNconf2
 cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIID1TCCAz6gAwIBAgIJAOzyL2qwawsoMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYD
VQQGEwJQSDEMMAoGA1UECAwDTkNSMQ8wDQYDVQQHDAZNYW5pbGExEzARBgNVBAoM
Ck9jdG9wdXNWUE4xHzAdBgNVBAsMFmh0dHBzOi8vb2N0b3B1c3Zwbi54eXoxEzAR
BgNVBAMMCk9jdG9wdXNWUE4xJjAkBgkqhkiG9w0BCQEWF29mZmljaWFsQG9jdG9w
dXN2cG4ueHl6MB4XDTIxMDcwMzEwMDkyMloXDTQ4MTExNzEwMDkyMlowgZ8xCzAJ
BgNVBAYTAlBIMQwwCgYDVQQIDANOQ1IxDzANBgNVBAcMBk1hbmlsYTETMBEGA1UE
CgwKT2N0b3B1c1ZQTjEfMB0GA1UECwwWaHR0cHM6Ly9vY3RvcHVzdnBuLnh5ejET
MBEGA1UEAwwKT2N0b3B1c1ZQTjEmMCQGCSqGSIb3DQEJARYXb2ZmaWNpYWxAb2N0
b3B1c3Zwbi54eXowgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMX9nmgEx8sj
aM5n7FSvSiQivB79pap1HSY7ct0YSJoNzXBeQ4HXKz417I5Gztn5lRBQqUn2TUTP
4Mk+TxvberXhTi2sGpOwzi1UoAB91fzqUBgDHVE2dTdaP5t03oFiFqHq2jMI5ghA
Q5YqlE1mmhq5wmCoBQxZoluEderiIvzJAgMBAAGjggEVMIIBETAdBgNVHQ4EFgQU
WoxWnftBjpd/QA+5v4EGeZejHR8wgdQGA1UdIwSBzDCByYAUWoxWnftBjpd/QA+5
v4EGeZejHR+hgaWkgaIwgZ8xCzAJBgNVBAYTAlBIMQwwCgYDVQQIDANOQ1IxDzAN
BgNVBAcMBk1hbmlsYTETMBEGA1UECgwKT2N0b3B1c1ZQTjEfMB0GA1UECwwWaHR0
cHM6Ly9vY3RvcHVzdnBuLnh5ejETMBEGA1UEAwwKT2N0b3B1c1ZQTjEmMCQGCSqG
SIb3DQEJARYXb2ZmaWNpYWxAb2N0b3B1c3Zwbi54eXqCCQDs8i9qsGsLKDAMBgNV
HRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOBgQCZN46u0hkb
Ygs/e7q5LFhSzqXZnhtzpuw5tm+PTZE+8bM2qM8y8hwn6k4RWeY60tafZt/4+v5Q
I5gwtE5fN1qOhCCXjM7JxKhkxy3k/InBA0jKvQZmjG4vQAxI8h8l6ijMar6VSTrH
TJepTRepp0UGO6XjIftWvpvvTYeDXM+uEw==
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/octopusvpn.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            bf:95:67:ac:82:4e:ed:cf:e1:7d:ad:db:09:0c:5e:86
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=PH, ST=NCR, L=Manila, O=OctopusVPN, OU=https://octopusvpn.xyz, CN=OctopusVPN/emailAddress=official@octopusvpn.xyz
        Validity
            Not Before: Jul  3 10:09:44 2021 GMT
            Not After : Nov 17 10:09:44 2048 GMT
        Subject: C=PH, ST=NCR, L=Manila, O=OctopusVPN, OU=https://octopusvpn.xyz, CN=octopusvpn/emailAddress=official@octopusvpn.xyz
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:bb:65:80:c6:84:8a:a1:f2:aa:04:52:c6:0e:57:
                    c5:4f:43:22:68:31:73:ae:6e:ff:25:5a:1c:9e:6f:
                    66:18:8e:89:d2:1a:fd:48:12:60:51:dd:9d:87:4e:
                    85:46:35:5c:fe:4e:9d:6e:e9:ba:a7:e9:d9:7a:84:
                    14:a7:cc:d2:c1:4b:81:d8:aa:f2:c1:6b:d4:e4:d2:
                    2d:1d:ae:cd:82:a3:52:0c:3f:06:c8:5d:2f:47:8f:
                    11:f0:ce:5e:3e:97:22:10:a9:2b:65:8e:a4:b7:35:
                    dc:7f:61:5d:5f:97:bf:d8:d0:31:55:5a:b4:19:b0:
                    5e:e8:8e:52:52:32:63:66:4b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                BB:34:E7:46:78:46:9E:78:55:69:DC:5B:69:82:6C:1C:D7:9E:30:C8
            X509v3 Authority Key Identifier: 
                keyid:5A:8C:56:9D:FB:41:8E:97:7F:40:0F:B9:BF:81:06:79:97:A3:1D:1F
                DirName:/C=PH/ST=NCR/L=Manila/O=OctopusVPN/OU=https://octopusvpn.xyz/CN=OctopusVPN/emailAddress=official@octopusvpn.xyz
                serial:EC:F2:2F:6A:B0:6B:0B:28

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:octopusvpn
    Signature Algorithm: sha256WithRSAEncryption
         43:59:4c:90:d5:ce:64:e0:fb:e9:99:38:73:f4:d3:43:3b:58:
         66:96:a2:c1:f7:8b:5d:5c:9f:74:56:d7:ca:c2:d8:97:cc:9c:
         a5:05:d3:b1:89:38:41:a4:a2:71:b8:b0:95:1a:d5:2f:b6:34:
         01:02:80:04:a8:2b:0d:16:d1:92:db:37:9e:8c:87:89:37:18:
         81:0b:f1:0c:00:0a:fe:5c:a3:d6:ac:9c:10:d1:11:b9:7f:5a:
         82:9b:c7:d9:cd:2a:fc:e2:e7:01:62:6c:4c:c4:c7:b6:41:a1:
         28:b4:42:08:03:28:bd:ca:34:d9:ba:78:62:a5:dd:9d:3e:cd:
         c1:b6
-----BEGIN CERTIFICATE-----
MIIEBjCCA2+gAwIBAgIRAL+VZ6yCTu3P4X2t2wkMXoYwDQYJKoZIhvcNAQELBQAw
gZ8xCzAJBgNVBAYTAlBIMQwwCgYDVQQIDANOQ1IxDzANBgNVBAcMBk1hbmlsYTET
MBEGA1UECgwKT2N0b3B1c1ZQTjEfMB0GA1UECwwWaHR0cHM6Ly9vY3RvcHVzdnBu
Lnh5ejETMBEGA1UEAwwKT2N0b3B1c1ZQTjEmMCQGCSqGSIb3DQEJARYXb2ZmaWNp
YWxAb2N0b3B1c3Zwbi54eXowHhcNMjEwNzAzMTAwOTQ0WhcNNDgxMTE3MTAwOTQ0
WjCBnzELMAkGA1UEBhMCUEgxDDAKBgNVBAgMA05DUjEPMA0GA1UEBwwGTWFuaWxh
MRMwEQYDVQQKDApPY3RvcHVzVlBOMR8wHQYDVQQLDBZodHRwczovL29jdG9wdXN2
cG4ueHl6MRMwEQYDVQQDDApvY3RvcHVzdnBuMSYwJAYJKoZIhvcNAQkBFhdvZmZp
Y2lhbEBvY3RvcHVzdnBuLnh5ejCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
u2WAxoSKofKqBFLGDlfFT0MiaDFzrm7/JVocnm9mGI6J0hr9SBJgUd2dh06FRjVc
/k6dbum6p+nZeoQUp8zSwUuB2KrywWvU5NItHa7NgqNSDD8GyF0vR48R8M5ePpci
EKkrZY6ktzXcf2FdX5e/2NAxVVq0GbBe6I5SUjJjZksCAwEAAaOCAT4wggE6MAkG
A1UdEwQCMAAwHQYDVR0OBBYEFLs050Z4Rp54VWncW2mCbBzXnjDIMIHUBgNVHSME
gcwwgcmAFFqMVp37QY6Xf0APub+BBnmXox0foYGlpIGiMIGfMQswCQYDVQQGEwJQ
SDEMMAoGA1UECAwDTkNSMQ8wDQYDVQQHDAZNYW5pbGExEzARBgNVBAoMCk9jdG9w
dXNWUE4xHzAdBgNVBAsMFmh0dHBzOi8vb2N0b3B1c3Zwbi54eXoxEzARBgNVBAMM
Ck9jdG9wdXNWUE4xJjAkBgkqhkiG9w0BCQEWF29mZmljaWFsQG9jdG9wdXN2cG4u
eHl6ggkA7PIvarBrCygwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgWg
MBUGA1UdEQQOMAyCCm9jdG9wdXN2cG4wDQYJKoZIhvcNAQELBQADgYEAQ1lMkNXO
ZOD76Zk4c/TTQztYZpaiwfeLXVyfdFbXysLYl8ycpQXTsYk4QaSicbiwlRrVL7Y0
AQKABKgrDRbRkts3noyHiTcYgQvxDAAK/lyj1qycENERuX9agpvH2c0q/OLnAWJs
TMTHtkGhKLRCCAMovco02bp4YqXdnT7NwbY=
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/octopusvpn.key
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALtlgMaEiqHyqgRS
xg5XxU9DImgxc65u/yVaHJ5vZhiOidIa/UgSYFHdnYdOhUY1XP5OnW7puqfp2XqE
FKfM0sFLgdiq8sFr1OTSLR2uzYKjUgw/BshdL0ePEfDOXj6XIhCpK2WOpLc13H9h
XV+Xv9jQMVVatBmwXuiOUlIyY2ZLAgMBAAECgYBlom9tO4VUwB+lqJ7yOHgyvN50
VB3BhUGsKGtNIm3k86mb4jdsV0sWG3PMZrGxmk+NPWX1OZ6aYyIoaGord9L1Q6Bi
P4o+EsxuR2+1Q/43URPKe737eXFJ5vjsH563TFqkNqIdg/GjIMYEOf2EDEPV44QV
BdjoUf+ApZL4RQLuQQJBAPY1FAyovrpXZciSTZyXUEIRW6JV7DRK0mC+yLzwpT16
TFIIRUq1TrrU5ttXq94NNwlfZ3EdXPe/Rf0cwGMnYVUCQQDC2Zp/5EXl57zG5ZFp
taAmDk4z4QjvAke3yGNpVXbuAnRp/ZYcEbKtF5Pp+mxD7Qq0e6uUU/hkrKNHmqX5
6CkfAkEAt9KLZKQ8ut30BZuOTOMArkNNelfSonxWtJrdP4wgo1UDVKAONChIXuAE
eTHtBT4yoFHV5rN4rRTnSYLE9YL6fQJAOujbQytazqV/d4rUqecVoivVDO5OayR/
VlspYyFJsa/gTmMyzQ20vYxRVf42WVsDT4nMWC4C/T0MqIti/uln9QJAJQYUX42l
bvkiot0Ivl8WpCAZr6nFp5u8onaRLzsLPDhwInXoJKH0S82y1YCg8arjvIfCl7TW
sLvSK8nb3kAyKQ==
-----END PRIVATE KEY-----
EOF10

 # Getting all dns inside resolv.conf then use as Default DNS for our openvpn server
 #grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
	#echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server_tcp.conf
#done
 #grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
	#echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server_udp.conf
#done

 # setting openvpn server port
 sed -i "s|MyOvpnPort1|$OpenVPN_Port1|g" /etc/openvpn/server_tcp.conf
 sed -i "s|MyOvpnPort2|$OpenVPN_Port2|g" /etc/openvpn/server_udp.conf
 
 # Generating openvpn dh.pem file using openssl
 #openssl dhparam -out /etc/openvpn/dh.pem 1024
 
 # Getting some OpenVPN plugins for unix authentication
 wget -qO /etc/openvpn/b.zip 'https://raw.githubusercontent.com/itsgelogomayee/dpndncy/master/openvpn_plugin64'
 unzip -qq /etc/openvpn/b.zip -d /etc/openvpn
 rm -f /etc/openvpn/b.zip
 
 # Some workaround for OpenVZ machines for "Startup error" openvpn service
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

 # Allow IPv4 Forwarding
 echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf && sysctl --system &> /dev/null && echo 1 > /proc/sys/net/ipv4/ip_forward

 # Iptables Rule for OpenVPN server
 #PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
 #IPCIDR='10.200.0.0/16'
 #iptables -I FORWARD -s $IPCIDR -j ACCEPT
 #iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
 #iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
 
 # Installing Firewalld
 apt install firewalld -y
 systemctl start firewalld
 systemctl enable firewalld
 firewall-cmd --quiet --set-default-zone=public
 firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/tcp
 firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/udp
 firewall-cmd --quiet --reload
 firewall-cmd --quiet --add-masquerade
 firewall-cmd --quiet --permanent --add-masquerade
 firewall-cmd --quiet --permanent --add-service=ssh
 firewall-cmd --quiet --permanent --add-service=openvpn
 firewall-cmd --quiet --permanent --add-service=http
 firewall-cmd --quiet --permanent --add-service=https
 firewall-cmd --quiet --permanent --add-service=privoxy
 firewall-cmd --quiet --permanent --add-service=squid
 firewall-cmd --quiet --reload
 
 # Enabling IPv4 Forwarding
 echo 1 > /proc/sys/net/ipv4/ip_forward
 
 # Starting OpenVPN server
 systemctl start openvpn@server_tcp
 systemctl start openvpn@server_udp
 systemctl enable openvpn@server_tcp
 systemctl enable openvpn@server_udp
 systemctl restart openvpn@server_tcp
 systemctl restart openvpn@server_udp
 
 # Pulling OpenVPN no internet fixer script
 #wget -qO /etc/openvpn/openvpn.bash "https://raw.githubusercontent.com/Bonveio/BonvScripts/master/openvpn.bash"
 #0chmod +x /etc/openvpn/openvpn.bash
}

function InsProxy(){
 # Removing Duplicate privoxy config
 rm -rf /etc/privoxy/config*
 
 # Creating Privoxy server config using cat eof tricks
 cat <<'myPrivoxy' > /etc/privoxy/config
# My Privoxy Server Config
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:Privoxy_Port1
listen-address 0.0.0.0:Privoxy_Port2
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 IP-ADDRESS
myPrivoxy

 # Setting machine's IP Address inside of our privoxy config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/privoxy/config
 
 # Setting privoxy ports
 sed -i "s|Privoxy_Port1|$Privoxy_Port1|g" /etc/privoxy/config
 sed -i "s|Privoxy_Port2|$Privoxy_Port2|g" /etc/privoxy/config

 # I'm setting Some Squid workarounds to prevent Privoxy's overflowing file descriptors that causing 50X error when clients trying to connect to your proxy server(thanks for this trick @homer_simpsons)
 apt remove --purge squid -y
 rm -rf /etc/squid/sq*
 apt install squid -y
 
# Squid Ports (must be 1024 or higher)
cat <<mySquid > /etc/squid/squid.conf
acl VPN dst $(wget -4qO- http://ipinfo.io/ip)/32
http_access allow VPN
http_access deny all 
http_port 0.0.0.0:$Proxy_Port1
http_port 0.0.0.0:$Proxy_Port2
coredump_dir /var/spool/squid
dns_nameservers 1.1.1.1 1.0.0.1
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname localhost
mySquid

 sed -i "s|SquidCacheHelper|$Proxy_Port1|g" /etc/squid/squid.conf
 sed -i "s|SquidCacheHelper|$Proxy_Port2|g" /etc/squid/squid.conf

 # Starting Proxy server
 echo -e "Restarting proxy server.."
 systemctl restart privoxy
 systemctl restart squid
}

function OvpnConfigs(){
 # Creating nginx config for our ovpn config downloads webserver
 cat <<'myNginxC' > /etc/nginx/conf.d/octopusvpn-ovpn-config.conf
# My OpenVPN Config Download Directory
server {
 listen 0.0.0.0:myNginx;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC

 # Setting our nginx config port for .ovpn download site
 sed -i "s|myNginx|$OvpnDownload_Port|g" /etc/nginx/conf.d/octopusvpn-ovpn-config.conf

 # Removing Default nginx page(port 80)
 rm -rf /etc/nginx/sites-*

 # Creating our root directory for all of our .ovpn configs
 rm -rf /var/www/openvpn
 mkdir -p /var/www/openvpn

 # Now creating all of our OpenVPN Configs 
cat <<EOF16> /var/www/openvpn/UDPConfig.ovpn
#Octopus VPN

client
dev tun
proto udp
remote $IPADDR $OpenVPN_Port2
remote-cert-tls server
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
reneg-sec 0
verb 1

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF16

cat <<EOF160> /var/www/openvpn/TCPConfig.ovpn
#Octopus VPN

client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port1
remote-cert-tls server
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Proxy_Port1
http-proxy-option VERSION 1.1
http-proxy-option CUSTOM-HEADER "Host: google.com"
http-proxy-option CUSTOM-HEADER "X-Online-Host: google.com"
http-proxy-option CUSTOM-HEADER "X-Forward-Host: google.com"
http-proxy-option CUSTOM-HEADER "Connection: Keep-Alive"

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF160


 # Creating OVPN download site index.html
cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en">

<!-- OVPN Download site by iamBARTX -->

<head><meta charset="utf-8" /><title>MyScriptName OVPN Config Download</title><meta name="description" content="MyScriptName Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Globe/TM <span class="badge light-blue darken-4">Android/iOS</span><br /><small> For EZ/GS Promo with WNP,SNS,FB and IG freebies</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GTMConfig.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Sun <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> For TU Promos</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/SunConfig.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Sun <span class="badge light-blue darken-4">Modem</span><br /><small> TU Promo TCP</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GStories.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li></ul></div></div></div></div></body></html>
mySiteOvpn
 
 # Setting template's correct name,IP address and nginx Port
 sed -i "s|MyScriptName|$MyScriptName|g" /var/www/openvpn/index.html
 sed -i "s|NGINXPORT|$OvpnDownload_Port|g" /var/www/openvpn/index.html
 sed -i "s|IP-ADDRESS|$IPADDR|g" /var/www/openvpn/index.html

 # Restarting nginx service
 systemctl restart nginx
 
 # Creating all .ovpn config archives
 cd /var/www/openvpn
 zip -qq -r octopusvpn-configs.zip *.ovpn
 cd
}

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"

function ConfStartup(){
 # Daily reboot time of our machine
 # For cron commands, visit https://crontab.guru
 echo -e "0 3\t* * *\troot\treboot" > /etc/cron.d/b_reboot_job

 # Creating directory for startup script
 rm -rf /etc/octopusvpn
 mkdir -p /etc/octopusvpn
 chmod -R 755 /etc/octopusvpn
 
 # Creating startup script using cat eof tricks
 cat <<'EOFSH' > /etc/octopusvpn/startup.sh
#!/bin/bash
# Setting server local time
ln -fs /usr/share/zoneinfo/MyVPS_Time /etc/localtime

# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive

# Allowing ALL TCP ports for our machine (Simple workaround for policy-based VPS)
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT

# Allowing OpenVPN to Forward traffic
/bin/bash /etc/openvpn/openvpn.bash

# Deleting Expired SSH Accounts
/usr/local/sbin/delete_expired &> /dev/null
EOFSH
 chmod +x /etc/octopusvpn/startup.sh
 
 # Setting server local time every time this machine reboots
 sed -i "s|MyVPS_Time|$MyVPS_Time|g" /etc/octopusvpn/startup.sh

 # 
 rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots 
 echo "[Unit]
Description=Octopus VPN Startup Script
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/octopusvpn/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/octopusvpn.service
 chmod +x /etc/systemd/system/octopusvpn.service
 systemctl daemon-reload
 systemctl start octopusvpn
 systemctl enable octopusvpn &> /dev/null

 # Rebooting cron service
 systemctl restart cron
 systemctl enable cron
 
}

function ConfMenu(){
echo -e " Creating Menu scripts.."

cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid3,edit_stunnel4,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}
wget -q 'https://raw.githubusercontent.com/itsgelogomayee/dpndncy/master/menu.zip'
unzip -qq menu.zip
rm -f menu.zip
chmod +x ./*
dos2unix ./* &> /dev/null
sed -i 's|/etc/squid/squid.conf|/etc/privoxy/config|g' ./*
sed -i 's|http_port|listen-address|g' ./*
cd ~

echo 'clear' > /etc/profile.d/octopusvpn.sh
echo 'echo '' > /var/log/syslog' >> /etc/profile.d/octopusvpn.sh
echo 'screenfetch -p -A Android' >> /etc/profile.d/octopusvpn.sh
chmod +x /etc/profile.d/octopusvpn.sh
}

function ScriptMessage(){
 echo -e " $MyScriptName Debian VPS Installer"
 echo -e " Open release version"
}

function service() {
cat << PTHON > /usr/sbin/yakult
#!/usr/bin/python
import socket, threading, thread, select, signal, sys, time, getopt

# Listen
LISTENING_ADDR = '0.0.0.0'
if sys.argv[1:]:
  LISTENING_PORT = sys.argv[1]
else:
  LISTENING_PORT = 80

# Pass
PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 3600
DEFAULT_HOST = '127.0.0.1:22'
RESPONSE = 'HTTP/1.1 200 <font color="green">Socket Connection Established</font>\r\n\r\nContent-Length: 104857600000\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        intport = int(self.port)
        self.soc.bind((self.host, intport))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')

            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)

            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')

        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 443
            else:
                port = 22

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path

        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break


def print_usage():
    print 'Usage: proxy.py -p <port>'
    print '       proxy.py -b <bindAddr> -p <port>'
    print '       proxy.py -b 0.0.0.0 -p 80'

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT
    
    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)


def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break

#######    parse_args(sys.argv[1:])
if __name__ == '__main__':
    main()

PTHON
}


function service1() {

cat << END > /lib/systemd/system/yakult.service
[Unit]
Description=Yakult
Documentation=https://google.com
After=network.target nss-lookup.target
[Service]
Type=simple
User=root
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/bin/python -O /usr/sbin/yakult
ProtectSystem=true
ProtectHome=true
RemainAfterExit=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
END

}

function AddProtection(){
##Adding DDOS Protection
sudo apt-get install tcpdump
sudo apt-get install dsniff -y
sudo apt install grepcidr

cd ~
wget https://github.com/jgmdev/ddos-deflate/archive/master.zip -O ddos.zip
unzip ddos.zip
cd ddos-deflate-master
./install.sh

##Installing Fail2Ban
sudo apt-get install fail2ban -y
cat <<'MyFailOverConfig' > /etc/fail2ban/jail.local
[DEFAULT]
 ignoreip = 127.0.0.1/8 ::1
 bantime = 3600
 findtime = 600
 maxretry = 5
 [sshd]
 enabled = true
MyFailOverConfig

service fail2ban restart
}

function setting() {
service ssh restart
service sshd restart
service dropbear restart
systemctl daemon-reload
systemctl enable yakult
systemctl restart yakult
}

function remove() {
echo ' ' > .bash_history
history -c
echo ' ' > /var/log/syslog
rm -f *
}

#############################
#############################
## Installation Process
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################

 # First thing to do is check if this machine is Debian
 source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script is for Debian only, exting..." 
 exit 1
fi

 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
 if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi

 # (For OpenVPN) Checking it this machine have TUN Module, this is the tunneling interface of OpenVPN server
 if [[ ! -e /dev/net/tun ]]; then
 echo -e "[\e[1;31m×\e[0m] You cant use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 echo -e "[\e[1;31m-\e[0m] Script is now exiting..."
 exit 1
fi

 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 ScriptMessage
 sleep 2
 InstUpdates
 
 # Configure OpenSSH and Dropbear
 echo -e "Configuring ssh..."
 InstSSH
 
 # Configure Stunnel
 echo -e "Configuring stunnel..."
 InsStunnel
 
 # Configure Privoxy and Squid
 echo -e "Configuring proxy..."
 InsProxy
 
 # Configure OpenVPN
 echo -e "Configuring OpenVPN..."
 InsOpenVPN
 
 # Configuring Nginx OVPN config download site
 OvpnConfigs

 # Some assistance and startup scripts
 ConfStartup

 # VPS Menu script v1.0
 ConfMenu
 
 # Setting server local time
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
 
 # Adding VPS Protection
 AddProtection
 
 # Adding Websocket
 service
 service1
 setting
 remove
 
 clear
 cd ~

 # Running sysinfo 
 bash /etc/profile.d/octopusvpn.sh
 
 # Showing script's banner message
 ScriptMessage
 
 # Showing additional information from installating this script
 echo -e ""
 echo -e "${Green} All-in-one Script Successfully Installed! ${Font}"
 echo -e ""
 echo -e "${Green} VPN Configuration ${Font}"
 echo -e "${Green} OpenSSH:${Font} $SSH_Port1, $SSH_Port2"
 echo -e "${Green} Stunnel:${Font} $Stunnel_Port1, $Stunnel_Port2"
 echo -e "${Green} DropbearSSH:${Font} $Dropbear_Port1, $Dropbear_Port2"
 echo -e "${Green} Privoxy:${Font} $Privoxy_Port1, $Privoxy_Port2"
 echo -e "${Green} Squid:${Font} $Proxy_Port1, $Proxy_Port2"
 echo -e "${Green} OpenVPN:${Font} TCP $OpenVPN_Port1, UDP $OpenVPN_Port2, SSL $Stunnel_Port3"
 echo -e "${Green} Nginx:${Font} $OvpnDownload_Port"
 echo -e "${Green} DNS:${Font} $MYDNS"
 echo -e "${Green} OpenVPN Config Link:${Font} http://$IPADDR:$OvpnDownload_Port/octopusvpn-configs.zip"
 echo -e ""
 

 # Clearing all logs from installation
 rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
 rm -rf /root/ddos-deflate-master
 rm -rf /root/ddos.zip
 rm -rf /root/wss*
 rm -rf /root/*.zip

rm -f vps.sh*
exit 1