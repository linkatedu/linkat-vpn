#!/bin/bash

## Declarar variables
VPN_CONF_FILE=/etc/linkat/linkat-vpn/linkat-vpn.conf
PLANTILLES=/usr/share/linkat/linkat-vpn/plantilles
FILES_LINKAT=/usr/share/linkat/linkat-vpn/configurador/files
ANSIBLEPLAY=/usr/share/linkat/linkat-vpn/configurador
DATE=`date '+%Y-%m-%d_%H:%M:%S'`


### FUNCTIONS 

function isRoot() {
        if [ "$EUID" -ne 0 ]; then
                return 1
        fi
}

function tunAvailable() {
        if [ ! -e /dev/net/tun ]; then
                return 1
        fi
}

function checkOS() {
if [[ $ID == "ubuntu" ]]; then
                        OS="ubuntu"
                        MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
                        if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
                                echo "⚠️  Aquesta versió de Linkat no està suportada."
                                echo ""
                                echo "Per altra banda, si estàs utilitzant una versió de Linkat >= 16.04 o experimental, pots continuar, sota la teva responsabilitat."
                                echo ""
                                until [[ $CONTINUE =~ (y|n) ]]; do
                                        read -rp "Continue? [y/n]: " -e CONTINUE
                                done
                                if [[ $CONTINUE == "n" ]]; then
                                        exit 1
                                fi
                        fi
                fi
}

function initialCheck() {
        if ! isRoot; then
                echo "Sorry, you need to run this as root"
                exit 1
        fi
        if ! tunAvailable; then
                echo "TUN is not available"
                exit 1
        fi
        checkOS
}

function initialCheck() {
        if ! isRoot; then
                echo "Sorry, you need to run this as root"
                exit 1
        fi
        if ! tunAvailable; then
                echo "TUN is not available"
                exit 1
        fi
        checkOS
}

if [ -f "$VPN_CONF_FILE" ]; then
  . "$VPN_CONF_FILE"
else
  NEW_NAME="servidor"
  NEW_DOMAIN="intracentre"
  NEW_DEV=""
  NEW_IP="192.168.0.240"
  NEW_VPN_PORT="24"
  NEW_VPN_PROTOCOL="192.168.0.1"
  NEW_DNS1="213.176.161.16"
  NEW_DNS2="213.176.161.18"
  NEW_PASSROOT1=""
  NEW_PASSROOT2=""
  NEW_PASSLNADMIN1=""
  NEW_PASSLNADMIN2=""
fi



## Llista de targetes de xarxa
LIST_DEV=`ip link sh | grep ^[0-9] | grep -v " lo" | cut -d":" -f 2 | tr -d " "`
DEVS=$(echo $LIST_DEV)
## Control d'errors
ERROR="1"
res=""


## VPN PARAMETERS #########################################################

## PORTS VPN
VPN_DEFAULT_PORT="1194"
VPN_CUSTOM_PORT="Personalitzat"
GEN_RANDOM_PORT="$(shuf -i49152-65535 -n1)" 
VPN_RANDOM_PORT="Aleatori:"$GEN_RANDOM_PORT""
NEW_VPN_PORT=$(echo "$VPN_DEFAULT_PORT $VPN_CUSTOM_PORT $VPN_RANDOM_PORT")

## PROTOCOLS VPN
PROTOCOL="udp tcp"
NEW_VPN_PROTOCOL="udp tcp"

## COMPRESSION VPN
COMPRESSION_ENABLED="Deshabilitada Habilitada"
COMPRESSION_ALG="lz4-v2 lz4 lzo"


## ENCRYPTION SETTINGS ###################################################

ENCRYPT="Estandar Personalitzada"

CIPHER="AES-128-GCM"
CERT_TYPE="1" # ECDSA
CERT_CURVE="prime256v1"
CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
DH_TYPE="1" # ECDH
DH_CURVE="prime256v1"
HMAC_ALG="SHA256"
TLS_SIG="1" # tls-crypt



## Revisar valor de xarxa
check_ip()
{
        echo "$2" | grep -E '^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])$' > /dev/null 2>&1
        if [ "$?" -gt 0 ]; then
                yad --title="Error" --text="\nEl valor $1: $2 no és vàlid." --image="dialog-error" --button="D'acord"
                ERROR="1"
        fi
}

## Revisar connexió
check_connexio()
{
        sudo hping3 -S google.com -p 443 -c 4
        if [ $? -eq 0 ]; then
                CONNEXIO="1"
        else
                echo -en "Error de connexió: Reviseu la configuració de xarxa"
                exit 12
        fi
}

## Revisar contrasenya
check_pass()
{
        if [ ! "$2" == "$3" ]; then
                yad --title="Error" --text="\nLa contrasenya de l'usuari $1 no coincideix." --image="dialog-error" --button="D'acord"
                ERROR="1"
        fi

        if [ -z "$2" ] || [ -z "$3" ]; then
                yad --title="Error" --text="\nLa contrasenya de l'usuari $1 és buida." --image="dialog-error" --button="D'acord"
                ERROR="1"
        fi

        for passnum in "$2"; do
                if [ ${#passnum} -lt 8 ]; then
                        yad --title="Error" --text="\nLa contrasenya de l'usuari $1 ha de contenir almenys 8 caràcters." --image="dialog-error" --button="D'acord"
                        ERROR="1"
                fi
        done
}

## Formulari de dades de configuracions del servidor OpenVPN

formulari()
{
res=$(yad --width=400 --title="Linkat Servidor Openvpn" --text="\nAquest instal·lador configura el servidor VPN Linkat.\nIntroduïu els valors per configurar el sevidor de centre.\nPots deixar els valors per defecte.\nCal emplenar tots els camps.\n\nConfiguracions del servidor:\n" \
--image="/usr/share/linkat/linkat-servidor/linkat-servidor-banner.png" \
--form --item-separator=" " \
--field="Nom del servidor" \
--field="Nom del domini" \
--field="Targeta de xarxa":CBE \
--field="IP pública del servidor VPN" \
--field="Port Servidor VPN":CBE \
--field="Protocol":CBE \
--field="Habilitar compressió (No recomanat)":CBE \
--field="Encriptació":CBE \
--field="DNS Primària" \
--field="DNS Secundària" \
--button="D'acord" --button="Cancel·la":11 \
"$NEW_NAME" "NEW_DOMAIN" "$DEVS" "$NEW_IP" "$NEW_VPN_PORT" "$NEW_VPN_PROTOCOL" "$COMPRESSION_ENABLED" "$ENCRYPT" "$NEW_DNS1" "$NEW_DNS2")
res1="$?"

if [ "$res1" -gt 1 ]; then
        exit 1
fi

NEW_NAME=$(echo "$res" | awk -F"|" '{print $1}')
NEW_DOMAIN=$(echo "$res" | awk -F"|" '{print $2}')
NEW_DEV=$(echo "$res" | awk -F"|" '{print $3}')
NEW_IP=$(echo "$res" | awk -F"|" '{print $4}')
NEW_VPN_PORT=$(echo "$res" | awk -F"|" '{print $5}')
NEW_VPN_PROTOCOL=$(echo "$res" | awk -F"|" '{print $6}')
COMPRESSION_ENABLED=$(echo "$res" | awk -F"|" '{print $7}')
ENCRYPT=$(echo "$res" | awk -F"|" '{print $8}')
NEW_DNS1=$(echo "$res" | awk -F"|" '{print $9}')
NEW_DNS2=$(echo "$res" | awk -F"|" '{print $10}')
}

check_errors()
{
if [ ! "$?" -eq 0 ]; then
        echo -en "Error: $1"
        yad --title="Error" --text="\nS'ha produit un error durant la instal·lacio de: $1.\nEl programa es tancara." --image="dialog-error" --button="D'acord"
        exit 22
fi
}

validar_formulari()
{
yad --width=400 --title="Linkat Servidor Openvpn" --text="\nLes dades següents són correctes?\n\nServidor: $NEW_NAME\nDomini: $NEW_DOMAIN\nDispositiu: $NEW_DEV\nIP: $NEW_IP\nPort: $NEW_VPN_PORT\nProtocol: $NEW_VPN_PROTOCOL\nCompressió habilitada: $COMPRESSION_ENABLED\nEncriptació: $ENCRYPT\nDNS Primària: $NEW_DNS1\nDNS Secundària: $NEW_DNS2" \
--image="/usr/share/linkat/linkat-servidor/linkat-servidor-banner.png" \
--button="D'acord" --button="Cancel·la":11
res1="$?"

if [ "$res1" -gt 1 ]; then
        ERROR="1"
fi
}

while [ "$ERROR" -eq 1 ]; do
        ERROR="0"
        formulari
        check_ip IP "$NEW_IP"
        #check_ip Passarel·la "$NEW_VPN_PROTOCOL"
        check_ip DNS "$NEW_DNS1"
  	check_ip DNS "$NEW_DNS2"
        #check_pass root "$NEW_PASSROOT1" "$NEW_PASSROOT2"
        #check_pass lnadmin "$NEW_PASSLNADMIN1" "$NEW_PASSLNADMIN2"
        if [ "$ERROR" -eq 0 ]; then
                validar_formulari
        fi
done



## Backup del fitxer de configuració linkat-servidor.conf
if [ -f "$CONF_FILE" ]; then
        cp -av "$CONF_FILE" "$CONF_FILE"."$DATE"
fi

## Genera nou fitxer de configuració linkat-servidor.conf
echo "$DATE" > $CONF_FILE
echo "NEW_NAME=$NEW_NAME" >> $CONF_FILE
echo "NEW_DOMAIN=$NEW_DOMAIN" >> $CONF_FILE
echo "NEW_DEV=$NEW_DEV" >> $CONF_FILE
echo "NEW_IP=$NEW_IP" >> $CONF_FILE
echo "NEW_VPN_PORT=$NEW_VPN_PORT" >> $CONF_FILE
echo "NEW_VPN_PROTOCOL=$NEW_VPN_PROTOCOL" >> $CONF_FILE
echo "NEW_DNS1=$NEW_DNS1" >> $CONF_FILE
echo "NEW_DNS2=$NEW_DNS2" >> $CONF_FILE
echo "NEW_PASSROOT=$NEW_PASSROOT1" >> $CONF_FILE
echo "NEW_PASSLNADMIN=$NEW_PASSLNADMIN1" >> $CONF_FILE





## Copia plantilles per modificar
rm -rf "$FILES_LINKAT"/*
cp -av "$PLANTILLES"/* "$FILES_LINKAT"/

## Aplica els nous valors al fitxer de configuració linkat-servidor.conf
### DNS ###
IP1=$(echo "$NEW_IP" | cut -d "." -f 1 2>&1)
IP2=$(echo "$NEW_IP" | cut -d "." -f 2 2>&1)
IP3=$(echo "$NEW_IP" | cut -d "." -f 3 2>&1)
IP4=$(echo "$NEW_IP" | cut -d "." -f 4 2>&1)

cd "$FILES_LINKAT"/

sed -i s/__NAME__/"$NEW_NAME"/g *
sed -i s/__DOMAIN__/"$NEW_DOMAIN"/g *
sed -i s/__DEV__/"$NEW_DEV"/g *
sed -i s/__IP__/"$NEW_IP"/g *
sed -i s/__NEW_VPN_PORT__/"$NEW_VPN_PORT"/g *
sed -i s/__NEW_VPN_PROTOCOL__/"$NEW_VPN_PROTOCOL"/g *
sed -i s/__DNS1__/"$NEW_DNS1"/g *
sed -i s/__DNS2__/"$NEW_DNS2"/g *
sed -i s/__PASSROOT__/"$NEW_PASSROOT1"/g *
sed -i s/__PASSLNADMIN__/"$NEW_PASSLNADMIN1"/g *
sed -i s/__IP1__/"$IP1"/g *
sed -i s/__IP2__/"$IP2"/g *
sed -i s/__IP3__/"$IP3"/g *
sed -i s/__IP4__/"$IP4"/g *

## Nou passwd de l'usuari lnadmin i root
echo "lnadmin:$NEW_PASSLNADMIN1" | chpasswd

## Aplica configuracions
echo -en "Aplicant configuracions...\n\n"

killall update-manager update-notifier 2>&1

## Aplica nova configuració de xarxa
cp -av "$FILES_LINKAT"/50-linkat-net-config.yaml /etc/netplan/ > /dev/null 2>&1
netplan apply

## Repara el fitxer resolv.conf
rm /etc/resolv.conf
ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf

## Aplica ANSIBLE
ansible-playbook "$ANSIBLEPLAY"/hostname.yml
ansible-playbook "$ANSIBLEPLAY"/dns.yml

systemctl restart bind9.service

## Revisa connexió
check_connexio

killall update-manager update-notifier > /dev/null 2>&1
dpkg -s slapd > /dev/null 2>&1
res="$?"
if [ "$res" -eq 0 ]; then
        sudo apt purge slapd ldap-auth-config auth-client-config -y
fi

## Aplicant Playbook LDAP
ansible-playbook "$ANSIBLEPLAY"/ldap.yml

## Aplicant Playbook servidor (webmin, lnadmin, etc)
ansible-playbook "$ANSIBLEPLAY"/server.yml

## Configurant servidor LDAP
cd "$FILES_LINKAT"/
sudo "$FILES_LINKAT"/ldap.sh
check_errors ldap

sudo "$FILES_LINKAT"/ldap-auth.sh
check_errors ldap-auth

## Configuració servidor SAMBA
ansible-playbook "$ANSIBLEPLAY"/smb.yml
sudo "$FILES_LINKAT"/ldap-samba.sh
check_errors ldap-samba
sudo "$FILES_LINKAT"/smbldap-populate.sh
check_errors populate

## Copy Jclic Projects
mv /usr/share/java/JClic/projects /srv/exports/S/jclic
chown -R root:Administradors /srv/exports/S/jclic

## Aplicant Playbook permisos i ACLs unitats
ansible-playbook "$ANSIBLEPLAY"/permisos.yml
ansible-playbook "$ANSIBLEPLAY"/acl.yml

# Flag d'instal·lació
echo servidor > /etc/modalitat_linkat

yad --width=300 --title="Linkat Servidor de centre" --text="\nLa configuració ha estat aplicada.\n\nEl Servidor de centre s'ha de reiniciar per aplicar els canvis.\n\nVoleu reiniciar-lo ara?" \
--image="/usr/share/linkat/linkat-servidor/linkat-servidor-banner.png" \
--button="D'acord" --button="Cancel·la":11
if [ $? -eq 0 ]; then
        sudo shutdown -r now
fi
~         
