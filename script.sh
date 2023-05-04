#! /bin/bash

# Confirmando que el script se ha ejecutado con sudo

if [[ $EUID -ne 0 ]]; then
	echo "Necesitas correr este script como usuario root"
	exit
fi
echo "[i] Iniciando proceso de hardening XD"

###############################################################
###############################################################

# Actualizando el sistema

echo "[i] Actualizando el sistema"

yum -y upgrade

cho "[i] Listo "

# 1.1.1.1 	Ensure mounting of cramfs filesystems is disabled

echo "[i] Mounting of cramfs filesystems debe estar desactivado... "

if [ -f "/etc/modprobe.d/CIS.conf" ]; then
    echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
else
    echo "install cramfs /bin/true" > /etc/modprobe.d/CIS.conf
fi

echo "[i] Listo "

# 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled

echo "[i] Mounting of freevxfs filesystems debe estar desactivado... "

echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf

echo "[i] Listo "

# 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled

echo "[i] Mounting of jffs2 filesystems debe estar desactivado... "

echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf

echo "[i] Listo "

# 1.1.1.4 Ensure mounting of hfs filesystems is disabled

echo "[i] Mounting of hfs filesystems debe estar desactivado... "

echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf

echo "[i] Listo "

# 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled

echo "[i] Mounting of hfsplus filesystems debe estar desactivado... "

echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf

echo "[i] Listo"

# 1.1.1.6 Ensure mounting of squashfs filesystems is disabled

echo "[i] Mounting of squashfs filesystems debe estar desactivado... "

echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf

echo "[i] Listo"

# 1.1.1.7 Ensure mounting of udf filesystems is disabled

echo "[i] Mounting of udf filesystems debe estar desactivado... "

echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf

echo "[i] Listo "

# 1.1.1.8 Ensure mounting of FAT filesystems is disabled

echo "[i] Mounting of FAT filesystems debe estar desactivado... "

echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf

echo "[i] Listo "

# 1.1.8 Ensure nodev option set on /var/tmp partition
# 1.1.9 Ensure nosuid option set on /var/tmp partition
# 1.1.10 Ensure noexec option set on /var/tmp partition

echo "[i] nodev debe estar establecido en /var/tmp partition... "
echo "[i] nosuiddebe estar establecido en /var/tmp partition... "
echo "[i] noexec debe estar establecido en /var/tmp partition... "

LINEVARTMP="tmpfs /var/tmp tmpfs nosuid,noexec,nodev 0 0"
grep -F "$LINEVARTMP" /etc/fstab || echo "$LINEVARTMP" | tee -a /etc/fstab > /dev/null

echo "[i] Listo "
echo "[i] Listo "
echo "[i] Listo "

# 1.1.15 Ensure nodev option set on /dev/shm partition
# 1.1.16 Ensure nosuid option set on /dev/shm partition
# 1.1.17 Ensure noexec option set on /dev/shm partition

echo "[i] nodev debe estar establecida en /dev/shm partition... "
echo "[i] nosuid debe estar establecida en /dev/shm partition... "
echo "[i] noexec debe estar establecida en /dev/shm partition... "

LINEDEVSHM="tmpfs /dev/shm tmpfs nosuid,noexec,nodev,relatime,rw 0 0"
grep -F "$LINEDEVSHM" /etc/fstab || echo "$LINEDEVSHM" | tee -a /etc/fstab > /dev/null
mount -o remount,nodev,nosuid,noexec /dev/shm

echo "[i] Listo "
echo "[i] Listo "
echo "[i] Listo "

# 1.1.21 Ensure sticky bit is set on all world-writable directories

echo "[i] Verificando que Sticky bit esta establecido en todos los directorios world-writable... "

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

echo "[i] Listo "

# 1.2.2 Ensure gpgcheck is globally activated

echo "[i] Verificando que gpgcheck esta globalmente activado... "

echo "gpgcheck=1" > /etc/yum.conf

echo "[i] Listo "

# 1.3.1 Ensure AIDE is installed

echo "[i] Verificando que AIDE este instalado... "

yum -y install aide 
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

echo "[i] Listo "

# 1.3.2 Ensure filesystem integrity is regularly checked

echo "[i]  Verificando que la integridad de los archivos del sistema sean regularmente revisados"

LINEAIDECRON="0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check"
AIDECRONFILE=/home/tmp.cron

crontab -l -u root 2>/dev/null

if [ $? -eq 0 ]
then
    crontab -u root -l > $AIDECRONFILE
else
    touch $AIDECRONFILE
fi

grep -qF "$LINEAIDECRON" "$AIDECRONFILE" || echo "$LINEAIDECRON" | tee -a "$AIDECRONFILE" > /dev/null

crontab -u root $AIDECRONFILE

rm $AIDECRONFILE

echo "[i] Listo "

# 1.4.3 Ensure authentication required for single user mode

echo "[i] Verificando que es requerida la autentificacion para el modo de un solo usuario "

if grep -q "ExecStart=" /usr/lib/systemd/system/rescue.service; then 
	sed -i 's/^ExecStart=.*/ExecStart=-\/bin\/sh -c "\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default"/' /usr/lib/systemd/system/rescue.service
else
    echo "ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" >> /usr/lib/systemd/system/rescue.service
fi


if grep -q "ExecStart=" /usr/lib/systemd/system/emergency.service; then 
	sed -i 's/^ExecStart=.*/ExecStart=-\/bin\/sh -c "\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default"/' /usr/lib/systemd/system/emergency.service
else
    echo "ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" >> /usr/lib/systemd/system/emergency.service
fi

echo "[i] Listo "

# 1.5.1 Ensure core dumps are restricted

echo "[i] Verificando que los core dumps estan restringidos "

DUMPLINE="* hard core 0"
DUMPFILE=/etc/security/limits.conf

grep -qF "$DUMPLINE" "$DUMPFILE" || echo "$DUMPLINE" | tee -a "$DUMPFILE" > /dev/null

DUMPABLELINE="fs.suid_dumpable=0"
DUMPABLEFILE=/etc/sysctl.conf

grep -qF "$DUMPABLELINE" "$DUMPABLEFILE" || echo "$DUMPABLELINE" | tee -a "$DUMPABLEFILE" > /dev/null

sysctl -w fs.suid_dumpable=0

echo "[i] Listo "

# 1.5.3 Ensure address space layout randomization (ASLR) is enabled

echo "[i] Verificando que ASLR esta habilitado "

if grep -q "^kernel.randomize_va_space" /etc/sysctl.conf; then 
	sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/' /etc/sysctl.conf
else
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
fi

sysctl -w kernel.randomize_va_space=2

echo "[i] Listo "

#####################################################################
#####################################################################
# 1.5.4 Ensure prelink is disabled ##################################
# prelink -ua #######################################################
# yum -y remove prelink #############################################
#####################################################################
#####################################################################
# PreLink no esta instalado en Fedora 


# 1.7.1.1 Ensure message of the day is configured properly

echo "[i] Verificando que el mensaje del dia este configurado apropiadamente"

echo "Unauthorised use of this system is an offence under the Computer Misuse Act 1990. All activity may be monitored and reported." > /etc/motd

echo "[i] Listo "

# 1.7.1.2 Ensure local login warning banner is configured properly

echo "[i] Verificando que el banner de advertencia para inicio local esta configurado apropiadamente"

echo "Unauthorised use of this system is an offence under the Computer Misuse Act 1990. All activity may be monitored and reported." > /etc/issue

echo "[i] Listo "

# 1.7.1.3 Ensure remote login warning banner is configured properly

echo "[i] Verificando que el el banner de advertencia para el inicio remoto esta configurado apropiadamente"

echo "Unauthorised use of this system is an offence under the Computer Misuse Act 1990. All activity may be monitored and reported." > /etc/issue.net

echo "[i] Listo "

# 1.7.1.4 Ensure permissions on /etc/motd are configured

echo "[i] Verificando que los permisos en /etc/motd estan configurados "

chown root:root /etc/motd
chmod 644 /etc/motd

echo "[i] Listo "

# 1.7.1.5 Ensure permissions on /etc/issue are configured

echo "[i] Verificando que los permisos en /etc/issue estan configurados "

chown root:root /etc/issue
chmod 644 /etc/issue

echo "[i] Listo "

# 1.7.1.6 Ensure permissions on /etc/issue.net are configured

echo "[i] Verificando que los permisos en /etc/issue.net estan configurados"

chown root:root /etc/issue.net
chmod 644 /etc/issue.net

echo "[i] Listo "

#######################################################################################
# 1.8.1 Ensure updates, patches, and additional security software are installed #######
# 2.1.1 Ensure chargen services are not enabled #######################################
# chkconfig chargen-dgram off #########################################################
# chkconfig chargen-stream off ########################################################
# 2.1.2 Ensure daytime services are not enabled #######################################
# chkconfig daytime-dgram off #########################################################
# chkconfig daytime-stream off ########################################################
# 2.1.3 Ensure discard services are not enabled #######################################
# chkconfig discard-dgram off #########################################################
# chkconfig discard-stream off ########################################################
# 2.1.4 Ensure echo services are not enabled ##########################################
# chkconfig echo-dgram off ############################################################
# chkconfig echo-stream off ###########################################################
# 2.1.5 Ensure time services are not enabled ########################################## 
# chkconfig time-dgram off ############################################################
# chkconfig time-stream off ###########################################################
# 2.1.6 Ensure tftp server is not enabled #############################################
# chkconfig tftp off ##################################################################
# 2.1.7 Ensure xinetd is not enabled ##################################################
# systemctl disable xinetd ############################################################
#######################################################################################
# Ninguno de estos son necesarios por ahora ya que Fedora no viene con "Inetd Services" instalado


# 2.2.1.2 Ensure ntp is configured

echo "[i] Verificando que ntp esta configurado "

yum -y install ntp
echo "restrict -4 default kod nomodify notrap nopeer noquery" > /etc/ntp.conf
echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf

echo "[i] Listo "

# 2.2.1.3 Ensure chrony is configured 

echo "[i] Verificando que chrony esta configurado "

sed -i 's/^pool.*/#/' /etc/chrony.conf

echo "[i] Listo "

# 2.2.3 Ensure Avahi Server is not enabled

echo "[i] Verificando que avahi server no esta habilitado "

systemctl disable avahi-daemon

echo "[i] Listo "

############################################################
# 2.2.5 Ensure DHCP Server is not enabled ##################
# systemctl disable isc-dhcp-server ########################
# systemctl disable isc-dhcp-server6 #######################
# LDAP isn't installed in Fedora by default ################
# 2.2.6 Ensure LDAP server is not enabled ##################
# systemctl disable slapd ##################################
############################################################
# "DHCP Server" No viene instalado por defecto en Fedora


# 2.2.7 Ensure NFS and RPC are not enabled 

echo "[i] Verificando que NFS y RPC no estan habilitados "

systemctl disable nfs-server
systemctl disable rpcbind

echo "[i] Listo "

#################################################
# 2.2.8 Ensure DNS Server is not enabled ########
# systemctl disable bind9 #######################
#################################################
# "DNS Server" No viene instalado por defecto en Fedora

#################################################
# 2.2.9 Ensure FTP Server is not enabled ########
# systemctl disable vsftpd ######################
#################################################
# "FTP Server" No viene instalado por defecto en Fedora

#################################################
# 2.2.10 Ensure HTTP Server is not enabled ######
# systemctl disable apache2 #####################
#################################################
# "HTTP Server" No viene instalado por defecto en Fedora

######################################################
# 2.2.11 Ensure IMAP and POP3 server is not enabled ##
# systemctl disable dovecot ##########################
######################################################
# "IMAP and POP3 server" No viene instalado por defecto en Fedora

#################################################
# 2.2.12 Ensure Samba is not enabled ############
# # systemctl disable smbd ######################
#################################################
# "Samba" No viene instalado por defecto en Fedora

###################################################
# 2.2.13 Ensure HTTP Proxy Server is not enabled ##
# systemctl disable squid #########################
###################################################
# "HTTP Proxy Server" No viene instalado por defecto en Fedora

###################################################
# 2.2.14 Ensure SNMP Server is not enabled ##
# systemctl disable snmpd #########################
###################################################
# "Ensure SNMP Server" No viene instalado por defecto en Fedora

#########################################################################################
# 2.2.15 Ensure mail transfer agent is configured for local-only mode ###################
# if grep -q "^inet_interfaces = " /etc/postfix/main.cf; then ###########################
# 	sed -i 's/^inet_interfaces.*/inet_interface = loopback-only/' /etc/postfix/main.cf ##
# else ##################################################################################
#     echo "inet_interfaces = loopback-only" >> /etc/postfix/main.cf ####################
# fi ####################################################################################
# systemctl restart postfix #############################################################
#########################################################################################
# "postfix" No viene instalado por defecto en Fedora

###################################################
# 2.2.16 Ensure rsync service is not enabled ######
# systemctl disable rsync #########################
###################################################
# "Rsync service" No viene instalado por defecto en Fedora

###################################################
# 2.2.17 Ensure NIS Server is not enabled ######
# systemctl disable nis #########################
###################################################
# "NIS Server" No viene instalado por defecto en Fedora

# 2.3.1 Ensure NIS Client is not installed

echo "[i] Verificando que el cliente NIS no este instalado "

yum remove -y nis

echo "[i] Listo "

# 2.3.2 Ensure rsh client is not installed

echo "[i] Verificando que el cliente RSH no este instalado "

yum remove -y rsh-client rsh-redone-client

echo "[i] Listo "

# 2.3.3 Ensure talk client is not installed

echo "[i] Verificando que el cliente TALK no este instalado "

yum remove -y talk

echo "[i] Listo "

# 2.3.4 Ensure telnet client is not installed 

echo "[i] Verificando que el cliente TELNET no este instalado "

yum remove -y telnet

echo "[i] Listo "

# 2.3.5 Ensure LDAP client is not installed 

echo "[i] Verificando que el cliente LDAP no este instalado "

yum remove -y ldap-utils

echo "[i] Listo "

# 3.2.1 Ensure source routed packets are not accepted

echo "[i] Verificando que los paquetes enrutados no son aceptados "

if grep -q "^net.ipv4.conf.all.accept_source_route" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.conf.all.accept_source_route.*/net.ipv4.conf.all.accept_source_route = 0/' /etc/sysctl.conf
else
    echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
fi


if grep -q "^net.ipv4.conf.default.accept_source_route" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.conf.default.accept_source_route.*/net.ipv4.conf.default.accept_source_route = 0/' /etc/sysctl.conf
else
    echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
fi

sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1

echo "[i] Listo "

# 3.2.2 Ensure ICMP redirects are not accepted

echo "[i] Verificando que la redireccion ICMP no sea aceptada "

if grep -q "^net.ipv4.conf.all.accept_redirects" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.conf.all.accept_redirects.*/net.ipv4.conf.all.accept_redirects = 0/' /etc/sysctl.conf
else
    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
fi


if grep -q "^net.ipv4.conf.default.accept_redirects" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.conf.default.accept_redirects.*/net.ipv4.conf.default.accept_redirects = 0/' /etc/sysctl.conf
else
    echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
fi

sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1

echo "[i] Listo "

# 3.2.3 Ensure secure ICMP redirects are not accepted

echo "[i] Verificando que la redireccion secure ICMP no esta siendo aceptada "

if grep -q "^net.ipv4.conf.all.secure_redirects" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.conf.all.secure_redirects.*/net.ipv4.conf.all.secure_redirects = 0/' /etc/sysctl.conf
else
    echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
fi


if grep -q "^net.ipv4.conf.default.secure_redirects" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.conf.default.secure_redirects.*/net.ipv4.conf.default.secure_redirects = 0/' /etc/sysctl.conf
else
    echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
fi

sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1

echo "[i] Listo "

# 3.2.4 Ensure suspicious packets are logged 

echo "[i] Verificando que los paquetes sospechosos no son cargados "

if grep -q "^net.ipv4.conf.all.log_martians" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.conf.all.log_martians.*/net.ipv4.conf.all.log_martians = 1/' /etc/sysctl.conf
else
    echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
fi


if grep -q "^net.ipv4.conf.default.log_martians" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.conf.default.log_martians.*/net.ipv4.conf.default.log_martians = 1/' /etc/sysctl.conf
else
    echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
fi


sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

echo "[i] Listo "

# 3.2.5 Ensure broadcast ICMP requests are ignored

echo "[i] Verificando que los requerimientos del broadcast ICMP sean ignorados "

if grep -q "^net.ipv4.icmp_echo_ignore_broadcasts" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.icmp_echo_ignore_broadcasts.*/net.ipv4.icmp_echo_ignore_broadcasts = 1/' /etc/sysctl.conf
else
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
fi

sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1

echo "[i] Listo "

# 3.2.6 Ensure bogus ICMP responses are ignored

echo "[i] Verificando que las respuestas de bogus ICMP sean ignoradas "

if grep -q "^net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.icmp_ignore_bogus_error_responses.*/net.ipv4.icmp_ignore_bogus_error_responses = 1/' /etc/sysctl.conf
else
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
fi


sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1

echo "[i] Listo "

# 3.2.7 Ensure Reverse Path Filtering is enabled

echo "[i] Verificando que el reverse path filtering esta habilitado "

if grep -q "^net.ipv4.conf.all.rp_filter" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.conf.all.rp_filter.*/net.ipv4.conf.all.rp_filter = 1/' /etc/sysctl.conf
else
    echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
fi


if grep -q "^net.ipv4.conf.default.rp_filter" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.conf.default.rp_filter.*/net.ipv4.conf.default.rp_filter = 1/' /etc/sysctl.conf
else
    echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
fi


sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

echo "[i] Listo "

# 3.2.8 Ensure TCP SYN Cookies is enabled

echo "[i] Verificando qie TCP SYN cookies estan habiltadas "

if grep -q "^net.ipv4.tcp_syncookies" /etc/sysctl.conf; then 
	sed -i 's/^net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies = 1/' /etc/sysctl.conf
else
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
fi


sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

echo "[i] Listo "

# 3.4.1 Ensure TCP Wrappers is installed 

echo "[i] Verificando que TCP wrappers esta instalado "

yum install -y tcp_wrappers

echo "[i] Listo "

# 3.4.2 Ensure /etc/hosts.allow is configured 

echo "[i] Verificando que /etc/hosts.allow esta configurado "

echo "ALL: 192.168.0.0/255.255.0.0" > /etc/hosts.allow

echo "[i] Listo "

# 3.4.3 Ensure /etc/hosts.deny is configured 

echo "[i] Verificando que /etc/hosts.deny esta configurado "

echo "ALL: ALL" >> /etc/hosts.deny

echo "[i] Listo "

# 3.4.4 Ensure permissions on /etc/hosts.allow are configured

echo "[i] Verificando que los permisos en /etc/hosts.allow estan configurados "

chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow

echo "[i] Listo "

# 3.4.4 Ensure permissions on /etc/hosts.deny are configured

echo "[i] Verificando que los permisos en /etc/hosts.deny estan configurados "

chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

echo "[i] Listo "

# 3.6.1 Ensure iptables is installed
# 3.6.2 Ensure default deny firewall policy 
# 3.6.3 Ensure loopback traffic is configured 
# 3.6.5 Ensure firewall rules exist for all open ports 

echo "[i] Verificando que iptables esta instalado "
echo "[i] Verificando que la politica de denegacion de firewall esta en default "
echo "[i] Verificando que el trafico loopback esta configurado "
echo "[i] Verificando que existan reglas en el firewall para todos los puertos "

yum install -y iptables
iptables -F
iptables -P INPUT DROP
iptables -P OUTPUT DROP 
iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

echo "[i] Listo "
echo "[i] Listo "
echo "[i] Listo "
echo "[i] Listo "

################################################
# 4.2.3 Ensure rsyslog or syslog-ng is installed
# La instalacion ya se ha encargado ############

# 4.2.4 Ensure permissions on all logfiles are configured 

echo "[i] Verificando que los permisos de todos los logfiles estan configurados "

find /var/log -type f -exec chmod g-wx,o-rwx {} +

echo "[i] Listo "

# 5.1.1 Ensure cron daemon is enabled

echo "[i] Verificando que cron daemon esta habilitado "

systemctl enable cron

echo "[i] Listo "

# 5.1.2 Ensure permissions on /etc/crontab are configured

echo "[i] Verificando que los permisos en /etc/crontab estan configurados "

chown root:root /etc/crontab
chmod og-rwx /etc/crontab

echo "[i] Listo "

# 5.1.3 Ensure permissions on /etc/cron.hourly are configured

echo "[i] Verificando que los permisos en /etc/cron.hourly estan configurados "

chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly

echo "[i] Listo "

# 5.1.4 Ensure permissions on /etc/cron.daily are configured 

echo "[i] Verificando que los permisos en /etc/cron.daily estan configurados "

chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

echo "[i] Listo "

# 5.1.5 Ensure permissions on /etc/cron.weekly are configured

echo "[i] Verificando que los permisos en /etc/cron.weekly estan configurados "

chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

echo "[i] Listo "

# 5.1.6 Ensure permissions on /etc/cron.monthly are configured

echo "[i] Verificando que los permisos en /etc/cron.monthly estan configurados "

chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

echo "[i] Listo "

# 5.1.7 Ensure permissions on /etc/cron.d are configured

echo "[i] Verificando que los permisos en/etc/cron.d estan configurados "

chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

echo "[i] Listo "

# 5.1.8 Ensure at/cron is restricted to authorized users

echo "[i] Verificando  que at/cron es disponible solo para usuarios autorizados "

rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

echo "[i] Listo "

# 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured correctly

echo "[i] Verificando que los permisos en /etc/ssh/sshd_config estan configurados correctamente "

chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

echo "[i] Listo "

# 5.2.2 Ensure SSH Protocol is set to 2

echo "[i] Verificando que el protocolo SSH esta establecido "

if grep -q "^Protocol" /etc/ssh/sshd_config; then 
	sed -i 's/^Protocol.*/Protocol 2/' /etc/ssh/sshd_config
else
    echo "Protocol 2" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# 5.2.3 Ensure SSH LogLevel is set to INFO

echo "[i] Verificando que SSH loglevel esta establecido para INFO "

if grep -q "^LogLevel" /etc/ssh/sshd_config; then 
	sed -i 's/^LogLevel.*/LogLevel INFO/' /etc/ssh/sshd_config
else
    echo "LogLevel INFO" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# 5.2.4 Ensure SSH X11 forwarding is disabled

echo "[i] Verificando SSH X11 forwarding esta desactivado "

if grep -q "^X11Forwarding" /etc/ssh/sshd_config; then 
	sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
else
    echo "X11Forwarding No" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# 5.2.5 Ensure SSH MaxAuthTries is set to 4 or less

echo "[i] Verificando que SSH maxauthtries esta establecudi para 4 o menos "

if grep -q "^MaxAuthTries" /etc/ssh/sshd_config; then 
	sed -i 's/^MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
else
    echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# 5.2.6 Ensure SSH IgnoreRhosts is enabled

echo "[i] Verificando que SSH ignorerhosts esta desactivado "

if grep -q "^IgnoreRhosts" /etc/ssh/sshd_config; then 
	sed -i 's/^IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config
else
    echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# 5.2.7 Ensure SSH HostbasedAuthentication is disabled

echo "[i] Verificando que SSH HostbasedAuthentication este desactivado "

if grep -q "^HostbasedAuthentication" /etc/ssh/sshd_config; then 
	sed -i 's/^HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config
else
    echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# 5.2.8 Ensure SSH root login is disabled

echo "[i] Verificando que el login SSH con root este desactivado "

if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then 
	sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
else
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# Ensure SSH PermitEmptyPasswords is disabled

echo "[i] Verificando que PermitEmptyPasswords este desactivado "

if grep -q "^PermitEmptyPasswords" /etc/ssh/sshd_config; then 
	sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
else
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# 5.2.10 Ensure SSH PermitUserEnvironment is disabled

echo "[i] Verificando que SSH PermitUserEnvironment este desactivado "

if grep -q "^PermitUserEnvironment" /etc/ssh/sshd_config; then 
	sed -i 's/^PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config
else
    echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# 5.2.11 Ensure only approved MAC algorithms are used

echo "[i] Verificando que los algoritmos de only approved MAC esten en uso "

if grep -q "^MACs" /etc/ssh/sshd_config; then 
	sed -i 's/^MACs.*/MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com/' /etc/ssh/sshd_config
else
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# 5.2.12 Ensure SSH Idle Timeout Interval is configured

echo "[i] Verificando que SSH Idle Timeout Interval esta configurado "

if grep -q "^ClientAliveInterval" /etc/ssh/sshd_config; then 
	sed -i 's/^ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
else
    echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
fi


if grep -q "^ClientAliveCountMax" /etc/ssh/sshd_config; then 
	sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
else
    echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# 5.2.13 Ensure SSH LoginGraceTime is set to one minute or less

echo "[i] Verificando que SSH LoginGraceTime este establecifo en un minuto o menos "

if grep -q "^LoginGraceTime" /etc/ssh/sshd_config; then 
	sed -i 's/^LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config
else
    echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# 5.2.15 Ensure SSH warning banner is configured

echo "[i] Verificando que el banner de advertencia SSH esta configurado"

if grep -q "^Banner" /etc/ssh/sshd_config; then 
	sed -i 's/^Banner.*/Banner /etc/issue.net/' /etc/ssh/sshd_config
else
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
fi

echo "[i] Listo "

# 5.3.2 Ensure lockout for failed password attempts is configured 

echo "[i] Verificando que el bloqueo por intentos fallidos de contraseña esta configurado "

if grep -q "pam_tally2.so" /etc/pam.d/common-auth; then 
	sed -i 's/.*pam_tally2.so.*/auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900/' /etc/pam.d/common-auth
else
    echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth
fi

echo "[i] Listo "

# 5.3.3 Ensure password reuse is limited

echo "[i] Verificando que la reutilizacion de contraseñas sea limitada "

if grep -q "pam_pwhistory.so" /etc/pam.d/common-password; then 
	sed -i 's/.*pam_pwhistory.so.*/password required pam_pwhistory.so remember=5/' /etc/pam.d/common-password
else
    echo "password required pam_pwhistory.so remember=5" >> /etc/pam.d/common-password
fi

echo "[i] Listo "

# 5.3.4 Ensure password hashing algorithm is SHA-512

echo "[i] Verificando que password hashing algorithm sea SHA-512 "

if grep -q "pam_unix.so" /etc/pam.d/common-password; then 
	sed -i 's/.*pam_unix.so.*/password [success=1 default=ignore] pam_unix.so sha512/' /etc/pam.d/common-password
else
    echo "password [success=1 default=ignore] pam_unix.so sha512" >> /etc/pam.d/common-password
fi

echo "[i] Listo "

#########################################################################################################
# 5.4.1.1 Ensure password expiration is 365 days or less ################################################
# echo "[i] Setting password expiry at 365 days" ########################################################
# if grep -q "PASS_MAX_DAYS" /etc/login.defs; then ######################################################
# 	sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs ######################################
# else ##################################################################################################
# 	echo "PASS_MAX_DAYS 90" >> /etc/login.defs ##########################################################
# fi ####################################################################################################
# No configurar la caducidad de la contraseña, ya que va en contra de las mejores medidas de seguridad ##

# 5.4.1.2 Ensure minimum days between password changes is 7 or more

echo "[i] Verificando que el mminimo de dias entre cambios de contraseña sea de 7 dias o mas "

if grep -q "PASS_MIN_DAYS" /etc/login.defs; then
	sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
else
	echo "PASS_MIN_DAYS 7" >> /etc/login.defs
fi

echo "[i] Listo "

###################################################################
# 5.4.1.3 Ensure password expiration warning days is 7 or more ####
# echo "[i] Setting password expiration warning to 7 days" ########
# if grep -q "PASS_WARN_AGE" /etc/login.defs; then ################
# 	sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs ##
# else ############################################################
# 	echo "PASS_WARN_AGE 7" >> /etc/login.defs #####################
# fi ##############################################################
# No necesario ya que se omitio el punto previo

# 5.4.1.4 Ensure inactive password lock is 30 days or less

echo "[i] Verificando que contraseñas inactivas sean bloqueadas en menos de 30 dias "

useradd -D -f 30

echo "[i] Listo "

####################################################################################
# 5.4.1.5 Ensure all users last password change date is in the past ################
# This is a manual task.  Run the following commands and confirm for each user: ####
# cat/etc/shadow | cut -d: -f1 #####################################################
# <list of users> ##################################################################
# chage --list <user> ##############################################################
# Last Change			: <date> ###################################################
# No necesario ya que no hay contraseñas expirables


# 5.4.2 Ensure system accounts are non-login
# This is a manual task.
# Run the following audit task to identify users which have interactive login privs which shouldn't:
# egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}'
# for user in `awk -F: '($1!="root" && $3 < 1000) {print $1 }' /etc/passwd`; do passwd -S $user | awk -F ' ' '($2!="L") {print $1}'; done
# To remediate, set the shell for all necessary accounts identified by the audit script to /usr/sbin/nologin by running the following command:
# usermod -s /usr/sbin/nologin <user>
# passwd -l <user>
# No necesario ya que no hay cuentas no defaults en esta maquina

# 5.4.3 Ensure default group for the root account is GID 0

echo "[i] Verificando que el grupo default para la cuenta root sea GID 0 "

usermod -g 0 root

echo "[i] Listo "

# 5.4.4 Ensure default user umask is 027 or more restrictive

echo "[i] Verificando que la umask de usuario sea 027 o mas restrictiva "

umask 027

echo "[i] Listo "

# 5.6 Ensure access to the su command is restricted

echo "[i] Verificando que el acceso a el comando su sea restringido "

if grep -q "pam_wheel.so" /etc/pam.d/su; then
	sed -i 's/.*pam_wheel.so.*/auth required pam_wheel.so/' /etc/pam.d/su
else
	echo "auth required pam_wheel.so" >> /etc/pam.d/su
fi

echo "[i] Listo "

# 6.1.2 Ensure permissions on /etc/passwd are configured

echo "[i] Verificando que los permisos para /etc/passwd estan configurados "

chown root:root /etc/passwd
chmod 644 /etc/passwd

echo "[i] Listo "

# 6.1.3 Ensure permissions on /etc/shadow are configured 

echo "[i] Verificando que los permisos para /etc/shadow estan configurados "

chown root:root /etc/shadow
chmod 000 /etc/shadow

echo "[i] Listo "

# 6.1.4 Ensure permissions on /etc/group are configured

echo "[i] Verificando que los permisos para /etc/group estan configurados "

chown root:root /etc/group
chmod 644 /etc/group

echo "[i] Listo "

# 6.1.5 Ensure permissions on /etc/gshadow are configured 

echo "[i] Verificando que los permisos para /etc/gshadow estan configurados "

chown root:root /etc/gshadow
chmod 000 /etc/gshadow

echo "[i] Listo "

# 6.1.6 Ensure permission on /etc/passwd- are configured 

echo "[i] Verificando que los permisos para /etc/passwd- estan configurados"

chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-

echo "[i] Listo "

# 6.1.7 Ensure permissions on /etc/shadow- are configured 

echo "[i] Verificando que los permisos para /etc/shadow- estan configurados "

chown root:root /etc/shadow-
chmod 000 /etc/shadow-

echo "[i] Listo "

# 6.1.8 Ensure permissions on /etc/group- are configured

echo "[i] Verificando que los permisos para /etc/group- estan configurados "

chown root:root /etc/group-
chmod u-x,go-wx /etc/group-

echo "[i] Listo "

# 6.1.9 Ensure permissions on /etc/gshadow- are configured

echo "[i] Verificando que los permisos para /etc/gshadow- estan configurados "

chown root:root /etc/gshadow-
chmod 000 /etc/gshadow-

echo "[i] Listo "

#########################################################################################################################################

# 6.1.10 Ensure no world writable files 
# 6.1.11 Ensure no unowned files or directories exist
# 6.1.12 Ensure no ungrouped files or directories exist 
# 6.2.1 Ensure password fields are not empty
# 6.2.2 Ensure no legacy "+" entries exist in /etc/passwd
# 6.2.3 Ensure no legacy "+" entries exist in /etc/shadow
# 6.2.4 Ensure no legacy "+" entries exist in /etc/group
# 6.2.5 Ensure root is the only UID 0 account
# 6.2.6 Ensure root PATH integrity
# 6.2.7 Ensure all users' home directories exist
# 6.2.8 Ensure all users' home directories permissions are 750 or more restrictive
# 6.2.9 Ensure users own their home directories
# 6.2.10 Ensure users' dot files are not group or world writable
# 6.2.11 Ensure no users have .forward files
# 6.2.12 Ensure no users have .netrc files
# 6.2.13 Ensure users' .netrc Files are not group or world accessible
# 6.2.14 Ensure no users have .rhosts files
# 6.2.15 Ensure all groups in /etc/passwd exist in /etc/group
# 6.2.16 Ensure no duplicate UIDs exist
# 6.2.17 Ensure no duplicate GIDs exist
# 6.2.18 Ensure no duplicate user names exist
# 6.2.19 Ensure no duplicate group names exist

# Las anteriores son todas las tareas de auditoría que no es necesario realizar durante la configuración inicial 
# (porque ninguna de ellas está allí de forma predeterminada)

#########################################################################################################################################

echo "[i] El procedimiento de Hardening finalizado"
