#!/bin/bash

## Changing Directory Colors ##
sed -i 's/DIR 00;34/DIR 01;34/g' /etc/DIR_COLORS.xterm
## Creating required directories ##
mkdir -p /root/Backup/
# Defining Functions
## Function for red line ##


reddline()
{
echo -e " \033[1m\033[31m=============================================================================\033[0m";tput sgr0
}

################# Function for script pause ################################
pause()
{
echo -e "\n\t\t\e[92m \e[5m"
read -p "### Press ENTER to go back to menu ###" ;tput sgr0
clear
}



################### Function for Action MENU ###############################
choose_act()
{
echo -e "`tput setaf 6``tput bold`\n\t\t### Please enter your choice ###`tput sgr0`\n"
echo -e "`tput setaf 3`\t\t1) Restric partitions`tput sgr0`\n"
echo -e "`tput setaf 3`\t\t2) Grant sudo access `tput sgr0`\n"
echo -e "`tput setaf 3`\t\t3) create a key SSH-KEYGEN `tput sgr0`\n"
echo -e "`tput setaf 3`\t\t4) Copy key and give_Perm to File-Dir`tput sgr0`\n"
echo -e "`tput setaf 3`\t\t5) Install Ansible latest version`tput sgr0`\n"
echo -e "`tput setaf 3`\t\t6) Install and configure git `tput sgr0`\n"
echo -e "`tput setaf 3`\t\t7) Configure Ansible Inventory`tput sgr0`\n"
echo -e "`tput setaf 3`\t\t8) Add Remote server`tput sgr0`\n"
echo -e "`tput setaf 3`\t\t9) Install Jenkins`tput sgr0`\n"
echo -e "`tput setaf 3`\t\t0) Exit`tput sgr0`\n"
}

restrict_part()
{
echo -e "`tput setaf 3`1.0 - Restrict Partition Mount Options`tput sgr0`"

#2. System Settings – File Permissions and Masks
#2.1 Restrict Partition Mount Options

#The storage location /var/tmp should be bind mounted to /tmp, as having multiple locations for temporary storage is not required:

echo "/tmp /var/tmp none rw,nodev,noexec,nosuid,bind 0 0" >> /etc/fstab


#The same applies to shared memory /dev/shm:

echo "tmpfs /dev/shm tmpfs rw,nodev,noexec,nosuid 0 0" >> /etc/fstab
}
#######################################################################

#2.2 Restrict Dynamic Mounting and Unmounting of Filesystems
#Add the following to /etc/modprobe.d/hardening.conf to disable uncommon filesystems:
restrict_dyn_mount()
{
echo "install cramfs /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install freevxfs /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install jffs2 /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install hfs /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install hfsplus /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install squashfs /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install udf /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install fat /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install vfat /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install cifs /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install nfs /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install nfsv3 /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install nfsv4 /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install gfs2 /bin/true" >> /etc/modprobe.d/hardening.conf
sleep 1
clear
}
##############################################################################

#2.3 Prevent Users Mounting USB Storage
#Add the following to /etc/modprobe.d/hardening.conf to disable modprobe loading of USB and FireWire storage drivers:

disable_usb()
{
echo "blacklist usb-storage" >> /etc/modprobe.d/hardening.conf
echo "blacklist firewire-core" >> /etc/modprobe.d/hardening.conf
echo "install usb-storage /bin/true" >> /etc/modprobe.d/hardening.conf
sleep 1
clear
}

#####################################################################################
umsk()
{

#2.5 Set UMASK 027
#The following files require umask hardening: /etc/bashrc, /etc/csh.cshrc, /etc/init.d/functions and /etc/profile.

 sed -i -e 's/umask 022/umask 027/g' -e 's/umask 002/umask 027/g' /etc/bashrc
 sed -i -e 's/umask 022/umask 027/g' -e 's/umask 002/umask 027/g' /etc/csh.cshrc
 sed -i -e 's/umask 022/umask 027/g' -e 's/umask 002/umask 027/g' /etc/profile
 sed -i -e 's/umask 022/umask 027/g' -e 's/umask 002/umask 027/g' /etc/init.d/functions

}
##################################################################################################
dis_core_dmp()
{
#2.6 Disable Core Dumps
#Open /etc/security/limits.conf and set the following:

echo "*  hard  core  0" >>> /etc/security/limits.conf
}

##########################################################################################
sec_limit_prevent_dos()
{
#2.7 Set Security Limits to Prevent DoS
#Add the following to /etc/security/limits.conf to enforce sensible security limits:

# 4096 is a good starting point
*      soft   nofile    4096
*      hard   nofile    65536
*      soft   nproc     4096
*      hard   nproc     4096
*      soft   locks     4096
*      hard   locks     4096
*      soft   stack     10240
*      hard   stack     32768
*      soft   memlock   64
*      hard   memlock   64
*      hard   maxlogins 10

# Soft limit 32GB, hard 64GB
*      soft   fsize     33554432
*      hard   fsize     67108864

# Limits for root
root   soft   nofile    4096
root   hard   nofile    65536
root   soft   nproc     4096
root   hard   nproc     4096
root   soft   stack     10240
root   hard   stack     32768
root   soft   fsize     33554432
}

##############################################################################################
mon_all_files_perm()
{
#2.8 Verify Permissions of Files
echo -e "`setaf 3`Ensure that all files are owned by a user`set sgr0`"
find / -ignore_readdir_race -nouser -print -exec chown root {} \;
sleep 2
clear

echo -e "`setaf 3`Ensure that all files are owned by a group`set sgr0`"
find / -ignore_readdir_race -nogroup -print -exec chgrp root {} \;
sleep 2 
clear

echo -e "`setaf 3`#If required, a specific path can be excluded from the search`set sgr0`"
find / -ignore_readdir_race -not -path "/proc/*" -nouser -print -exec chown root {} \;
sleep 2
clear

echo -e "`setaf 3`Automate the process by creating a cron file /etc/cron.daily/unowned_files with the following content`set sgr0`"
find / -ignore_readdir_race \( -nouser -print -exec chown root {} \; \) , \( -nogroup -print -exec chgrp root {} \; \)
sleep 2
clear

echo -e "`setaf 3`Set ownership and permissions`set sgr0`"
 chown root:root /etc/cron.daily/unowned_files
 chmod 0700 /etc/cron.daily/unowned_files
}

##########################################################################################
special_perm()
{
echo -e "`setaf 2`2.9 Monitor SUID/GUID Files`set sgr0`"
#Search for setuid/setgid files and identify if all are required:
find / -xdev -type f -perm -4000 -o -perm -2000
sleep 2
clear
}


###################################################################################
ker_parm()
{
echo -e "`tput setaf 3`3.3 Kernel Parameters Which Affect Networking`set sgr0`"
#Open /etc/sysctl.conf and add the following:

# Disable packet forwarding
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf

# Disable redirects, not a router
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf

# Disable source routing
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf

# Enable source validation by reversed path
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf

# Log packets with impossible addresses to kernel log
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf

# Disable ICMP broadcasts
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf

# Ignore bogus ICMP errors
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf

# Against SYN flood attacks
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

# Turning off timestamps could improve security but degrade performance.
# TCP timestamps are used to improve performance as well as protect against
# late packets messing up your data flow. A side effect of this feature is 
# that the uptime of the host can sometimes be computed.
# If you disable TCP timestamps, you should expect worse performance 
# and less reliable connections.
echo "net.ipv4.tcp_timestamps = 1" >> /etc/sysctl.conf

# Disable IPv6 unless required
echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf

# Do not accept router advertisements
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
}
################################################################################
dis_ker_mod()
{
echo -e "`tput setaf 3`3.4 Disable kernel modules which Affect Networking`tput sgr0`"
#Open /etc/modprobe.d/hardening.conf and disable Bluetooth kernel modules:
echo "install bnep /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install bluetooth /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install btusb /bin/true" >> /etc/modprobe.d/hardening.conf
echo "install net-pf-31 /bin/true" >> /etc/modprobe.d/hardening.conf
}


##########################################################
dis_wireless()
{
#Since we’re looking at server security, wireless shouldn’t be an issue, therefore we can disable all the wireless drivers.
echo -e "`tput setaf`Disable all wireless drivers`tput sgr0`"

 for i in $(find /lib/modules/$(uname -r)/kernel/drivers/net/wireless -name "*.ko" -type f);do \
  echo blacklist "$i" >>/etc/modprobe.d/hardening-wireless.conf;done

sleep 2
clear
}
  
#################################################################

selinx()
{
#4. System Settings – SELinux
echo -e "`tput setaf 3`Ensure that SELinux is not disabled in /etc/default/grub, and verify that the state is enforcing`tput sgr0`"

 if [ $(sestatus | awk -F  ":" '{print $2}') !=  enforcing ]; then

    sed 's/SELINUX=disabled/SELINUX=enforcing/g' /etc/sysconfig/selinux
        
 fi 

 sleep 2 
 clear
 
}

######################################################################

#5. System Settings – Account and Access Control
#5.1 Delete Unused Accounts and Groups
usr_del()
{
echo -e "`tput setaf 3`Remove any account which is not required, e.g`tput sgr0`"

 for i in "adm" "ftp" "games" "lp";do userdel -r $i;done;

 echo -e "`tput setaf 3`Remove game group which is not required, e.g`tput sgr0`"
  groupdel games

sleep 2
clear
}

#################################
dis_root_console()
{
#5.2 Disable Direct root Login from console

echo "root" > /etc/securetty
sleep 2
clear
}

################

paswd_policy()
{

echo -e "`tput setaf 3` Enable Secure (high quality) Password Policy and enable SHA512`tput sgr0`"

#Note that running authconfig will overwrite the PAM configuration files destroying any manually made changes. Make sure that you have a backup.
#Secure password policy rules are outlined below.

 authconfig --passalgo=sha512 \
 --passminlen=8 \
 --passminclass=4 \
 --passmaxrepeat=2 \
 --passmaxclassrepeat=2 \
 --enablereqlower \
 --enablerequpper \
 --enablereqdigit \
 --enablereqother \
 --update

 sleep 2
 clear
 
echo -e "`tput setaf 3`These will ensure that 8 characters in the new password must not be present in the old password, and will check for the words from the passwd entry GECOS string of the user`tput sgr0`"
#Open /etc/security/pwquality.conf and add the following:
echo  "difok = 8" >> /etc/security/pwquality.conf
echo "gecoscheck = 1" >> /etc/security/pwquality.conf
sleep 2 
clear

################################

echo -e "`tput setaf 3` Prevent Log In to Accounts With Empty Password`tput sgr0`"
#Remove any instances of nullok from /etc/pam.d/system-auth and /etc/pam.d/password-auth to prevent logins with empty passwords.
 sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth /etc/pam.d/system-auth-ac
 sed -i 's/\<nullok\>//g' /etc/pam.d/password-auth /etc/pam.d/password-auth-ac
sleep 2
clear
 
###############################
#5.5 Set Account Expiration Following Inactivity
#Disable accounts as soon as the password has expired.
#Open /etc/default/useradd and set the following:
#INACTIVE=0
sed -i 's/^INACTIVE.*/INACTIVE=0/' /etc/default/useradd


#####################################################################
#5.6 Secure Pasword Policy
#Open /etc/login.defs and set the following:

sed -i -e 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' \
  -e 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' \
  -e 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 14/' \
  -e 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs

#############################################################
#5.7 Log Failed Login Attemps
#Open /etc/login.defs and enable logging:
#Also add a delay in seconds before being allowed another attempt after a login failure:
echo "FAILLOG_ENAB yes" >> /etc/login.defs
echo "FAIL_DELAY 4" >> /etc/login.defs


##############################################################
#5.8 Ensure Home Directories are Created for New Users
#Open /etc/login.defs and configure:
echo "CREATE_HOME yes" /etc/login.defs



#####################################################
echo -e "`tput setaf 3`#5.9 Verify All Account Password Hashes are Shadowed`tput sgr0`"
#The command below should return “x”:
cut -d: -f2 /etc/passwd|uniq

}

pam_set()
{
###################################################
echo -e "`tput setaf 3`Set Deny and Lockout Time for Failed Password Attempts`tput sgr 0`"
sleep 2
#echo -e "tput setaf 3Set Deny and Lockout Time for Failed Password Attempts`tput sgr0`"
#Add the following line immediately before the pam_unix.so statement in the AUTH section of /etc/pam.d/system-auth and /etc/pam.d/password-auth:
echo "auth    required    pam_faillock.so    preauth    silent deny=3    unlock_time=900    fail_interval=900" >> /etc/pam.d/system-auth


#Add the following line immediately after the pam_unix.so statement in the AUTH section of /etc/pam.d/system-auth and /etc/pam.d/password-auth:
echo "auth  [default=die]    pam_faillock.so    authfail    deny=3    unlock_time=900    fail_interval=900" >> /etc/pam.d/system-auth

#Add the following line immediately before the pam_unix.so statement in the ACCOUNT section of /etc/pam.d/system-auth and /etc/pam.d/password-auth:
echo "account        required      pam_faillock.so" >> /etc/pam.d/system-auth

#Allow users to reuse recent passwords by adding the remember option
echo  "password      sufficient    pam_unix.so sha512      shadow      try_first_pass use_authtok     remember=5" >> 

chattr +i /etc/pam.d/system-auth /etc/pam.d/password-auth
}

boot_loader()
{
####################################################################################################
echo -e "`tput setaf 3`Set Boot Loader Password`tput sgr0`"
#Prevent users from entering the grub command line and edit menu entries:
grub2-setpassword
grub2-mkconfig -o /boot/grub2/grub.cfg

#This will create the file /boot/grub2/user.cfg if one is not already present, which will contain the hashed Grub2 bootloader password.
#Verify permissions of /boot/grub2/grub.cfg:
chmod 0600 /boot/grub2/grub.cfg
 
########################################
#5.12 Password-protect Single User Mode
#CentOS 7 single user mode is password protected by the root password by default as part of the design of Grub2 and systemd.

###################################################
#5.15 Disable Ctrl-Alt-Del Reboot Activation
#Prevent a locally logged-in console user from rebooting the system when Ctrl-Alt-Del is pressed:
systemctl mask ctrl-alt-del.target

##########################################
#5.16 Warning Banners for System Access
#Add the following line to the files /etc/issue and /etc/issue.net:

echo  "Unauthorised access prohibited. Logs are recorded and monitored" >> /etc/issue 
echo  "Unauthorised access prohibited. Logs are recorded and monitored" >> /etc/issue.net

##########################################
#5.17 Set Interactive Session Timeout
#Open /etc/profile and set:
readonly TMOUT=900

#########################################

#5.19 Configure History File Size
#Open /etc/profile and set the number of commands to remember in the command history to 5000:

sed -i 's/HISTSIZE=.*/HISTSIZE=5000/g' /etc/profile

}


#############################################
echo -e "`tput setaf 7``tput bold`Services – SSH Server hardening`tput sgr0`"

#Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

#MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

#HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com

#KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256

# INFO is a basic logging level that will capture user login/logout activity.
# DEBUG logging level is not recommended for production servers.
#echo -e "LogLevel INFO"

# Disconnect if no successful login is made in 60 seconds.
#LoginGraceTime 60

echo -e "`tput setaf 3`Do not permit root logins via SSH`tput sgr0`"

sed 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config


# Check file modes and ownership of the user's files before login.
StrictModes yes

# Close TCP socket after 2 invalid login attempts.
MaxAuthTries 2

# The maximum number of sessions per network connection.
MaxSessions 3

# User/group permissions.
#AllowUsers
#AllowGroups ssh-users
#DenyUsers root
#DenyGroups root

# Password and public key authentications.
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile  .ssh/authorized_keys

# Disable unused authentications mechanisms.
RSAAuthentication no # DEPRECATED
RhostsRSAAuthentication no # DEPRECATED
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreUserKnownHosts yes

# Disable insecure access via rhosts files.
IgnoreRhosts yes

AllowAgentForwarding no
AllowTcpForwarding no

# Disable X Forwarding.
X11Forwarding no

# Disable message of the day but print last log.
PrintMotd no
PrintLastLog yes

# Show banner.
Banner /etc/issue

# Do not send TCP keepalive messages.
TCPKeepAlive no

# Default for new installations.
UsePrivilegeSeparation sandbox

# Prevent users from potentially bypassing some access restrictions.
PermitUserEnvironment no

# Disable compression.
Compression no

# Disconnect the client if no activity has been detected for 900 seconds.
ClientAliveInterval 900
ClientAliveCountMax 0


# systemctl enable chronyd.service
#3. Services – Mail Server
#3.1 Postfix
#Postfix should be installed and enabled already. In case it isn’t, the do the following:
 yum install postfix
 systemctl enable postfix.service
 

# yum install cyrus-sasl-plain
#Open /etc/postfix/main.cf and add the following:
#Set permissions and create a database file:
 chmod 0600 /etc/postfix/sasl_passwd
 postmap /etc/postfix/sasl_passwd
#Restart the service and ensure that firewall allows outgoing traffic to the SMTP relay server.


#4. Services – Remove Obsolete Services
#None of these should be installed on CentOS 7 minimal:

 yum remove xinetd telnet-server rsh-server \
  telnet rsh ypbind ypserv tfsp-server bind \
  vsfptd dovecot squid net-snmpd talk-server talk

######  
#Check all enabled services:
 systemctl list-unit-files --type=service|grep enabled


########################
#5. Services – Restrict at and cron to Authorised Users
#If the file cron.allow exists, then only users listed in the file are allowed to use cron, and the cron.deny file is ignored.

 echo root > /etc/cron.allow
 echo root > /etc/at.allow
 rm -f /etc/at.deny /etc/cron.deny
#Note that the root user can always use cron, regardless of the usernames listed in the access control files.

############
#6. Services – Disable X Windows Startup
#This can be achieved by setting a default target:
 systemctl set-default multi-user.target

