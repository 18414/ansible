#!/bin/bash

############ Change default kernel####################################
 echo -e "`tput setaf 3`Setting up default kernel`tput sgr0`"
 export ZPOOL_VDEV_NAME_PATH=YES

 old_ker=`awk -F\' '$1=="menuentry " {print i++ " : " $2}' /etc/grub2.cfg | awk -F ":" 'NR==2{print $1}'`
  
 grub2-editenv list
  
 grub2-set-default $old_ker
  
 cat /etc/grub.conf
  
####################################### Roll back ####################
 echo -e "`tput setaf 1` Roll back......`tput sgr0`"
 
 #grep -v '^#' /etc/grub.conf

 #yum history info 18

 undo_new=`yum history info | grep "ID" | cut -d ":" -f2`
 yum history undo $undo_new

 #grep -v ^# /etc/grub.conf


# REF #https://www.svennd.be/change-default-kernel-boot-centos-7/
################################# END ################################


