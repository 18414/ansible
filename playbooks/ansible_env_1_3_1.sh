#!/bin/bash
# Create Ansible Environment
# Version: 1.0
# Author : Bhushan Mahajan
# Date:- 09-JAN-2018
# Updated date: 05-May-2019

################# Function for redline ####################################
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
echo -e "`tput setaf 3`\t\t1) Add user and assign password`tput sgr0`\n"
echo -e "`tput setaf 3`\t\t2) Grant sudo access `tput sgr0`\n"
echo -e "`tput setaf 3`\t\t3) create a key SSH-KEYGEN `tput sgr0`\n"
echo -e "`tput setaf 3`\t\t4) Copy key and give_Perm to File-Dir`tput sgr0`\n"
echo -e "`tput setaf 3`\t\t5) Install Ansible latest version`tput sgr0`\n"
echo -e "`tput setaf 3`\t\t6) Configure Ansible Inventory `tput sgr0`\n"
echo -e "`tput setaf 3`\t\t7) Add remote server to the Ansible control node`tput sgr0`\n"
echo -e "`tput setaf 3`\t\t0) Exit`tput sgr0`\n"
}

#######################  User input #################
user_add()
{

echo -e -n "`tput setaf 2``tput bold`\nAdding the $user_name user `tput sgr0`";sleep 2;echo -n ..;sleep 1;echo -n ...;echo " ";echo " "
useradd $user_name
echo "$user_name" | passwd --stdin $user_name
  cat /etc/passwd | grep "$user_name"
  if [ $? -eq 0 ]; then
    echo -e "`tput setaf 1`User $user_name successfully added `tput sgr0`"
  else
        echo -e "`tput setaf 1`User $user_name has not added please try again`tput sgr0`"
                pause
  fi

}


##################################################################################

grant_access()
{

## Granting sudo access
echo -e -n "`tput setaf 2``tput bold`\nGranting sudo access to $user_name user `tput sgr0`";sleep 2;echo -n ..;sleep 1;echo -n ...;echo " ";echo " "
## NOTE: Put double backslash before the variable and escapae the string in SED 

     sed -i "/^root/a \\$user_name ALL=(ALL) NOPASSWD: ALL" /etc/sudoers > /dev/null
}



###################################################################################
create_key()
{
  echo -e -n "`tput setaf 2``tput bold`\nCreating ssh keys for user $user_name `tput sgr0`";sleep 2;echo -n ..;sleep 1;echo -n ...;echo " ";echo " "
    su - $user_name << EOF
    echo -e "\n"|ssh-keygen -t rsa -N ""    
EOF
}


#################################### Create dir, file & give perm ##################
gv_perm()
{
  echo -e -n "`tput setaf 2``tput bold`\nGrating permission to files/dir $user_name `tput sgr0`";sleep 2;echo -n ..;sleep 1;echo -n ...;echo " ";echo " "

  echo -e "`tput setaf 6`copy and paste the pub key from control node`tput sgr0`"
  read -p "Enter Key: " k

        if [ ! -d /home/$user_name/.ssh/ ]; then
          mkdir -p /home/$user_name/.ssh/
          chmod 700 /home/$user_name/.ssh/
          chown $user_name.$user_name /home/$user_name/.ssh/
         fi
          if [ ! -f /home/$user_name/.ssh/authorized_keys ]; then
            echo "$k" > /home/$user_name/.ssh/authorized_keys
           # touch /home/$user_name/.ssh/authorized_keys
            chmod 600 /home/$user_name/.ssh/authorized_keys
            chown -R $user_name.$user_name /home/$user_name/.ssh/authorized_keys

          fi

            echo "$k" > /home/$user_name/.ssh/authorized_keys
}



ansible_install()
{
  rpm -qa | grep ansible > /dev/null
  if [ $? -eq 0 ]; then

   echo -e "`tput setaf 6`Ansible is installed with version `ansible --version | head -1 | awk -F " " '{print $2}'``tput sgr0`"
   pause
  else
   echo -e -n "`tput setaf 2``tput bold`\nInstalling Ansible $main_var `tput sgr0`";sleep 2;echo -n ..;sleep 1;echo -n ...;echo " ";echo " "

      yum install epel-release -y > /dev/null
      yum install ansible -y  /dev/null
  fi
}


ansible_inv()
{

while true 
do
echo -e "\nWe are configuring Ansible inventory and please provide the details\n" 
read -p "Enter groups: " grp
echo -e "\n"
read -p "Enter hostname: " h

echo -e "[$grp]" >> /etc/ansible/hosts
echo -e "$h\n" >> /etc/ansible/hosts

### case ### 
echo -e "`tput setaf 6`\n## please enter c continue or m main menu ##\n`tput sgr0`"
read -p "Enter Value: " vv
echo -e "\n"
case $vv in
c)ansible_inv;;

m)break;choose_act;;

*)echo "Please enter the valid value\n"
   pause
   ansible_inv
esac
### case end ### 

done
}

remote_srv()
{
 
 echo -e "`tput setaf 2`Please enter the remote Server IP where you want send root public key:`tput sgr0`"

 read -p "Enter remote server IP: " r_server

 #ssh-copy-id -o "StrictHostKeyChecking=no" $r_server
 echo -e "`tput setaf 2`Create the $user_name user on the remote server`tput sgr0`"
 ssh $r_server "useradd $user_name"

 su - $user_name << EOF   
    ssh-copy-id -o "StrictHostKeyChecking=no" $r_server
EOF
pause

}

#######################################################################################
### get username and use as Global variable 
echo -e "`tput setaf 2`Please enter the username:`tput sgr0`"
read -p "Enter Name: " abc
export user_name="$abc"

pause
### CASE LOOP to choose an option

while true
do
choose_act

echo -e  "\n"
read -p "Enter your number: " action
echo -e "\n"

case "$action" in

1)user_add;;

2)grant_access;;

3)create_key;;

4)gv_perm;;

5)ansible_install;;

6)ansible_inv;;

7)remote_srv;;

0)exit;;

*)      echo -e "`tput setaf 1`Invalid input`tput sgr0`"
        echo -e "Enter a value as per Menu.....\n\n"
        echo -e "`tput setaf 2`***************PRESS ENTER TO CONTINUE******************\n`tput sgr0`"
        read abcdef
            choose_act
        clear
esac
done

