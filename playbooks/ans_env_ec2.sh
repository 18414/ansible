#!/bin/bash
 
 #Adding user
 useradd ansible
 
 #SUDO access
 sed -i "/^root/a \\ansible ALL=(ALL) NOPASSWD: ALL" /etc/sudoers > /dev/null

 #Creating SSH keygen 
 echo -e -n "`tput setaf 2``tput bold`\nCreating ssh keys for user $user_name `tput sgr0`";sleep 2;echo -n ..;sleep 1;echo -n ...;echo " ";echo " "
    su - ansible << EOF
    echo -e "\n"|ssh-keygen -t rsa -N ""    
EOF

 #Installing Ansible
 rpm -qa | grep ansible > /dev/null
  if [ $? -eq 0 ]; then

   echo -e "`tput setaf 6`Ansible is installed with version `ansible --version | head -1 | awk -F " " '{print $2}'``tput sgr0`"
   pause
  else
   echo -e -n "`tput setaf 2``tput bold`\nInstalling Ansible $main_var `tput sgr0`";sleep 2;echo -n ..;sleep 1;echo -n ...;echo " ";echo " "

      yum install epel-release -y > /dev/null
      yum install ansible -y  /dev/null
  fi

  ## Git clone
  yum install git -y 
  git config --global user.name "Bhushan Mahajan"
  git config --global user.email "bmahajan0@gmail.com"  

  su - ansible 
    git clone https://github.com/18414/ansible.git
  
    echo " cd /home/ansible/ansible/playbooks" >> ~/.bashrc
  
  
