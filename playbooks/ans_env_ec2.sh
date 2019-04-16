#!/bin/bash

 #Adding user
 useradd ansible

 #SUDO access
 sed -i "/^root/a \\ansible ALL=(ALL) NOPASSWD: ALL" /etc/sudoers > /dev/null

 #Creating SSH keygen
    su - ansible << EOF
    echo -e "\n"|ssh-keygen -t rsa -N ""
EOF

 #Installing Ansible

  yum install epel-release -y > /dev/null
  yum install ansible -y  /dev/null
  yum install git -y
  #git config --global user.name "Bhushan Mahajan"
  #git config --global user.email "bmahajan0@gmail.com"

  ## Git clone

  su - ansible << EOF
  git config --global user.name "Bhushan Mahajan"
  git config --global user.email "bmahajan0@gmail.com"
  git clone https://github.com/18414/ansible.git
  echo "cd /home/ansible/ansible/playbooks" >> ~/.bashrc
EOF


