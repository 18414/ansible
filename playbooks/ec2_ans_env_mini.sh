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
  yum install -y wget
  wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat/jenkins.repo
  rpm --import https://pkg.jenkins.io/redhat/jenkins.io.key
  yum install jenkins  java-1.8.0-openjdk-devel -y
  systemctl enable jenkins
  systemctl start jenkins


  ## Git clone

  su - ansible << EOF
  git config --global user.name "Bhushan Mahajan"
  git config --global user.email "bmahajan0@gmail.com"
  git clone https://github.com/18414/ansible.git
  echo "cd /home/ansible/ansible/playbooks" >> ~/.bashrc
  cd /home/ansible/ansible
  git pull https://github.com/18414/ansible.git
EOF
