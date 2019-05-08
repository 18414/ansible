#!/bin/bash
# Version: 1.0

#Deleting previous ip addresses of instances from ANSIBLE inventory
sed -i '/^[0-9]/d' hosts
sleep 1

### NTP 
sudo ntpdate us.pool.ntp.org

#Launching EC2 instances  
ansible-playbook gym_mgmt_system_setup_nginx.yml

sleep 1


#installing Docker 
ansible-playbook docker_install_centos.yml

# IP of created instance
host_ip=$(grep [0-9] hosts)

sleep 1


#Launching containers 
ansible-playbook docker_launch_nginx_lb_v1.yml  --extra-vars  "hip=$host_ip paswd=ganesha@123" 



