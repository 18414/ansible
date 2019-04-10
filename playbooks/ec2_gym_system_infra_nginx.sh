#!/bin/bash
# Version: 1.0

#Deleting previous ip addresses of instances from ANSIBLE inventory
sed -i '/^[0-9]/d' hosts
sleep 1

#Launching EC2 instances  
#ansible-playbook gym_mgmt_system_setup_elb_v2.yml
sleep 1

#Classic load balancer 
ansible-playbook gym_mgmt_system_setup_classic_elb_v3.yml

#installing Docker on Docker1 and Docker2
ansible-playbook docker_install_centos.yml

grep [0-9] hosts > ip_list
host_ip=`grep [0-9] hosts > ip_list`

sleep 1




#Launching containers 
ansible-playbook docker_launch_nginx_lb_v1.yml -extra-vars  "hip=$host_ip paswd=ganesha@123"



