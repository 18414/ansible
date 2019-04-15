#!/bin/bash
# Version: 1.0

#Deleting previous ip addresses of instances from ANSIBLE inventory
sed -i '/^[0-9]/d' hosts
sleep 1

#Launching EC2 instances  
ansible-playbook gym_mgmt_system_setup_nginx.yml
<<<<<<< HEAD
=======

>>>>>>> 32fa295473f721ea8df7977d98aaddca39278b01
sleep 1


#installing Docker 
ansible-playbook docker_install_centos.yml

grep [0-9] hosts > ip_list
<<<<<<< HEAD
host_ip=`grep [0-9] hosts`
=======
host_ip=$(grep [0-9] hosts)
>>>>>>> 32fa295473f721ea8df7977d98aaddca39278b01

sleep 1


<<<<<<< HEAD

=======
>>>>>>> 32fa295473f721ea8df7977d98aaddca39278b01
#Launching containers 
ansible-playbook docker_launch_nginx_lb_v1.yml --extra-vars  "hip=$host_ip paswd=ganesha@123"



