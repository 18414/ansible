#!/bin/bash


ansible-playbook gym_mgmt_system_setup.yml  --extra-vars "host_name=doc" 

grep [0-9] hosts > ip_list

sleep 5
ansible-playbook docker_launch_xampp_v2_new.yml --extra-vars "instance1=`cat ip_list| head -1` instance2=`cat ip_list| tail -1` paswd=ganesha@123"

