#!/bin/bash
 useradd ansible
 mkdir -p /home/ansible/.ssh
     echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCTjprb9r0HAkfyevOJl/pFPyzmnmCPqki1g9u3g+fbc9Biguhc4axDf5nh5tqNOIN8mhHhc1O+or/rlAs8+6cw6kNFz1oBTZeNpxubr0+hn/cpu/TqPyWS9w8m+XVSRpyY3u1Kp36TD6+8um+OApNeOylUqygA/snkr5RZOofdQOwJArcrQyvZ1NcxBtaDg+F9YVzzu4eKQ87orT7+joE6kuz8rSYUm9laV4bV+4Wloy/sAeseOuDqihwuX8DvTQodGGT+sa3e6lWyK6D4YV2BADR1KFTQMC8yR+65PQOD9VGnNSW7z3LQmdO86Y+O8MCGUmg+MmeZeTYLh6j4ibXl ansible@ansible.ganesha.local" > /home/ansible/.ssh/authorized_keys
 chmod 700 /home/ansible/.ssh
 chmod 600 /home/ansible/.ssh/authorized_keys
 chown -R ansible.ansible /home/ansible/.ssh/authorized_keys
 chown -R ansible.ansible /home/ansible/.ssh/
 sed -i "/^root/a \\ansible ALL=(ALL) NOPASSWD: ALL" /etc/sudoers > /dev/null



