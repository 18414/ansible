#!/bin/bash
 useradd ansible
 mkdir -p /home/ansible/.ssh
     echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC92Ihz4c0UgL78rV83XyFByuY3PP0bXxl70DFBNoUL/kPjLjGgYnfAmQRovIHaLJMUybQj4DoUHk2VtHGRFRx3K78Zo1G1/kiSDqvDWFvYr8gi3tDkXG1mBhuh7owFEHRSsuzITGtyUXp9aEZlM24N7KJ5zJzTYgIbQstVuRWddzzElom9UGwXQXZXMfThnocMCWfj6KJoLgYfzLg6M6gSE5VtrvJa6d7n1CyGryoc9Gz92TPOMXT+qrrKqsr0Pfvp5xmMCUa2efEVYDfot/UDA4hRL8hHHDdNXfmHfZpi0oW7Ew7sLf14d7TVpjpmKy0bNZIgYToSDy04Qxhh/uV7 ansible@ansible.example.com" > /home/ansible/.ssh/authorized_keys
 chmod 700 /home/ansible/.ssh
 chmod 600 /home/ansible/.ssh/authorized_keys
 chown -R ansible.ansible /home/ansible/.ssh/authorized_keys
 chown -R ansible.ansible /home/ansible/.ssh/
 sed -i "/^root/a \\ansible ALL=(ALL) NOPASSWD: ALL" /etc/sudoers > /dev/null



