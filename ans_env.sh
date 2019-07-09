#!/bin/bash
 useradd ansible
 mkdir -p /home/ansible/.ssh
     echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9YEQrp/XO2GEr5DfaJPsr+G4qFYO1+JSwqRZxZNfT4dz+Yj7tRShOEX6XM3ieLsGZQxCbXqp3GDah+6uZwnBBuvuTrzWh0ynb9r1rBzAM/g3VQ1iyzWlsU5FOPOMvs5WaKPgfT5/CexAlUHhM4H4IMWi7kVVAVQaKJrNyqoCUtlEwNweXqUpNNzI3KfzZxHAy64X+kzg0i7XmSeJvH4FMmC0+rT5kNs/DJes8KpVkIbqwx/LPUjUU2M5c4JvxNdkgPiEn28ooaSbLjgJIGMcJUuMoOYn8/rY3v0QCnUl2xsE5gXbdAXkqmyT6gRwBoTIPEZC8TYr2RHP5qsULt9n7 ansible@ip-172-31-1-128.us-east-2.compute.internal
" > /home/ansible/.ssh/authorized_keys
 chmod 700 /home/ansible/.ssh
 chmod 600 /home/ansible/.ssh/authorized_keys
 chown -R ansible.ansible /home/ansible/.ssh/authorized_keys
 chown -R ansible.ansible /home/ansible/.ssh/
 sed -i "/^root/a \\ansible ALL=(ALL) NOPASSWD: ALL" /etc/sudoers > /dev/null



