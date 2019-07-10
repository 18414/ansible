#!/bin/bash
 useradd ansible
 mkdir -p /home/ansible/.ssh
     echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4mN7XiPFpNIRUG5pD1alFuOAyWRV9YvgovAVNZsg0twb0FF9ImW40YFHwXIxitBaVq7pnOJYIYJlYsbgJ0w/4KO2HNXgatNBfoEQxXXsrexYNLiPW9yLS9bMYg/7EtgfM6KHo3WwoO6HYVoopsQuMbf96wmRGup/zZHYnK3rm1BJbFMKlbTL3Ie4vut2qyeQUVhJ3jM9wGjMOccdw/DlWoffOCpJTyrxoF4YJdbjP0CkzmysbxM3qOe4q+7oF6CpC/MV9VwVJCERXy6JQs/m8HfiYhRqLPwcFAmSc29T8keJ6uzJ5hcFb0okZGYIDw2mZnvCgy3fXFUv6mwVXauH7 ansible@ip-172-31-1-205.us-east-2.compute.internal" > /home/ansible/.ssh/authorized_keys
 chmod 700 /home/ansible/.ssh
 chmod 600 /home/ansible/.ssh/authorized_keys
 chown -R ansible.ansible /home/ansible/.ssh/authorized_keys
 chown -R ansible.ansible /home/ansible/.ssh/
 sed -i "/^root/a \\ansible ALL=(ALL) NOPASSWD: ALL" /etc/sudoers > /dev/null



