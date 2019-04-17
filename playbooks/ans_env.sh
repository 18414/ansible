#!/bin/bash
 useradd ansible
 mkdir -p /home/ansible/.ssh
     echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDjklgtB5N0cxsn3LTFhB/c22/i50RqJ0Zm+5ECbGA+FkxAu6xvpe5ifiAjcFJF5rYz2bQkYEpFGtPJcYPp8+GG3gCOdGvt5dl0+Uh7kJS/z51LbQl3A+BcXr/JqYYFEtqYZ3olIyyQLCVnap57TSJxs8taUmhT0yS61fZoCk0uso4I+tJer3VmO4pQLwuaojZfkNwOu2VIHjkdx2Iv70mEh0h92p/pT8tMJPefUlgN5cF8a1x3ewyXy2B1QKE2PwTHRZTqwR2eDmUXzI/sI3nLvsbZ4CSsrcOb4+4ih9DrIOXveYCxSZZW6f7aJebwl291+VwTi/ztusZM2P+Vdbpn ansible@ip-172-31-45-133.us-east-2.compute.internal" > /home/ansible/.ssh/authorized_keys
 chmod 700 /home/ansible/.ssh
 chmod 600 /home/ansible/.ssh/authorized_keys
 chown -R ansible.ansible /home/ansible/.ssh/authorized_keys
 chown -R ansible.ansible /home/ansible/.ssh/
 sed -i "/^root/a \\ansible ALL=(ALL) NOPASSWD: ALL" /etc/sudoers > /dev/null



