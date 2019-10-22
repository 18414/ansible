#!/usr/bin/expect

#set ho "localhost"
#set us "ansible"
#set psw "ThisisMylastpass@28"
set cmd1 "sudo vim /etc/ansible/hosts"
set cmd2 "sh /opt/gms/bin/tomcat_stop_graceful.sh"

spawn ssh -q -o StrictHostKeyChecking=no -t  $us@$ho

expect "assword: "
send "$psw\r"
sleep 2
expect "$ "
send "$cmd1\r"
set timeout 30
expect "aikh:"
send "$psw\r"
set timeout 30

expect "$ "
send "$cmd2\r"

expect "$ "
send "exit\r"

expect "$ "
send "exit\r"

interact
 
