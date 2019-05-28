######################################################################################
# Script: checklist.sh                                                               #
# Description: Script will take checklist of server and email it to cyb_sys_eng_team #
# Author: Mayuresh Wadekar                                                           #
######################################################################################

#!/bin/sh
HOSTNAME=`hostname`
fname=`date +"%Y%m%d%H%M"`
HTML_LOG=/var/tmp/index.html
prechecklist_output=/var/tmp/prechecklist.txt

> $prechecklist_output
> $HTML_LOG

ToHtml() {
        echo $1 >> ${HTML_LOG}
}

Genrate_Report()
{

ToHtml "
        <html>
        <head><title>Checklist</title></head>
        <body>
        <table border="0" width="831" id="table9">
        <tr>
        <td><font size=3>Hi Team<f/font></td>
        </tr>
        <tr>
        <td><font size=3>Please find attached checklist of server $HOSTNAME</font></td>
        </tr>
        <tr>
        <td><font color=red><u>Kind attention on below issues</u></font></td>
        </tr>
        </table>"

ToHtml "
        <table border="1">
        <tr>
        <td bgcolor="#00FFFF">Alerts</td>
        <td bgcolor="#00FFFF">Status</td>
        <tr>"


cpu_utilization=`top -b -n2 -p 1 | fgrep "Cpu(s)" | tail -1 | awk -F'id,' -v prefix="$prefix" '{ split($1, vs, ","); v=vs[length(vs)]; sub("%", "", v); printf "%s%.1f%%\n", prefix, 100 - v }'`

cpu_uzt=`top -b -n2 -p 1 | fgrep "Cpu(s)" | tail -1 | awk -F'id,' -v prefix="$prefix" '{ split($1, vs, ","); v=vs[length(vs)]; sub("%", "", v); printf "%s%.1f%%\n", prefix, 100 - v }'|cut -d "." -f1`

if [ "$cpu_uzt" -gt "80" ]; then
ToHtml "<tr>
        <td>CPU Utilization </td>
        <td>$cpu_utilization</td>
        </tr>
        "
fi



cpu_counts=`cat /proc/cpuinfo | grep -i processor | wc -l`
cpu_load_avg=`cat /proc/loadavg | awk '{print $1}' | cut -d . -f1`
if [ "$cpu_load_avg" -ge "$cpu_counts" ]; then
ToHtml "<tr>
        <td>CPU Load </td>
        <td>$cpu_load_avg (processors $cpu_counts)</td>
        </tr>
       "
echo "====================Processes Consuming High CPU load======================" >> $prechecklist_output
top -b -n 1 | awk '{if (NR <=7) print; else if ($8 == "D") {print; count++} } END {print "Total status D (I/O wait probably): "count}' >> $prechecklist_output
fi




mem_utilization=`free -m |grep Mem |awk '{print $3/$2*100}' | cut -d"." -f1`
if [ "$mem_utilization" -gt "80" ]; then
ToHtml "<tr>
        <td>Memory Utilization </td>
        <td>$mem_utilization %</td>
        </tr>
        "
fi

readonly_fs=`cat /proc/mounts | grep ro,`
readonly_checks=`echo "$?"`
if [ "$readonly_checks" = "0" ]; then
ToHtml "<tr>
        <td>Readonly Filesystems</td>
        <td>$readonly_fs</td>
        </tr>
        "
fi

fs_count=`df -PH | grep -vE '^Filesystem|tmpfs|cdrom' | awk '{ print $2" "$3" "$4" "$5" "$6 }' | wc -l`
for((i=1; i<=$fs_count; i++))
do
fs_util=`df -PH | grep -vE '^Filesystem|tmpfs|cdrom' | awk '{ print $2" "$3" "$4" "$5" "$6 }' | head -n $i | tail -n 1| awk '{print $4}'  | cut -d "%" -f1`
fs_name=`df -PH | grep -vE '^Filesystem|tmpfs|cdrom' | awk '{ print $2" "$3" "$4" "$5" "$6 }' | head -n $i | tail -n 1| awk '{print $5}'`
if [ "$fs_util" -gt "80" ]; then
ToHtml "<tr>
        <td>Utilization of fs $fs_name </td>
        <td>$fs_util %</td>
        </tr>
        "
fi
unset fs_util
unset fs_name
done


chef_service_status=`ps -ef |grep -v grep | grep -i chef-client`
chef_running_result=`echo "$?"`
if [ "$chef_running_result" = "0" ]
then
        chef_failed_status=`find /var/chef/cache/chef-stacktrace.out -mmin -30 |  grep chef`
        chef_error_status=`echo "$?"`
           if [ "$chef_error_status" = "0" ]
             then
                ToHtml " <tr>
                         <td>Chef-Client</td>
                         <td>Failed</td>
                        </tr>"
            fi

else
   ToHtml " <tr>
   <td>Chef-Client</td>
   <td>Not Running</td>
    </tr>"
fi



ToHtml "</table>
        <br>
        <font size=3>Regards,</font><br>
        <font size=4 face="Calibri" color="blue"><b>Travelclick, An Amadeus Company</b></font>
        "
echo "====================hostname======================" >> $prechecklist_output
hostname -f >> $prechecklist_output
echo "================date and time=====================" >> $prechecklist_output
date >> $prechecklist_output
echo "==========current logged in users=================" >> $prechecklist_output
w >> $prechecklist_output
echo "=================filesystem=======================" >> $prechecklist_output
df -Ph >> $prechecklist_output
echo "===================Logical Volumes=========================" >> $prechecklist_output
lvs >> $prechecklist_output
echo "===================Volumes Group=========================" >> $prechecklist_output
vgs >> $prechecklist_output
echo "===================Physical Volumes=========================" >> $prechecklist_output
pvs >> $prechecklist_output
echo "===================kernel=========================" >> $prechecklist_output
uname -a >> $prechecklist_output
echo "===================ExportFS=========================" >> $prechecklist_output
cat /etc/exports >> $prechecklist_output
echo "===================Memory=========================" >> $prechecklist_output
free -g >> $prechecklist_output
echo "==================iptables========================" >> $prechecklist_output
iptables -nL >> $prechecklist_output
echo "=================ipaddress========================" >> $prechecklist_output
ifconfig -a >> $prechecklist_output
echo "==================routes==========================" >> $prechecklist_output
route -n >> $prechecklist_output
echo "=================multipath========================" >> $prechecklist_output
multipath -ll >> $prechecklist_output
echo "=================hardware=========================" >> $prechecklist_output
dmidecode -t 1 >> $prechecklist_output
echo "===============SELinux Status=====================" >> $prechecklist_output
sestatus >> $prechecklist_output
echo "==================Process=========================" >> $prechecklist_output
netstat -ntulp >> $prechecklist_output
echo "==============Kernel Parameters===================" >> $prechecklist_output
sysctl -a >>  $prechecklist_output
echo "==================Packages========================" >> $prechecklist_output
rpm -qa >> $prechecklist_output


MailReport

}

MailReport() {

/usr/sbin/sendmail -t <<!
To: bmahajan0@gmail.com
Subject: CHECKLIST of $HOSTNAME
MIME-Version: 1.0
Content-Type: multipart/mixed;
        boundary="XXXXboundary text"


--XXXXboundary text
Content-Type: text/html

`cat ${HTML_LOG}`

--XXXXboundary text
Content-Type: text/plain
Content-Disposition: attachment; filename=checklist-$fname.txt

`cat $prechecklist_output`
.
!

}

Genrate_Report

