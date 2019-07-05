#!/bin/bash
# Version: 1.0
#file=`date +%F_%T`
oneyear=/root/log_script/activity_logs/1y_log_rotate_`date +%F_%T`.log
twomonth=/root/log_script/activity_logs/2m_log_rotate_`date +%F_%T`.log
threemonth=/root/log_script/activity_logs/3m_log_rotate_`date +%F_%T`.log
threemonth1=/root/log_script/activity_logs/3m1_log_rotate_`date +%F_%T`.log
#path="/root/log_script/activity_logs/"

host=`hostname | awk -F"." '{print $1}' | tr '[:lower:]' '[:upper:]'`

### Mail Body
echo -e "/opt/gms/archived/logs older than > 1year\n\n /opt/gms/archived/GMS older than > 2months \n\n /opt/gms/archived/reports older than > 3months \n\n /opt/gms/archived/pms_uploads/ older than > 3months" > body.log

#th=`df -PhT |grep /opt/gms/archived  | tr -d "%"  | awk -F" " '{if ( $6 > 65 ) print "critical" }'`

#if [ $th == "critical" ]
#then

echo "## Remove logs by 1 year old from this /opt/gms/archived/logs/##"  > $oneyear
find /opt/gms/archived/logs/* -type f -mtime +365 -exec ls -lrt {} \; >> $oneyear
find /opt/gms/archived/logs/* -type f -mtime +365 -exec rm -rf {} \;
echo "======================================================" >> $oneyear


echo "## Remove logs by 2 months old from /opt/gms/archived/GMS/##"  > $twomonth
find /opt/gms/archived/GMS/* -type f -mtime +60 -exec ls -lrt {} \; >> $twomonth
find /opt/gms/archived/GMS/* -type f -mtime +60 -exec rm -rf {} \;
echo "======================================================" >> $twomonth

echo "## Remove logs by 3 months old from this /opt/gms/archived/reports/##"  > $threemonth
find /opt/gms/archived/reports/* -type f -mtime +90 -exec ls -lrt {} \; >> $threemonth
find /opt/gms/archived/reports/* -type f -mtime +90 -exec rm -rf {} \;
echo "======================================================" >> $threemonth

echo "## Remove logs by 3 months old from this /opt/gms/archived/pms_uploads/ ##"  > $threemonth1
#find /opt/gms/archived/pms_uploads/* -type f -mtime +90 -exec ls -lrt {} \; >> $threemonth1
#find /opt/gms/archived/pms_uploads/* -type f -mtime +90 -exec rm -rf {} \;
echo "======================================================" >> $threemonth1

cat $oneyear $twomonth $threemonth $threemonth1 > /root/log_script/activity_logs/log_summary_`date +%F_%T`.log



val="$(cat log_summary_`date +%F_%T`.log | wc -l)"

if [ $val -gt "8" ]; then

#if [ -s "log_summary_`date +%F_%T`.log" ];then
#echo -e "Old logs archived from the below path\n===============================\n \n\n`cat body.log`"| mail -s "OLD logs archived on $host" -a log_summary_`date +%F_%T`.log  "abhalerao@travelclick.com"  "bmahajan@travelclick.com"

echo -e "Old logs archived from the below path\n===============================\n\nInstruction to Archived logs\n===============================\n`cat body.log`" | mail -s "OLD logs archived on $host" -a log_summary_`date +%F_%T`.log -r `$hostname`  GMS "bmahajan@travelclick.com" "abhalerao@travelclick.com"

#else
#echo -e "Old logs not found on below path\n\n`cat body`"| mail -s "`hostname` OLD logs not found" -a $path/Deleted_logs_lst_`$file.txt` "bmahajan@travelclick.com"
fi

#fi

