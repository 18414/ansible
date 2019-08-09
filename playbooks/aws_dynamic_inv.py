#!/bin/python

import boto3
import json
import pprint 

def get_hosts(ec2,fv):
  f={'Name': 'tag:Ansible','Values':[fv]}
  hosts=[]
  for each_in in ec2.instances.filter(Filters=[f]):
    #print each_in.private_ip_address 
    hosts.append(each_in.private_ip_address)
  return hosts

def main():
  ec2=boto3.resource("ec2")
  db_group=get_hosts(ec2, "db")
  app_group=get_hosts(ec2,"App")
#  print "db: ",db_group
 # print "App:",app_group
 
  all_groups= {
              'db': {
                 'hosts':db_group,
                 'vars': {
                       'group_name': 'Database group'
                         }     
                    },
               'App': {
                  'hosts': app_group,
                  'vars': {
                       'group_name': 'Application group'
                          }
                      }
              }

 # pprint.pprint ( all_groups )
  print json.dumps(all_groups)


if __name__=="__main__":
   main()
