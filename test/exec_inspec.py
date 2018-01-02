#!/bin/python

import os
import json
import subprocess
import sys
import re
import glob

deploy_dirs = '/opt/mu/var/deployments'
current_deploys = os.listdir(deploy_dirs)
test = '/opt/mu/lib/test'


def get_profile():
  which_profile = str(sys.argv[1])
  if os.path.isdir(test+'/'+which_profile):
    return test+'/'+which_profile
  else:
    return 'NOT_PROVIDED'


### TODO:
### BOK has 2 or more servers...
### with different run_list
### Inspec must know which profile to run on which node
### Then as of now this only work with 1 server


def get_deploy_id(bok, all_boks='/opt/mu/lib/demo'):
  partial_dep_name = None
  deploy_id = None
  yml_file = open(all_boks+'/'+bok, 'r')
  for each_line in yml_file.readlines():
    line = each_line.splitlines()
    for each in line:
      stripped =  each.strip()
      if 'appname:' in stripped:
        partial_dep_name = stripped.split()[1].upper()+'-DEV'
  
  os.chdir(deploy_dirs)
  for dirs in glob.glob(partial_dep_name+'*'):
    deploy_id = dirs
    break
  return deploy_id


def get_host_info(deploy_id):
  host_infos = []
  ssh_info = {}
  if os.path.isdir(deploy_dirs+'/'+deploy_id):
    node = json.load(open(deploy_dirs+'/'+deploy_id+'/deployment.json'))
    bok = json.load(open(deploy_dirs+'/'+deploy_id+'/basket_of_kittens.json'))
    platform=None
    ssh_user=None
    for server in bok['servers']:
      platform = server['platform']
      ssh_user = server['ssh_user']

    for k,v in node['servers'].iteritems():
      key_file = open(deploy_dirs+'/'+deploy_id+'/ssh_key_name')
      ssh_key = key_file.readline().strip()
      ssh_info = {'server_name': k, 'fqdn': v[deploy_id+'-'+k.upper()]['public_dns_name'], 'ssh_user':ssh_user, 'ssh_file': '~/.ssh/'+ssh_key, 'run_list': v[deploy_id+'-'+k.upper()]['run_list'], 'platform': platform} 
      host_infos.append(ssh_info)
      print ssh_info
  else:
    raise Exception('ERROR: '+deploy_id+' ==> deploy id does not exist in '+deploy_dirs)
  return host_infos
  

##### Run Tests
bok_name = None
if str(sys.argv[2]) != None:
  bok_name = str(sys.argv[2])
else:
  bok_name = "NOT_PROVIDED"

profile = get_profile()
deploy_id = get_deploy_id(bok_name)
ssh_infos = get_host_info(deploy_id)
os.chdir(test)
for ssh_info in ssh_infos:
  print ssh_info['platform']
  if ssh_info['platform'] == 'windows':
    print 'winrm is not yet configured...'
    ## Figure out how to perform winrm here...
  else:
    ssh = 'ssh://%s@%s' % (ssh_info['ssh_user'], ssh_info['fqdn'])
    exit_status = subprocess.call(['inspec','exec', profile, '-t',ssh, '-i',ssh_info['ssh_file']]) 
  
### get test status
if int(exit_status) != 0:
  raise Exception("Tests Failed with Exit status: "+str(exit_status))
