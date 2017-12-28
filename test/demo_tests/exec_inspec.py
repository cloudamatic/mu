#!/bin/python

import os
import json
import subprocess

deploy_dirs = '/opt/mu/var/deployments'
current_deploys = os.listdir(deploy_dirs)
test = '/opt/mu/lib/test'


def get_host_info(deploy_id):
  host_info = {}
  if os.path.isdir(deploy_dirs+'/'+deploy_id):
    node = json.load(open(deploy_dirs+'/'+deploy_id+'/deployment.json'))
    bok = json.load(open(deploy_dirs+'/'+deploy_id+'/basket_of_kittens.json'))
    server_name = bok['servers'][0]['name']
    key_file = open(deploy_dirs+'/'+deploy_id+'/ssh_key_name')
    ssh_key = key_file.readline().strip()
    host_info['server_name']= server_name
    host_info['fqdn'] = node['servers'][server_name][deploy_id+'-'+server_name.upper()]['public_dns_name']
    host_info['ssh_user'] = 'root'
    host_info['ssh_file'] = ssh_key
  else:
    raise Exception('ERROR: '+deploy_id+' ==> deploy id does not exist in '+deploy_dirs)

  return host_info


##### Upload Cookbooks, roles, etc
#os.system('/opt/mu/bin/mu-upload-chef-artifacts -s')


##### Run Tests
demo_test_profile = '/opt/mu/lib/test/demo_tests/demo-test-profile'
for deploy in current_deploys:
  ssh_info = get_host_info(deploy)
  os.chdir(test)
  ssh = 'ssh://%s@%s' % (ssh_info['ssh_user'], ssh_info['fqdn'])
  ssh_file = '~/.ssh/%s' % ssh_info['ssh_file']
  exit_status = subprocess.call(['inspec','exec',demo_test_profile, '-t',ssh, '-i',ssh_file]) 
  
  ### get test status
  if int(exit_status) != 0:
    raise Exception("Tests Failed with Exit status: "+str(exit_status))


