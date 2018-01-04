#!/bin/python

import os
import json
import subprocess
import sys
import re
import glob

deploy_dirs = '/opt/mu/var/deployments'
current_deploys = os.listdir(deploy_dirs)
workspace = os.environ['WORKSPACE']
test = workspace+'/test'


def get_profile():
  which_profile = str(sys.argv[1])
  if os.path.isdir(test+'/'+which_profile):
    return which_profile
  else:
    return 'NOT_PROVIDED'


### TODO: NEEDS TO BE TESTED WITH BELOW SOLUTION
### BOK has 2 or more servers...
### with different run_list
### Inspec must know which profile to run on which node
### Then as of now this only work with 1 server

### Getting the correct deploy id
### Pass the bok.yaml when running the inspec test as another positional param
### Yes I tried parsing through the yaml file using yaml.load but it complains
### It complains about having embedded ruby tags.... 
### Sure I can skip x number of lines that have those embedded ruby tags but,
### each bok is differrent and number of lines to skip when parsing will change
### So instead I did it this way...



def get_deploy_id(bok, all_boks=workspace+'/demo'):
  partial_dep_name = None
  deploy_id = None
  yml_file = open(all_boks+'/'+bok, 'r')
  for each_line in yml_file.readlines():
    line = each_line.splitlines()
    for each in line:
      stripped =  each.strip()
      if 'appname:' in stripped:
        partial_dep_name = stripped.split()[1].upper()+'-DEV'
        break

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
      control = []
      run_list = v[deploy_id+'-'+k.upper()]['run_list']
      for recipe in run_list:
        recipe_name = re.search(r"\w+]", recipe).group(0).replace(']','')
        if recipe_name != 'store_attr':
          control.insert(0,recipe_name)
        else:
          print 'SKIP: Not adding ==> %s <== to the controls list' % recipe_name
        run_list.remove(recipe)
      key_file = open(deploy_dirs+'/'+deploy_id+'/ssh_key_name')
      ssh_key = key_file.readline().strip()
      ssh_info = {'server_name': k, 'fqdn': v[deploy_id+'-'+k.upper()]['public_dns_name'], 'ssh_user':ssh_user, 'ssh_file': '~/.ssh/'+ssh_key, 'run_list': v[deploy_id+'-'+k.upper()]['run_list'], 'controls': control, 'platform': platform } 
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
  if ssh_info['platform'] == 'windows':
    print 'winrm is not yet configured...'
    ## Figure out how to perform winrm here...
  else:
    ssh = 'ssh://%s@%s' % (ssh_info['ssh_user'], ssh_info['fqdn'])
    controls = ssh_info['controls']
    for control in controls:
        ssh = 'ssh://%s@%s' % (ssh_info['ssh_user'], ssh_info['fqdn'])
        exit_status = subprocess.call(['inspec','exec', profile, '--controls='+control,'-t',ssh, '-i',ssh_info['ssh_file']]) 
    

### get test status
if int(exit_status) != 0:
  raise Exception("Tests Failed with Exit status: "+str(exit_status))
