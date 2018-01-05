#!/bin/python

import os
import json
import subprocess
import sys
import re
import glob
import time
import yaml
import ast

deploy_dirs = '/opt/mu/var/deployments'
current_deploys = os.listdir(deploy_dirs)
workspace = os.environ['WORKSPACE']
test = workspace+'/test'


def get_profile():
  which_profile = str(sys.argv[1])
  print which_profile
  if os.path.isdir(test+'/'+which_profile):
    return which_profile
  else:
    return 'NOT_PROVIDED'


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



### Use only for async_groom
def wait_till_confirmed(seconds_to_wait):
  done = False
  file_to_check = '/Mu_Logs/master.log'
  while done == False:
    file1 = os.stat(file_to_check) # initial file size
    start_size = file1.st_size
    time.sleep(seconds_to_wait)
    file2 = os.stat(file_to_check) # updated file size
    new_size = file2.st_size
    comp = new_size - start_size # compares sizes
    if comp != 0:
      print 'INFO: File changes detected.. Checking again after %s seconds....' % str(seconds_to_wait)
      done = False
    else:
      done = True
      print 'SKIP: No new changes detected in the logs, continuing to inspec...'


def get_load_balancers(deploy_id):
  all_loads = []
  each_load = {}
  if os.path.isdir(deploy_dirs+'/'+deploy_id):
      node = json.load(open(deploy_dirs+'/'+deploy_id+'/deployment.json'))
      
      ## Check if any?
      if node.get('loadbalancers') != None:
        for key,val in node['loadbalancers'].iteritems():
          for k,v in val.iteritems():
            each_load = {key:val['dns']}
            all_loads.append(each_load)
            break
  return all_loads 


def get_host_info(deploy_id):
  host_infos = []
  ssh_info = {}
  if os.path.isdir(deploy_dirs+'/'+deploy_id):
    node = json.load(open(deploy_dirs+'/'+deploy_id+'/deployment.json'))
    bok = json.load(open(deploy_dirs+'/'+deploy_id+'/basket_of_kittens.json'))
    platform=None
    ssh_user=None
    fqdn = None
    ### detect if servers or server_pools?
    if bok.get('servers') != None:
      platform = bok['servers'][0]['platform']
      ssh_user = bok['servers'][0]['ssh_user']

    elif bok.get('server_pools') != None:
      platform = bok['server_pools'][0]['platform']
      ssh_user = bok['server_pools'][0]['ssh_user']

    load_balancers = get_load_balancers(deploy_id)

    for k,v in node['servers'].iteritems():
      control = []
      run_list = []
      dep = None
      for key,val in v.iteritems():
        if key.startswith(deploy_id+'-'+k.upper()):
          dep = key
          run_list = val['run_list']
          
          ### Get DNS
          if len(v[dep]['public_dns_name']) != 0:
            fqdn = v[dep]['public_dns_name']
          else:
            fqdn = v[dep]['private_dns_name']
          
          for recipe in run_list:
            if '::' in recipe:
              recipe_name = re.search(r"\w+]", recipe).group(0).replace(']','')
              if recipe_name != 'store_attr' and recipe_name != 'default':
                control.insert(0,recipe_name)
              else:
                print 'SKIP: Not adding ==> %s <== to the controls list' % recipe_name
                run_list.remove(recipe)
      
      ### Get SSH Key Name from deploy_id dir
      key_file = open(deploy_dirs+'/'+deploy_id+'/ssh_key_name')
      ssh_key = key_file.readline().strip()
      
      
      ssh_info = {'server_name': k, 'fqdn': fqdn, 'ssh_user':ssh_user, 'ssh_file': '~/.ssh/'+ssh_key, 'controls': control, 'platform': platform, 'load_balancers':load_balancers } 
      host_infos.append(ssh_info)
      #print ssh_info
  else:
    raise Exception('ERROR: '+deploy_id+' ==> deploy id does not exist in '+deploy_dirs)
  return host_infos
 





#########################################################################
##### Run Tests
bok_name = None
if str(sys.argv[2]) != None:
  bok_name = str(sys.argv[2])
  print bok_name

profile = get_profile()

####### FOR ETCO ONLY -- ASYNC_GROOM
if 'ETCO' in bok_name or 'etco' in bok_name:
  wait_till_confirmed(120)
###################

deploy_id = get_deploy_id(bok_name)
ssh_infos = get_host_info(deploy_id)
os.chdir(test)
for ssh_info in ssh_infos:
  
  ## dump ssh info so inspec tests can utilize dns addresses
  ya = open(workspace+'/test/'+profile+'/'+ssh_info['server_name']+'_attr.yaml','w')
  yaml.safe_dump(ssh_info, ya,default_flow_style=False)


  if ssh_info['platform'] == 'windows':
    print 'winrm is not yet configured...'
    ## Figure out how to perform winrm here...
  else:
    ssh = 'ssh://%s@%s' % (ssh_info['ssh_user'], ssh_info['fqdn'])
    controls = ssh_info['controls']
    all_controls_spaced_out = ' '.join(controls)
    print 'Control'+'='*5+'>'+all_controls_spaced_out+'<'+5*"="
    
    ssh = 'ssh://%s@%s' % (ssh_info['ssh_user'], ssh_info['fqdn'])
    exit_status = subprocess.call(['inspec','exec', profile, '--controls='+all_controls_spaced_out,'-t',ssh, '-i',ssh_info['ssh_file']]) 
    if int(exit_status) != 0:
      raise Exception("Tests Failed with Exit status: "+str(exit_status))
