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
workspace = '/home/jenkins/workspace/test2'
test = workspace+'/test'


def get_profile():
  which_profile = str(sys.argv[1])
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
        print stripped
        partial_dep_name = stripped.split()[1].upper()+'-DEV'
        break

  os.chdir(deploy_dirs)
  for dirs in glob.glob(partial_dep_name+'*'):
    deploy_id = dirs
    break
  return deploy_id


def wait_for_servers(deploy_id,seconds_to_poll=3):
  node = json.load(open(deploy_dirs+'/'+deploy_id+'/deployment.json')) 
  servers_present = False
  
  while servers_present == False:
    if node.has_key('servers'):
      servers_present = True
    else:
      time.sleep(seconds_to_poll)
      servers_present = False
      print "INFO: Servers not found. Checking back in %s seconds" % seconds_to_poll


def wait_till_confirmed(deploy_id, node, seconds_to_poll):
  done = False
  os.chdir(deploy_dirs+'/'+deploy_id)
  while done == False:
    if os.path.isfile(node+'_done.txt'):
      print "INFO: Server Converged: %s" % node
      done = True
    else:
      print "INFO: Server =====> %s <===== not fully converged. Checking back in %s seconds." % (node, seconds_to_poll)
      done = False
      time.sleep(10)  
  return done

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
  print deploy_id
  if os.path.isdir(deploy_dirs+'/'+deploy_id):
    node = json.load(open(deploy_dirs+'/'+deploy_id+'/deployment.json'))
    bok = json.load(open(deploy_dirs+'/'+deploy_id+'/basket_of_kittens.json'))
    platform=None
    ssh_user=None
    fqdn = None
    server_pools = True
      
    try:
      platform = bok['servers'][0]['platform']
      ssh_user = bok['servers'][0]['ssh_user']
    except KeyError as e:
      platform = bok['server_pools'][0]['platform']
      ssh_user = bok['server_pools'][0]['ssh_user']

    load_balancers = get_load_balancers(deploy_id)
    
    ### Get SSH Key Name from deploy_id dir
    key_file = open(deploy_dirs+'/'+deploy_id+'/ssh_key_name')
    ssh_key = key_file.readline().strip()
    
    for k,v in node['servers'].iteritems():
      control = []
      run_list = []
      dep = None
  
      ### need each servers ssh info
      for key,val in v.iteritems():
        if key.startswith(deploy_id+'-'+k.upper()):
          dep = key
          print 'INFO: Deploy ID Detected: %s' % dep
          run_list = val['run_list']

          ### Get DNS
          if len(v[dep]['public_dns_name']) != 0:
            fqdn = v[dep]['public_dns_name']
          else:
            fqdn = v[dep]['private_dns_name']
          
          ### Filter recipe names to map to inspec controls
          for recipe in run_list:
            if '::' in recipe \
            and 'store_attr' not in recipe \
            and 'default' not in recipe and 'nat' not in recipe:
              recipe_name = re.search(r"\w+]", recipe).group(0).replace(']','')
              control.insert(0,recipe_name)
      
      ssh_info = {'server_name': k, 'fqdn': fqdn, 'ssh_user':ssh_user, 'ssh_file': '~/.ssh/'+ssh_key, 'controls': control, 'platform': platform, 'load_balancers':load_balancers } 
      host_infos.append(ssh_info)
    
  
  else:
    raise Exception('ERROR: '+deploy_id+' ==> deploy id does not exist in '+deploy_dirs)
  return host_infos



def store_ssh_info(array_of_ssh_info, where='/tmp'):
  for ssh_info in array_of_ssh_info:
    print ssh_info
    ya = open(where+'/'+ssh_info['server_name']+'_attr.yaml','w')
    ### yes safe_dump to get rid of python unicode text
    yaml.safe_dump(ssh_info, ya,default_flow_style=False)



def get_win_pass(deploy_id):
  command = subprocess.check_output(['knife', 'vault', 'show', deploy_id+'-WINDOWS','windows_credentials'])
  for line in command.splitlines():
    if line.startswith('password:'):
      return line.split(':')[1].strip()
      break



def run_windows_tests(deploy_id,profile,controls,ssh_user):
  pas =  "\'%s\'" % get_win_pass(deploy_id)
  winrm = "winrm://%s@%s" % (ssh_user,deploy_id.upper()+'-WINDOWS')
  cmd = "inspec exec "+profile+" --controls="+controls+" -t "+winrm+" --password "+pas


def run_linux_tests(profile, ssh, ssh_file, all_controls):
  status = subprocess.call(['inspec','exec', profile, '--controls='+all_controls,'-t',ssh, '-i', ssh_file])
  return status
  


bok_name = None
if str(sys.argv[2]) != None:
  bok_name = str(sys.argv[2])

profile = get_profile()
deploy_id = get_deploy_id(bok_name)
ssh_infos = get_host_info(deploy_id)
store_ssh_info(ssh_infos)
#########################################################################
##### Run Tests ###########################################
for ssh_info in ssh_infos:

  ### get all inspec controls to run
  controls = ssh_info['controls']
  all_controls_spaced_out = ' '.join(controls)
  print 'Control =====> '+all_controls_spaced_out+' <=====' 
  
  ### Check if servers are up and  grooming finished
  wait_for_servers(deploy_id)
  wait_till_confirmed(deploy_id, ssh_info['server_name'],5)
 
  os.chdir(test)
  if ssh_info['platform'] == 'windows':
    exit_status = run_windows_tests(deploy_id, profile, all_controls_spaced_out, ssh_info['ssh_user'])
  else:
    ssh = 'ssh://%s@%s' % (ssh_info['ssh_user'], ssh_info['fqdn'])
    exit_status = run_linux_tests(profile, ssh, ssh_info['ssh_file'],all_controls_spaced_out)
