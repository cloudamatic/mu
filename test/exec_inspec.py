#!/bin/python

import os, json, subprocess, sys, re, glob, time, yaml

deploy_dirs = '/opt/mu/var/deployments'
current_deploys = os.listdir(deploy_dirs)
workspace = os.environ['WORKSPACE']
#workspace = '/opt/mu/lib'
test = workspace+'/test'



def base_controls():
  return ['base_repositories', 'set_mu_hostname', 'disable-requiretty', 'set_local_fw', 'rsyslog', 'nrpe']


def get_profile():
  which_profile = str(sys.argv[1])
  if os.path.isdir(test+'/'+which_profile):
    return which_profile
  else:
    return 'NOT_PROVIDED'


def rebuild_inspec_lock(which_profile):
  if os.path.exists(workspace+'/test/'+which_profile):
    os.chdir(workspace+'/test/'+which_profile)
    os.system('inspec vendor --overwrite')

          

## In terms of scaling, this is not ideal... Maybe 
## we should consider saving the deploy output to a file with time_stamp in /tmp
## and then parse out the deploy_id from stdout 
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


### Inorder to properly trigger inspec exec
### Need to wait for each server_name_done.txt file to exist in deploy_id dir.
### server_pools is the only stanza when this will be used
### The only to retrieve the server_names is from the bok(the json version -- full blown one)
### the server names are not added in the deployment.json right away therefore using the bok.json
def get_server_names(deploy_id):
  server_names = []
  bok_json = json.load(open(deploy_dirs+'/'+deploy_id+'/basket_of_kittens.json'))
  server_or_pools = server_or_server_pools(deploy_id)
  if server_or_pools == 'server_pools':
    num_servers = len(bok_json['server_pools'])
    for x in range(0,num_servers):
      server_names.insert(0,bok_json['server_pools'][x]['name'])
  
  return server_names


def server_or_server_pools(deploy_id):
  bok_json = json.load(open(deploy_dirs+'/'+deploy_id+'/basket_of_kittens.json'))
  if bok_json.has_key('server_pools'):
    return 'server_pools'
  elif bok_json.has_key('servers'):
    return 'servers'
  else:
    return None


def wait_till_groomed(deploy_id,  seconds_to_poll):
  node_names = get_server_names(deploy_id)
  print "Nodes to check: %s "% node_names
  print "Deploy ID: %s"% deploy_id
  for each_node in node_names:
    done = False
    while done == False:
      if os.path.isfile(deploy_dirs+'/'+deploy_id+'/'+each_node+'_done.txt'):
        print "INFO: Server Converged   =====>    %s" % each_node
        done = True
      else:
        done = False
        print "INFO: Server: %s not fully converged. Checking back in %s seconds." % (each_node, seconds_to_poll)
        time.sleep(seconds_to_poll)


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
  print "INFO: Deploy ID    =====>    %s" %deploy_id
  if os.path.isdir(deploy_dirs+'/'+deploy_id):
    node = json.load(open(deploy_dirs+'/'+deploy_id+'/deployment.json'))
    bok = json.load(open(deploy_dirs+'/'+deploy_id+'/basket_of_kittens.json'))
    platform=None
    ssh_user=None
    fqdn = None
      
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
            fqdn = v[dep]['private_ip_address']
          
          ### Filter recipe names to map to inspec controls
          for recipe in run_list:
            if '::' in recipe \
            and 'store_attr' not in recipe \
            and 'default' not in recipe and 'nat' not in recipe:
              recipe_name = re.search(r"\w+]", recipe).group(0).replace(']','')
              control.insert(0,recipe_name)
      
      ssh_info = {'host_name':dep,'server_name': k, 'fqdn': fqdn, 'ssh_user':ssh_user, 'ssh_file': '~/.ssh/'+ssh_key, 'controls': control, 'platform': platform, 'load_balancers':load_balancers } 
      host_infos.append(ssh_info)
    
  
  else:
    raise Exception('ERROR: '+deploy_id+' ==> deploy id does not exist in '+deploy_dirs)
  return host_infos



def store_ssh_info(array_of_ssh_info, where='/tmp'):
  for ssh_info in array_of_ssh_info:
    print ssh_info
    ya = open(where+'/'+ssh_info['server_name']+'_attr.yaml','w')
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
  status = subprocess.call(['inspec','exec',profile,'--controls='+controls,'-t',winrm,'--password',pas])
  return status

def run_linux_tests(profile, ssh, ssh_file, all_controls):
  cmd = "inspec exec %s --controls=%s -t %s -i %s" %(profile,all_controls,ssh,ssh_file)
  stat = os.system(cmd)
  return stat
  

inspec_retry_dir = '/tmp/inspec_retries'
bok_name = None
if str(sys.argv[2]) != None:
  bok_name = str(sys.argv[2])
profile = get_profile()
rebuild_inspec_lock(profile)
os.chdir(workspace)
deploy_id = get_deploy_id(bok_name)
server_or_pools = server_or_server_pools(deploy_id)
if server_or_pools == 'server_pools':
  wait_till_groomed(deploy_id, 5)
ssh_infos = get_host_info(deploy_id)
store_ssh_info(ssh_infos)

try:
  os.makedirs(inspec_retry_dir)
except OSError:
  print "SKIP ===> %s already exists" % inspec_retry_dir


#########################################################################
##### Run Tests ###########################################
for ssh_info in ssh_infos:
  
 
  ### when no recipes -- switch to mu-tools-test profile
  if len(ssh_info['controls']) == 0:
    profile = 'mu-tools-test'
  
  controls = base_controls() + ssh_info['controls']
  all_controls_spaced_out = ' '.join(controls)
  print 'Inspec Profile: =====> %s ' %profile
  print 'Controls To Test =====> '+all_controls_spaced_out+' <====='
  os.chdir(test)
  if ssh_info['platform'] == 'windows':
    exit_status = run_windows_tests(deploy_id, profile, all_controls_spaced_out, ssh_info['ssh_user'])
  else:
    ssh = 'ssh://%s@%s' % (ssh_info['ssh_user'], ssh_info['fqdn'])
    exit_status = run_linux_tests(profile, ssh, ssh_info['ssh_file'],all_controls_spaced_out)
    if int(exit_status != 0):
      ssh_info['profile'] = profile
      ssh_info['bok'] = bok_name
      retry_dump_host_info = open(inspec_retry_dir+'/'+ssh_info['server_name']+'_retry.yaml','w')
      yaml.safe_dump(ssh_info, retry_dump_host_info,default_flow_style=False)

