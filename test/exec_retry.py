#!/bin/python

import os, json, subprocess, sys, re, glob, time, yaml

workspace = os.environ['WORKSPACE']
test = workspace+'/test'
all_retries = '/tmp/inspec_retries'


def get_all_yml_files():
  return os.listdir(all_retries)

## To run base again or to not? for now just run it
def base_controls():
  return ['base_repositories', 'set_mu_hostname', 'disable-requiretty', 'set_local_fw', 'rsyslog', 'nrpe']

os.chdir(test)
files = get_all_yml_files()
if len(files) != 0:
  for x in files:
      f = yaml.load(open(all_retries+'/'+x,'r'))

      
      
      print ('=============== INFO: Auto Retry in 60 secs============== \nNode: %s \nBOK: %s \nProfile: %s \nControl: %s\nRetry File: %s===================================' % (f['server_name'],f['bok'],f['profile'],f['controls'],x))
      
      
      
      ssh = 'ssh://%s@%s' % (f['ssh_user'], f['fqdn'])
      ssh_file = str(f['ssh_file'])
      ctrls = (base_controls()+f['controls'])
      ctrls_spaced_out = ' '.join(ctrls)
      
      
      cmd = "inspec exec %s --controls=%s -t %s -i %s" %(f['profile'],ctrls_spaced_out,ssh,ssh_file)
      time.sleep(60) 
      stat = os.system(cmd)
      if stat != 0:
        raise Exception("Retry Failed on %s " % f['server_name'])
      else:
        os.system('rm -rf /tmp/inspec_retries/%s' % x)
else:
  print "All Tests passed! No retry files found!!!"



### Empty /tmp/inspec_retries
os.system('rm -rf /tmp/inspec_retries/*')
