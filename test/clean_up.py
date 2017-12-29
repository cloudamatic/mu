#!/bin/python

import os
import json
import subprocess

deploy_dirs = '/opt/mu/var/deployments'
current_deploys = os.listdir(deploy_dirs)


def clean_all(list_of_deploy_ids):
  ## loop over current deploys and terminate them
    for each in list_of_deploy_ids:
        os.system('/opt/mu/bin/mu-cleanup %s' % each)



### sometimes, there is a weird file 'unique_ids' so delete if needed
if os.path.isfile(deploy_dirs+'/unique_ids'):
  os.system('rm -f %s/unique_ids' % deploy_dirs)

clean_all(current_deploys)
print ('**'*20)
print ('INFO: Cleanup up %s '%  current_deploys)
print ('**'*20)
