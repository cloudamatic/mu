#!/usr/bin/env python 

import os
import subprocess
import sys

def bok_exists(which_bok,all_boks=os.environ['WORKSPACE']+'/demo'):
  if os.path.isfile(all_boks+'/'+which_bok):
    return True
  else:
    return False

def run_bok(bok_to_run, all_boks=os.environ['WORKSPACE']+'/demo'):
  if bok_exists(bok_to_run):
    os.system(os.environ['WORKSPACE']+"/bin/mu-deploy -n "+all_boks+'/'+bok_to_run)
  else:
    raise Exception('BOK '+bok_to_run+' DOES NOT EXIST!')

### get the positinal parameter for BOK file Name
bok_name = None
if str(sys.argv[1]) != None:
  bok_name = str(sys.argv[1])
else:
  bok_name = "NOT_PROVIDED"

run_bok(bok_name)
