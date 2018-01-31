#!/bin/python

import subprocess, boto3, os, json, time, datetime


### TODO:
##### Grab the installer from a specific branch
##### Update installer url with the correct branch name
##### Have the CI server inject an env var of branch name if there's not one already
##### But what CI to use -- dunno 


#workspace=os.environ['WORKSPACE']
ssh_data_file = '/tmp/MU-MASTER-INSTALL-TEST.json'
branch = "issue_100"
user_data= """#!/bin/bash 
sed -i 's/#PermitRootLogin yes/PermitRootLogin yes/g' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
echo "RSAAuthentication yes" >> /etc/ssh/sshd_config
sed -i 's/.*ssh-rsa/ssh-rsa/g' /root/.ssh/authorized_keys
service sshd reload
yum install wget -y
yum install git -y
cd /tmp 
wget https://raw.githubusercontent.com/cloudamatic/mu/%s/install/installer 
chmod +x installer
ip=$(curl http://169.254.169.254/latest/meta-data/public-ipv4)
admin_email="amrit.gill@eglobaltech.com"
sed -i "s/\/opt\/mu\/bin\/mu-configure \$\@/\/opt\/mu\/bin\/mu-configure \$\@ -np $ip -m $admin_email/g" installer""" % branch


def base_controls():
  return ['default','init','basepackages','firewall-holes', 'ssl-certs', 'vault']




def run_installer_over_ssh(user,host, key_file, command):
  if user != None and host != None and command != None:
    exists = False
    time.sleep(90)
    counter = 0
    max_retries = 20
    while (counter != max_retries):
      out = subprocess.check_output(["ssh","-oStrictHostKeyChecking=no","-i", key_file, user+"@"+host,"ls","/tmp/"])
      if 'installer' in out:
        exists = True
        break
      else:
        counter += 1
        exists = False
        print "Installer does not exist yet... checking back 5 secs... (Retry %s/%s)" % (counter,max_retries)
        time.sleep(5)
    
    ssh_syntax = "ssh -oStrictHostKeyChecking=no -i %s %s@%s %s" % (key_file,user,host,command)
    os.system(ssh_syntax)


# not using currently -- but good to have (just in case ya know)
def allocat_associate_eip(ins_id):
  ec2 = boto3.client('ec2')
  try:
    allocation = ec2.allocate_address(Domain='vpc')
    res = ec2.associate_address(AllocationId=allocation['AllocationId'],InstanceId=ins_id)
    print(res)
  except ClientError as e:
    print(e)
  print allocation['AllocationId']
  
  ## to use release_eip, we need the alloc_id
  return allocation['AllocationId']


## de-register eip and then release it
def release_eip(alloc_id):
  ec2 = boto3.client('ec2')
  if alloc_id != None and len(alloc_id) != 0:
    res = ec2.release_address(AllocationId= alloc_id)
    return res
  else:
    raise Exception("Please pass a valid EIP Allocation ID..")


### Create instance to install mu-master
def create_instance(name="MU-INSTALL-TEST", type='t2.medium',maxx=1,region='us-east-1'):
  ec2_name = name+"{:%Y%m%d%H%M%S}".format(datetime.datetime.now())
  ec2 = boto3.resource('ec2', region_name=region)
  instance = ec2.create_instances(
    ImageId = 'ami-02e98f78', ## CS7 
    MinCount = 1,
    MaxCount = maxx,
    InstanceType = type,
    KeyName='MU-MASTER-INSTALL-TEST', ## exists prior
    UserData = user_data,
    SecurityGroupIds = ['sg-66fdfe12'],
    TagSpecifications=[
      {
        'ResourceType':'instance',
        'Tags':[
          {
            'Key': 'Name',
            'Value':ec2_name
          }
        ]
      }
    ],

    SubnetId = 'subnet-7dd64636',
    IamInstanceProfile={
      'Name': 'mu-master-role'
    }
  )
  ins = instance[0]
  ins.wait_until_running()
  ins.load() ## reload
  instances = ins.id
  print "Instance Initliazed %s " % instances
  return instances



### Pull out servers ssh info for inspec
def desc_instances(ins_ids,region='us-east-1'):
  ec2 = boto3.client('ec2')
  bootstrap = {}
  all_bootstraps = []
  ins = ec2.describe_instances(InstanceIds=ins_ids)

  for each_running in ins['Reservations']:
    key = None
    fqdn = None
    name = None
    ins_id = None
    pub_ip = None
    for each in each_running['Instances']:
      
      key = '/root/.ssh/'+each['KeyName']+'.pem'
      fqdn = each['PublicDnsName']
      name = each['Tags'][0]['Value']
      ins_id = each['InstanceId'] 
      pub_ip = each['PublicIpAddress']
      break

    bootstrap = {'pub_ip': pub_ip,'key':key, 'fqdn':fqdn,'name':name, 'ins_id':ins_id}
    all_bootstraps.append(bootstrap)
  print all_bootstraps
  return all_bootstraps


def run_master_test(ssh_data_file,controls):
  if os.path.isfile(ssh_data_file):
    ssh_info = json.load(open(ssh_data_file))
    os.chdir("/opt/mu/lib/test")
    cmd = "inspec exec mu-master-test --controls=%s -t ssh://root@%s -i %s" % (controls, ssh_info[0]['fqdn'],ssh_info[0]['key'])
    exit = os.system(cmd)
  else:
    raise Exception("ssh file does not exist: %s" % ssh_data_file)


def dump_ssh_info(data):
  new_file = open(ssh_data_file,'w')
  json.dump(data, new_file)


def rm_chef_node_json_frm_target(user,host,key,file_to_rm="/tmp/chef_node.json"):
  if user != None and host != None and os.path.isfile(key):
    cmd = "ssh -oStrictHostKeyChecking -i %s %s@%s rm -rf %s" %(key,user,host,file_to_rm)
    exit = os.system(cmd)
    return exit
  else:
    raise Exception("Check user, host and make sure key file exists on this machine")


def ec2_clean_up(ins_ids):
  ec2 = boto3.resource('ec2')
  print "*********************************************"
  print "INFO: CLEANED UP: %s" % ins_ids
  print "*********************************************"
  ec2.instances.filter(InstanceIds=ins_ids).terminate()  
  termination_wait(ins_ids)

def termination_wait(ins_ids):
  ec2 = boto3.client('ec2')
  wait = ec2.get_waiter('instance_terminated')
  wait.wait(InstanceIds=ins_ids)


######## Main 
instance_ids = []
instance_ids.append(create_instance())
eip_id = allocat_associate_eip(instance_ids[0])
controls = base_controls()
controls_spaced_out = ' '.join(controls)
data = desc_instances(instance_ids)
dump_ssh_info(data)

if os.path.isfile(ssh_data_file):
  ssh_info = json.load(open(ssh_data_file))    
  run_installer_over_ssh('root',ssh_info[0]['fqdn'],ssh_info[0]['key'],'sh /tmp/installer')
  run_master_test(ssh_data_file, controls_spaced_out) 
  rm_chef_node_json_frm_target('root',ssh_info[0]['fqdn'],ssh_info[0]['key'])
  cleanup_ids = []
  for each in ssh_info:
    cleanup_ids.append(each['ins_id']) 
  ec2_clean_up(cleanup_ids)
  release_eip(eip_id)
else:
  print("Nothing to do! Instance Data file does not exists: %s" % ssh_data_file)


#os.system("rm -rf "+ssh_data_file)
