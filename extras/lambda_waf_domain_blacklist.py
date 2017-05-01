from __future__ import print_function

# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#     http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# This Lambda function reads Elastic Load Balancer and Application Load
# Balancer logs from an S3 bucket, searches for requests whose source IPs
# resolve to domains in our blacklist, and adds matching IPs to a WAF IP
# blacklist named DomListFromLBLogs.
#
# When using this function, you must (in Lambda) define a trigger or triggers
# on the ObjectCreated event in your S3 bucket(s) where Load Balancer logs are
# written.
#
# You must also grant the Lambda function an IAM role or roles that grant it
# GetObject permission to your S3 bucket(s), as well as at least the
# UpdateIPSet permission on the appropriate IPSet in WAF. NB: Our production
# implementation has additional privileges for other uses, so the minimal
# permission set required may be broader than listed here.

import json
import urllib
import boto3
import socket
import re
import gzip

s3 = boto3.client('s3')
waf = boto3.client('waf-regional')

def lookup(addr):
    try:
        return socket.gethostbyaddr(addr)[0]
    except socket.herror:
        return None

# Is a persistent cache across requests possible? That'd be a nice new feature.
# Might have to use ElastiCache if we needed something like that.
results = {}
current_ips = []

blacklist = [
    'adomainidontlike.com',
    'rudeintrusion.ru'
]

def addIPToWAFBlacklist(ip):
    cidr = ip+"/32"
    for ipset in waf.list_ip_sets()['IPSets']:
        if ipset['Name'] == "DomListFromLBLogs":
            if len(current_ips) == 0:
                for desc in waf.get_ip_set(IPSetId=ipset['IPSetId'])['IPSet']['IPSetDescriptors']:
                    current_ips.append(desc['Value'])
            if cidr not in current_ips:
                chtok = waf.get_change_token()['ChangeToken']
                waf.update_ip_set(IPSetId=ipset['IPSetId'], ChangeToken=chtok, Updates=[{'Action': 'INSERT','IPSetDescriptor': {'Type': 'IPV4', 'Value':cidr}}])


def lambda_handler(event, context):
    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.unquote_plus(event['Records'][0]['s3']['object']['key'].encode('utf8'))
    text = ""
    if re.search('\.gz$', key):
        path = key
        while re.search('\/', path):
            path = re.sub('^.*?/', "", path)
        path = '/tmp/' + path
        with open(path, 'wb') as data:
            s3.download_fileobj(bucket, key, data)
        with gzip.open(path, 'rb') as f:
            text = f.read()
    else:
        response = s3.get_object(Bucket=bucket, Key=key)
        text = response['Body'].read()
    for line in text.splitlines():
        fields = line.split()
        ipfield = fields[2]
        # new LBs have a slightly different format
        if(not re.search(':', ipfield)):
            ipfield = fields[3]
        ip, port = ipfield.split(':')
        if ip not in results:
            results[ip] = lookup(ip)
            if results[ip] != None and results[ip] != ".":
                for dom in blacklist:
                    regex = re.compile(r'^.*?\.%s$' % re.escape(dom), re.IGNORECASE)
                    if re.search(regex, results[ip]) or results[ip] == dom:
                        print("Blocking IP "+ip+". Request from '"+results[ip]+"' matched blacklist entry. LB log was: "+key)
                        addIPToWAFBlacklist(ip)
    return True
