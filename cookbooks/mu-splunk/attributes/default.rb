#
# Author: Joshua Timberman <joshua@getchef.com>
# Copyright (c) 2014, Chef Software, Inc <legal@getchef.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Assume default use case is a Universal Forwarder (client).
default['splunk']['accept_license'] = false
default['splunk']['is_server'] = false
default['splunk']['receiver_port'] = '9997'
default['splunk']['web_port'] = '443'
default['splunk']['discovery'] = 'environment'
default['splunk']['user'] = {
    'username' => 'splunk',
    'comment' => 'Splunk Server',
    'home' => '/opt/splunkforwarder',
    'shell' => '/bin/bash',
    'uid' => 396
}

default['splunk']['auth'] = {
    'data_bag' => 'vault',
    'data_bag_item' => "splunk_#{node.chef_environment}"
}


default['splunk']['ssl_options'] = {
    'enable_ssl' => false,
    'data_bag' => 'vault',
    'data_bag_item' => 'splunk_certificates',
    'keyfile' => 'self-signed.example.com.key',
    'crtfile' => 'self-signed.example.com.crt'
}

# Add key value pairs to this to add configuration pairs to the output.conf file
# 'sslCertPath' => '$SPLUNK_HOME/etc/certs/cert.pem'
default['splunk']['outputs_conf'] = {
    'forwardedindex.0.whitelist' => '.*',
    'forwardedindex.1.blacklist' => '_.*',
    'forwardedindex.2.whitelist' => '_audit',
    'forwardedindex.filter.disable' => 'false'
}

# Add a host name if you need inputs.conf file to be configured
# Note: if host is empty the inputs.conf template will not be used.
default['splunk']['inputs_conf']['host'] = ''
default['splunk']['inputs_conf']['ports'] = []

# If the `is_server` attribute is set (via an overridable location
# like a role), then set particular attribute defaults based on the
# server, rather than Universal Forwarder. We hardcode the path
# because we don't want to rely on automagic.
default['splunk']['user']['home'] = '/opt/splunk' if node['splunk']['is_server']

default['splunk']['server']['runasroot'] = true

case node['platform_family']
  when 'rhel'
    if node['kernel']['machine'] == 'x86_64'
      default['splunk']['forwarder']['url'] = 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=6.6.0&product=universalforwarder&filename=splunkforwarder-6.6.0-1c4f3bbe1aea-linux-2.6-x86_64.rpm&wget=true'
      default['splunk']['server']['url'] = 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=6.6.0&product=splunk&filename=splunk-6.6.0-1c4f3bbe1aea-linux-2.6-x86_64.rpm&wget=true'
    else
      default['splunk']['forwarder']['url'] = 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=6.6.0&product=universalforwarder&filename=splunkforwarder-6.6.0-1c4f3bbe1aea.i386.rpm&wget=true'
      default['splunk']['server']['url'] = 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=i386&platform=linux&version=6.6.0&product=splunk&filename=splunk-6.6.0-1c4f3bbe1aea-linux-2.6-i386.rpm&wget=true'
    end
  when 'debian'
    if node['kernel']['machine'] == 'x86_64'
      default['splunk']['forwarder']['url'] = 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=6.6.0&product=universalforwarder&filename=splunkforwarder-6.6.0-1c4f3bbe1aea-linux-2.6-amd64.deb&wget=true'
      default['splunk']['server']['url'] = 'http://download.splunk.com/releases/6.4.1/splunk/linux/splunk-6.6.0-1c4f3bbe1aea-linux-2.6-amd64.deb'
    else
      default['splunk']['forwarder']['url'] = 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=6.6.0&product=universalforwarder&filename=splunkforwarder-6.6.0-1c4f3bbe1aea-linux-2.6-intel.deb&wget=true'
      default['splunk']['server']['url'] = 'http://download.splunk.com/releases/6.4.1/splunk/linux/splunk-6.6.0-1c4f3bbe1aea-linux-2.6-intel.deb'
    end
  when 'omnios'
    default['splunk']['forwarder']['url'] = 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=solaris&version=6.6.0&product=universalforwarder&filename=splunkforwarder-6.6.0-1c4f3bbe1aea-solaris-10-intel.pkg.Z&wget=true'
    default['splunk']['server']['url'] = 'http://download.splunk.com/releases/6.4.1/splunk/solaris/splunk-6.6.0-1c4f3bbe1aea-solaris-10-intel.pkg.Z'
  when 'windows'
    if node['kernel']['machine'] == 'x86_64'
      default['splunk']['forwarder']['url'] = 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=windows&version=6.6.0&product=universalforwarder&filename=splunkforwarder-6.6.0-1c4f3bbe1aea-x64-release.msi&wget=true'
      default['splunk']['server']['url'] = 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=windows&version=6.6.0&product=splunk&filename=splunk-6.6.0-1c4f3bbe1aea-x64-release.msi&wget=true'
    else
      default['splunk']['forwarder']['url'] = 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=windows&version=6.6.0&product=universalforwarder&filename=splunkforwarder-6.6.0-1c4f3bbe1aea-x86-release.msi&wget=true'
      default['splunk']['server']['url'] = 'http://download.splunk.com/releases/6.4.1/splunk/windows/splunk-6.6.0-1c4f3bbe1aea-x86-release.msi'
    end
end
