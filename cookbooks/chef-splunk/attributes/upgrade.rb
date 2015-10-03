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
if node['splunk']['upgrade_enabled']
  case node['platform_family']
    when 'rhel'
      if node['kernel']['machine'] == 'x86_64'
        default['splunk']['forwarder']['url'] = 'http://download.splunk.com/releases/6.3.0/universalforwarder/linux/splunkforwarder-6.3.0-aa7d4b1ccb80-linux-2.6-x86_64.rpm'
        default['splunk']['server']['url'] = 'http://download.splunk.com/releases/6.3.0/splunk/linux/splunk-6.3.0-aa7d4b1ccb80-linux-2.6-x86_64.rpm'
      else
        default['splunk']['forwarder']['url'] = 'http://download.splunk.com/releases/6.3.0/universalforwarder/linux/splunkforwarder-6.3.0-aa7d4b1ccb80.i386.rpm'
        default['splunk']['server']['url'] = 'http://download.splunk.com/releases/6.3.0/splunk/linux/splunk-6.3.0-aa7d4b1ccb80.i386.rpm'
      end
    when 'debian'
      if node['kernel']['machine'] == 'x86_64'
        default['splunk']['forwarder']['url'] = 'http://download.splunk.com/releases/6.3.0/universalforwarder/linux/splunkforwarder-6.3.0-aa7d4b1ccb80-linux-2.6-amd64.deb'
        default['splunk']['server']['url'] = 'http://download.splunk.com/releases/6.3.0/splunk/linux/splunk-6.3.0-aa7d4b1ccb80-linux-2.6-amd64.deb'
      else
        default['splunk']['forwarder']['url'] = 'http://download.splunk.com/releases/6.3.0/universalforwarder/linux/splunkforwarder-6.3.0-aa7d4b1ccb80-linux-2.6-intel.deb'
        default['splunk']['server']['url'] = 'http://download.splunk.com/releases/6.3.0/splunk/linux/splunk-6.3.0-aa7d4b1ccb80-linux-2.6-intel.deb'
      end
    when 'omnios'
      default['splunk']['forwarder']['url'] = 'http://download.splunk.com/releases/6.3.0/universalforwarder/solaris/splunkforwarder-6.3.0-aa7d4b1ccb80-solaris-10-intel.pkg.Z'
      default['splunk']['server']['url'] = 'http://download.splunk.com/releases/6.3.0/splunk/solaris/splunk-6.3.0-aa7d4b1ccb80-solaris-10-intel.pkg.Z'
    when 'windows'
      if node['kernel']['machine'] == 'x86_64'
        default['splunk']['forwarder']['url'] = 'http://download.splunk.com/releases/6.3.0/universalforwarder/windows/splunkforwarder-6.3.0-aa7d4b1ccb80-x64-release.msi'
        default['splunk']['server']['url'] = 'http://download.splunk.com/releases/6.3.0/splunk/windows/splunk-6.3.0-aa7d4b1ccb80-x64-release.msi'
      else
        default['splunk']['forwarder']['url'] = 'http://download.splunk.com/releases/6.3.0/universalforwarder/windows/splunkforwarder-6.3.0-aa7d4b1ccb80-x86-release.msi'
        default['splunk']['server']['url'] = 'http://download.splunk.com/releases/6.3.0/splunk/windows/splunk-6.3.0-aa7d4b1ccb80-x86-release.msi'
      end
  end
end
