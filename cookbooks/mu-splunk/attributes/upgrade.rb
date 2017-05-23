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

default['splunk']['preferred_version'] = "6.6.0"

if node['splunk']['upgrade_enabled']
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
end
