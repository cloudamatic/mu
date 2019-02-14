#
# Cookbook Name:: splunk
# Recipe:: upgrade
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

unless node['splunk']['upgrade_enabled']
  Chef::Log.fatal('The mu-splunk::upgrade recipe was added to the node,')
  Chef::Log.fatal('but the attribute `node["splunk"]["upgrade_enabled"]` was not set.')
  Chef::Log.fatal('I am bailing here so this node does not upgrade.')
  raise
end

service 'splunk_stop' do
  if node['platform_family'] != 'windows'
    service_name 'splunk'
    provider Chef::Provider::Service::Init
    only_if { ::File.exist?("/etc/init.d/splunk") }
  else
    service_name 'SplunkForwarder'
    provider Chef::Provider::Service::Windows
    timeout 90
    retries 3
    retry_delay 10
    supports :status => false, :restart => false
    start_command "c:/Windows/system32/sc.exe start SplunkForwarder"
    stop_command "c:/Windows/system32/sc.exe stop SplunkForwarder"
    pattern "splunkd.exe"
    only_if { ::Dir.exist?("c:/Program Files/SplunkUniversalForwarder") }
    not_if { ::Dir.glob("c:/Program Files/SplunkUniversalForwarder/splunkforwarder-#{node['splunk']['preferred_version']}-*").size > 0 }
  end
  supports :status => true
  action :stop
end

if node['platform_family'] == 'windows'
  # Splunk can't seem to upgrade itself in some cases if we don't explicitly
  # purge the old installation.
  powershell_script "Purge old versions of Splunk Universal Forwarder" do
    guard_interpreter :powershell_script
    code <<-EOH
      wmic product get /format:csv | findstr /i UniversalForwarder | findstr /i /v splunkforwarder-#{node['splunk']['preferred_version']}- | foreach {
        $fields = $_.split(",")
        $arg1 = "/x"+$fields[6]
        $arg2 = "/quiet"
        msiexec $arg1 $arg2
      }
    EOH
    not_if { ::Dir.glob("c:/Program Files/SplunkUniversalForwarder/splunkforwarder-#{node['splunk']['preferred_version']}-*").size > 0 }
    only_if { ::Dir.exist?("c:/Program Files/SplunkUniversalForwarder") }
  end
end



if node['splunk']['is_server']
  splunk_package = 'splunk'
  url_type = 'server'
else
  splunk_package = 'splunkforwarder'
  url_type = 'forwarder'
end

splunk_installer splunk_package do
  url node['splunk'][url_type]["url"]
  if node['splunk']['accept_license']
    notifies :run, "execute[splunk-unattended-upgrade]", :immediately
  end
end

if node['splunk']['accept_license']
  execute 'splunk-unattended-upgrade' do
    command "\"#{splunk_cmd}\" start --accept-license --answer-yes"
    action :nothing
  end
else
  Chef::Log.fatal('You did not accept the license (set node["splunk"]["accept_license"] to true)')
  Chef::Log.fatal('Splunk is stopped and cannot be restarted until the license is accepted!')
  raise
end
