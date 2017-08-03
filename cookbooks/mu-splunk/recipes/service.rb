#
# Cookbook Name:: splunk
# Recipe:: service
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

myuser = 'root'
unless node['splunk']['server']['runasroot']
  myuser = node['splunk']['user']['username']
end

if node['splunk']['is_server']
  directory splunk_dir do
    owner myuser
    group myuser
    mode 00755
  end

  directory "#{splunk_dir}/var" do
    owner node['splunk']['user']['username']
    group node['splunk']['user']['username']
    mode 00711
  end

  directory "#{splunk_dir}/var/log" do
    owner node['splunk']['user']['username']
    group node['splunk']['user']['username']
    mode 00711
  end

  directory "#{splunk_dir}/var/log/splunk" do
    owner node['splunk']['user']['username']
    group node['splunk']['user']['username']
    mode 00700
  end
end

if node['splunk']['accept_license'] and node['platform_family'] != 'windows'
  execute "#{splunk_cmd} enable boot-start --accept-license --answer-yes" do
#    not_if "grep -q -- '--no-prompt --answer-yes' /etc/init.d/splunk"
  end
end


if node['platform_family'] != 'windows'
  if node['splunk']['is_server']
    chown_r_splunk("#{splunk_dir}/etc/users", myuser)
    chown_r_splunk(splunk_dir, myuser)
  end

  template '/etc/init.d/splunk' do
    source 'splunk-init.erb'
    mode 0700
    variables(
        :splunkdir => splunk_dir,
        :runasroot => node['splunk']['server']['runasroot']
    )
  end
end

begin
  resources('service[splunk]')
rescue Chef::Exceptions::ResourceNotFound
  service 'splunk' do
    if node['platform_family'] == 'windows'
      service_name 'SplunkForwarder'
      provider Chef::Provider::Service::Windows
      timeout 90
      retries 3
      retry_delay 10
      supports :status => false, :restart => false
      start_command "c:/Windows/system32/sc.exe start SplunkForwarder"
      stop_command "c:/Windows/system32/sc.exe stop SplunkForwarder"
      pattern "splunkd.exe"
    else
      provider Chef::Provider::Service::Init
      supports :status => true, :restart => true
    end
    action :start
  end
end
