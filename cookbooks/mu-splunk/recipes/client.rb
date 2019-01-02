#
# Cookbook Name:: splunk
# Recipe:: client
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
# This recipe encapsulates a completely configured "client" - a
# Universal Forwarder configured to talk to a node that is the splunk
# server (with node['splunk']['is_server'] true). The recipes can be
# used on their own composed in your own wrapper cookbook or role.
include_recipe 'mu-splunk::user'
include_recipe 'mu-splunk::install_forwarder'

if node['splunk']['discovery'] == 'groupname'
  splunk_servers = search(
      :node,
      "splunk_is_server:true AND splunk_groupname:#{node['splunk_groupname']}"
  ).sort! do
  |a, b|
    a.name <=> b.name
  end
elsif node['splunk']['discovery'] == 'static'
  splunk_servers = [
      { "splunk" =>
        {
          "receiver_port" => node['splunk']['server_port'],
          "receiver_ip" => node['splunk']['server_address']
        }
      }
    ]
else
  splunk_servers = search(# ~FC003
      :node,
      "splunk_is_server:true AND chef_environment:#{node.chef_environment}"
  ).sort! do
  |a, b|
    a.name <=> b.name
  end
end

# ensure that the splunk service resource is available without cloning
# the resource (CHEF-3694). this is so the later notification works,
# especially when using chefspec to run this cookbook's specs.
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

directory "#{splunk_dir}/etc/system/local" do
  recursive true
  if node['platform_family'] != 'windows'
    owner node['splunk']['user']['username']
    group node['splunk']['user']['username']
  end
end

if node['splunk']['splunk_cloud_installer']
  splunk_auth_info = chef_vault_item(node['splunk']['auth']['data_bag'], node['splunk']['auth']['data_bag_item'])['auth']
  user, pw = splunk_auth_info.split(':')
  execute "Install Splunk Cloud app" do
    command "/opt/splunkforwarder/bin/splunk install app #{node['splunk']['install_spl_file']} -auth #{user}:#{pw}"
    not_if "/opt/splunkforwarder/bin/splunk display app | grep ^splunkclouduf"
  end
end

template "#{splunk_dir}/etc/system/local/outputs.conf" do
  source 'outputs.conf.erb'
  mode 0644 unless platform_family?("windows")
  variables :splunk_servers => splunk_servers, :outputs_conf => node['splunk']['outputs_conf'], :ssl_chain => node['splunk']['ssl_chain'], :ssl_cert => node['splunk']['ssl_cert']
#  notifies :restart, 'service[splunk]', :immediately if platform_family?("windows")
  notifies :restart, 'service[splunk]', :delayed #unless platform_family?("windows")
end

template "#{splunk_dir}/etc/system/local/inputs.conf" do
  source 'inputs.conf.erb'
  mode 0644
  variables :inputs_conf => node['splunk']['inputs_conf']
  notifies :restart, 'service[splunk]', :delayed
  not_if { node['splunk']['inputs_conf'].nil? || node['splunk']['inputs_conf']['host'].empty? }
end
if node['platform_family'] != 'windows'
  directory "/opt/splunkforwarder/etc/apps"
  directory "/opt/splunkforwarder/etc/apps/base_logs_unix"
  directory "/opt/splunkforwarder/etc/apps/base_logs_unix/local"
  template "#{splunk_dir}/etc/apps/base_logs_unix/local/inputs.conf" do
    source 'base_logs_unix_inputs.conf.erb'
    mode 0644
    notifies :restart, 'service[splunk]', :delayed
  end
end

include_recipe 'mu-splunk::service'
include_recipe 'mu-splunk::setup_auth'

svr_conf = "#{splunk_dir}/etc/system/local/server.conf"
ruby_block "tighten SSL options in #{svr_conf}" do
  block do
    newfile = []
    File.readlines(svr_conf).each { |line|
      newfile << line
      if line.match(/^\[sslConfig\]/)
        newfile << "useClientSSLCompression = false\n"
        newfile << "sslVersions = tls1.2\n"
        newfile << "cipherSuite = TLSv1.2:!eNULL:!aNULL\n"
      end
    }
    f = File.new(svr_conf, File::CREAT|File::TRUNC|File::RDWR)
    f.puts newfile
    f.close
  end
  not_if "grep ^sslVersions '#{svr_conf}'"
  notifies :restart, 'service[splunk]', :delayed
end
