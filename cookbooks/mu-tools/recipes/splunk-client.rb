#
# Cookbook Name:: mu-tools
# Recipe:: splunk-client
#
# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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

include_recipe "mu-splunk::client"

if node['splunk']['discovery'] == "groupname"
  splunk_servers = search(
      :node,
      "splunk_is_server:true AND splunk_groupname:#{node['splunk_groupname']}"
  ).sort! do
  |a, b|
    a.name <=> b.name
  end
else
  splunk_servers = search(# ~FC003
      :node,
      "splunk_is_server:true AND chef_environment:#{node.chef_environment}"
  ).sort! do
  |a, b|
    a.name <=> b.name
  end
end

splunk_auth_info = chef_vault_item(node['splunk']['auth']['data_bag'], node['splunk']['auth']['data_bag_item'])['auth']
user, pw = splunk_auth_info.split(':')

if node['platform_family'] != "windows"
  deploy_guard = "#{splunk_dir}/etc/.setup_deploy_poll"
  file deploy_guard do
    content 'true\n'
    owner 'root'
    group 'root'
    mode 00600
    action :nothing
  end
else
  deploy_guard = "#{splunk_dir}/etc/setup_deploy_poll"
  file deploy_guard do
    content 'true\n'
    action :nothing
  end
end

deploy_svr = splunk_servers.first
if !deploy_svr.nil?
  execute 'Splunk client poll for deploy server' do
    command "\"#{splunk_cmd}\" set deploy-poll #{deploy_svr['splunk']['receiver_ip']}:8089 -auth #{user}:#{pw}"
    not_if { ::File.exist?(deploy_guard) }
    notifies :create, "file[#{deploy_guard}]", :immediately
    notifies :restart, "service[splunk]", :delayed
  end
else
  Chef::Log.info("Configured to run a Splunk client, but no Splunk servers were found.")
end
