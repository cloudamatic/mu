#
# Cookbook Name:: splunk
# Recipe:: setup_auth
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
include_recipe 'chef-vault'

splunk_auth_info = chef_vault_item(node['splunk']['auth']['data_bag'], node['splunk']['auth']['data_bag_item'])['auth']
user, pw = splunk_auth_info.split(':')


if node['platform_family'] != 'windows'
  guard_path = "#{splunk_dir}/etc/.setup_#{user}_password"
  file "guard setup_#{user}_password" do
    path guard_path
    content 'true\n'
    owner node['splunk']['user']['username']
    group node['splunk']['user']['username']
    mode 00600
    action :nothing
  end
else
  guard_path = "#{splunk_dir}\\etc\\setup_#{user}_password"
  file "guard setup_#{user}_password" do
    path guard_path
    content 'true\n'
    action :nothing
  end
end

execute 'change-admin-user-password-from-default' do
  command "\"#{splunk_cmd}\" edit user #{user} -password '#{pw}' -role admin -auth admin:changeme"
  not_if { ::File.exist?(guard_path) }
  notifies :create, "file[guard setup_#{user}_password]", :immediately
end
