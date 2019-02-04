#
# Cookbook Name:: splunk
# Recipe:: server
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
node.default['splunk']['is_server'] = true
include_recipe 'mu-splunk::user'
include_recipe 'mu-splunk::install_server'
include_recipe 'mu-splunk::service'
include_recipe 'mu-splunk::setup_auth'

# We can rely on loading the chef_vault_item here, as `setup_auth`
# above would have failed if there were another issue.
splunk_auth_info = chef_vault_item(node['splunk']['auth']['data_bag'], node['splunk']['auth']['data_bag_item'])['auth']

firewall_rule "HTTP ports for Splunk admin console" do
  port [80, 443]
end

execute 'enable-splunk-receiver-port' do
  command "\"#{splunk_cmd}\" enable listen #{node['splunk']['receiver_port']} -auth '#{splunk_auth_info}'"
  not_if do
    # TCPSocket will return a file descriptor if it can open the
    # connection, and raise Errno::ECONNREFUSED if it can't. We rescue
    # that exception and return false so not_if works proper-like.
    begin
      ::TCPSocket.new(node['ipaddress'], node['splunk']['receiver_port'])
    rescue Errno::ECONNREFUSED
      false
    end
  end
end
firewall_rule "Splunk receiver port(s)" do
  port [node['splunk']['receiver_port'].to_i, 8089]
end

if node['splunk']['ssl_options']['enable_ssl']
  include_recipe 'mu-splunk::setup_ssl'
end
