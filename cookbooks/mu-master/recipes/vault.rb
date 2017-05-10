# Cookbook Name:: mu-master
# Recipe:: vault
#
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

# This recipe is meant to be invoked standalone, by chef-apply. It can safely
# be invoked during a regular chef-client run.
#
# When modifying this recipe, DO NOT ADD EXTERNAL DEPENDENCIES. That means no
# references to other cookbooks, no include_recipes, no cookbook_files, no
# templates.

include_recipe 'mu-master::firewall-holes'

node.normal['consul']['config']['ca_file'] = "#{$MU_CFG['datadir']}/ssl/Mu_CA.pem"
# local-only is fine for now, but if we ever use the cluster features we'll
# need to get sassy here
#node.normal['consul']['config']['advertise_addr'] = $MU_CFG['public_address']
#node.normal['consul']['config']['advertise_addr_wan'] = $MU_CFG['public_address']
#node.normal['consul']['config']['bind_addr'] = "0.0.0.0"

node.save

include_recipe "consul-cluster"
include_recipe "vault-cluster"

# honestly guys, I shouldn't have to do this
execute "find /opt/vault -type d -exec chmod og+rx {} \\;"
execute "find /opt/consul -type d -exec chmod og+rx {} \\;"
directory "/etc/consul/ssl" do
  owner "consul"
  group "consul"
end
directory "/etc/vault" do
  owner "root"
  mode 0755
end
directory "/etc/vault/ssl" do
  owner "root"
  mode 0755
end
directory "/etc/consul/ssl" do
  owner "root"
  mode 0755
end
directory "/etc/consul/ssl/CA" do
  owner "root"
  mode 0755
end
include_recipe 'chef-vault'

file "/etc/consul/ssl/CA/ca.crt" do
  mode 0644
  content chef_vault_item("secrets", "consul")["ca_certificate"]
end

service "consul" do
  action [:enable, :start]
end
service "vault" do
  action [:enable, :start]
end
