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

# Mangle a bunch of values used by the Consul and Vault community cookbooks
#node.normal['consul']['config']['bootstrap_expect'] = 1 # XXX we only want this on our first run, maybe figure out how to toss it later
#node.normal['consul']['config']['start_join'] = ["127.0.0.1"]
#node.normal['consul']['config']['ca_file'] = "#{$MU_CFG['datadir']}/ssl/Mu_CA.pem"
#node.normal['consul']['config']['key_file'] = "#{$MU_CFG['datadir']}/ssl/consul.key"
#node.normal['consul']['config']['cert_file'] = "#{$MU_CFG['datadir']}/ssl/consul.crt"
#consul_public = $MU_CFG['public_address']
#if !consul_public.match(/^\d+\.\d+\.\d+\.\d+$/)
#  resolver = Resolv::DNS.new
#  begin
#    consul_public = resolver.getaddress(consul_public).to_s
#  end
#end
## strictly speaking we could split internal vs. external IPs here, but atm
## we're treating everything not local to this machine as public anyway
#node.normal['consul']['config']['advertise_addr'] = consul_public
#node.normal['consul']['config']['advertise_addr_wan'] = consul_public
#node.normal['consul']['config']['bind_addr'] = "0.0.0.0"
#node.normal['consul-cluster']['tls']
#node.normal['hashicorp-vault']['config']['tls_key_file'] = "#{$MU_CFG['datadir']}/ssl/vault.key"
#node.normal['hashicorp-vault']['config']['tls_cert_file'] = "#{$MU_CFG['datadir']}/ssl/vault.crt"
#node.normal['hashicorp-vault']['config']['address'] = '0.0.0.0:8200'
#node.save

#["consul", "vault"].each { |cert|
#  # These community cookbooks aren't bright enough to deal with a stringent
#  # umask, and create these unreadable by the application if we don't do it for
#  # them.
#  directory "fix /opt/#{cert} permissions" do
#    path "/opt/#{cert}"
#    mode 0755
#    notifies :restart, "service[#{cert}]", :delayed
#  end
#}

#include_recipe "consul-cluster"
#include_recipe "vault-cluster"

#["consul", "vault"].each { |cert|
#  file "fix #{cert} cert permissions" do
#    path "#{$MU_CFG['datadir']}/ssl/#{cert}.crt"
#    owner cert
#    notifies :restart, "service[#{cert}]", :delayed
#  end
#  file "fix #{cert} key permissions" do
#    path "#{$MU_CFG['datadir']}/ssl/#{cert}.key"
#    notifies :restart, "service[#{cert}]", :delayed
#    owner cert
#  end
#  }

#directory "/opt/vault/#{node['hashicorp-vault']['version']}" do
#  mode 0755
#  notifies :restart, "service[vault]", :delayed
#end

#directory "/etc/consul/ssl" do
#  owner "consul"
#  group "consul"
#  mode 0755
#end
#directory "/etc/vault" do
#  owner "root"
#  mode 0755
#end
#directory "/etc/vault/ssl" do
#  owner "root"
#  mode 0755
#end
#directory "/etc/consul/ssl/CA" do
#  owner "root"
#  mode 0755
#end
#include_recipe 'chef-vault'

#file "/etc/consul/ssl/CA/ca.crt" do
#  mode 0644
#  content chef_vault_item("secrets", "consul")["ca_certificate"]
#end

#service "consul" do
#  action [:enable, :start]
#end
#service "vault" do
#  action [:enable, :start]
#end
