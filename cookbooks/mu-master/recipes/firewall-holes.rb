#
# Cookbook Name:: mu-master
# Recipe:: firewall-holes
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

include_recipe 'mu-firewall'

# TODO Move all mu firewall rules to a mu specific chain
firewall_rule "MU Master default ports" do
  port [MU.mommaCatPort, 7443, 8443, 9443, 10514, 443, 80, 25]
end

firewall_rule "Logstash port" do
  port [5044]
  source "10.0.0.0/8"
end

local_chef_ports = [4321, 9463, 9583, 16379, 8983, 8000, 9680, 9683, 9090, 5432]
firewall_rule "Chef Server ports on 127.0.0.1" do
  port local_chef_ports
  source "127.0.0.1/32"
end
local_chef_ports_2 = [5672, 9999, 15672, 25672, 81, 111, 4369, 9463]
firewall_rule "Chef Server ports on 127.0.0.1 (2)" do
  port local_chef_ports_2
  source "127.0.0.1/32"
end
if node.has_key?(:local_ipv4)
  firewall_rule "Chef Server ports on #{node['local_ipv4']}" do
    port local_chef_ports
    source "#{node['local_ipv4']}/32"
  end
end

firewall_rule "Mu Master LDAP ports" do
  port [389, 636] # TODO 389 should probably be local-only
end

firewall_rule "Mu Master Vault ports" do
  port [8200]
end
firewall_rule "Mu Master Consul ports on 127.0.0.1" do
  port [8300, 8301, 8302, 8400, 8500, 8600]
  source "127.0.0.1/32"
end
if node.has_key?(:local_ipv4)
  firewall_rule "Mu Master Consul ports on #{node['local_ipv4']}" do
    port [8300, 8301, 8302, 8400, 8500, 8600]
    source "#{node['local_ipv4']}/32"
  end
end

firewall_rule "Mu Master Jenkins ports on 127.0.0.1" do
  port [8080]
  source "127.0.0.1/32"
end
if node.has_key?(:local_ipv4)
  firewall_rule "Mu Master Jenkins ports on #{node['local_ipv4']}" do
    port [8080]
    source "#{node['local_ipv4']}/32"
  end
end
