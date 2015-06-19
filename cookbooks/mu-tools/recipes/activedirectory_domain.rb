#
# Cookbook Name:: mu-tools
# Recipe:: activedirectory
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
#
# Create an Active Directory Domain Controller

::Chef::Recipe.send(:include, Chef::Mixin::PowershellOut)

if !platform_family?("windows")
	Chef::Log.info "I don't know how to set up an Active Directory Domain Controller when not in Windows"
else
	require 'chef/win32/version'
	version = Chef::ReservedNames::Win32::Version.new

	include_recipe 'chef-vault'
	domain_admin = chef_vault_item("activedirectory", "domain_admin")

	
	cmd = powershell_out("(Get-ADDomainController).name -eq '#{node.ad.computer_name}'")
	cmd.run_command
	if cmd.stdout.match(/True/)
		i_am_a_dc = true
	else
		i_am_a_dc = false
	end

	
	dc_ips = []
	node.deployment.servers[node.ad.node_class].each_pair { |name, data|
		if data['activedirectory_dc_initialized'] and !data['private_ip_address'].nil? and !data['private_ip_address'].empty?
			dc_ips << data['private_ip_address']
		end
	} rescue NoMethodError
	if dc_ips.size == 0
		dc_ips << node.ipaddress
	end
	
	
	first_dc = false
	i_am_first_dc = false
	node.deployment.servers[node.ad.node_class].each_pair { |name, data|
		if data['ad_master']
		first_dc = true
			if name == Chef::Config[:node_name]
				i_am_first_dc = true
			end
		end
	}
	if !first_dc
		node.normal['deployment']['servers'][node.ad.node_class][Chef::Config[:node_name]]['ad_master'] = true
		node.save
		i_am_first_dc = true
	end

	if !version.windows_server_2012? and !version.windows_server_2012_r2?
		Chef::Log.info "Requires Windows Server 2012 or 2012R2 (#{version})"
	elsif i_am_first_dc
		Chef::Log.info "I am first Domain Controller"
		mu_tools_active_directory_domain node['ad']['dns_name'] do
			action :create
			netbios_name node['ad']['netbios_name']
			domain_admin_user domain_admin['username']
			domain_admin_password domain_admin['password']
			safe_mode_pw domain_admin['password']
			site_name node['ad']['site_name']
			computer_name node['ad']['computer_name']
			sites node['ad']['sites']
			existing_dc_ips dc_ips
			ntds_static_port node['ad']['ntds_static_port']
			ntfrs_static_port node['ad']['ntfrs_static_port']
			dfsr_static_port node['ad']['dfsr_static_port']
		end
	else
		mu_tools_active_directory_domain node['ad']['dns_name'] do
			action :add_controller
			netbios_name node['ad']['netbios_name']
			domain_admin_user domain_admin['username']
			domain_admin_password domain_admin['password']
			safe_mode_pw domain_admin['password']
			site_name node['ad']['site_name']
			computer_name node['ad']['computer_name']
			sites node['ad']['sites']
			existing_dc_ips dc_ips
			ntds_static_port node['ad']['ntds_static_port']
			ntfrs_static_port node['ad']['ntfrs_static_port']
			dfsr_static_port node['ad']['dfsr_static_port']
		end
	end

end
