#
# Cookbook Name:: mu-tools
# Recipe:: join_activedirectory_domain
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

if !platform_family?("windows")
	Chef::Log.info "I don't know how to set up an Active Directory Domain Controller when not in Windows"
else
	domain_exists = nil
	if !node.deployment.activedirectory_domain_created.nil?
		domain_exists = node.deployment.activedirectory_domain_created
	end rescue NoMethodError

	dc_ips = []
	node.deployment.servers.ad.each_pair { |name, data|
		if data['activedirectory_dc_initialized'] and !data['private_ip_address'].nil? and !data['private_ip_address'].empty?
			dc_ips << data['private_ip_address']
		end
	} rescue NoMethodError
	if dc_ips.size == 0
		dc_ips << node.ipaddress
	end
	include_recipe 'chef-vault'
	domain_admin = chef_vault_item("activedirectory", "domain_admin")

	cap_tools_active_directory_domain node['ad']['dns_name'] do
		action :join
		netbios_name node['ad']['netbios_name']
		domain_admin_user domain_admin['username']
		domain_admin_password domain_admin['password']
		safe_mode_pw domain_admin['password']
		computer_name node['ad']['computer_name']
		existing_dc_ips dc_ips
	end

end
