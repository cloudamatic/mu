#
	# Cookbook Name:: mu-activedirectory
# Recipe:: domain-node
#
# Copyright 2015, eGlobalTech,
#
# All rights reserved - Do Not Redistribute
#

include_recipe 'chef-vault'
domain_creds = chef_vault_item(node.ad.join_auth[:vault], node.ad.join_auth[:item])
can_join_domain = false

case node.platform
when "windows"
	::Chef::Recipe.send(:include, Chef::Mixin::PowershellOut)

	require 'chef/win32/version'
	version = Chef::ReservedNames::Win32::Version.new

	if version.windows_server_2012? || version.windows_server_2012_r2?
		can_join_domain = true
	else
		Chef::Log.info "Requires Windows Server 2012 or 2012R2, current version is #{version})"
	end
when "centos", "redhat"
	if node.platform_version.to_i >= 6
		can_join_domain = true
	else
		Chef::Log.info "Requires CentOS/RedHat 6/7. Current version is #{node.platform} #{node.platform_version.to_i}"
	end
else
	Chef::Log.info("Unsupported platform #{node.platform}")
end

if can_join_domain
	mu_activedirectory_domain_node node.ad.domain_name do
		netbios_name node.ad.netbios_name
		computer_name node.ad.computer_name
		join_user domain_creds[node.ad.join_auth[:username_field]]
		join_password domain_creds[node.ad.join_auth[:password_field]]
		ou node.ad.computer_ou if node.ad.computer_ou
		dc_ips node.ad.dc_ips
		dc_names node.ad.dcs
	end
end
