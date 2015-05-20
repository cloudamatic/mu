#
# Cookbook Name:: mu-jenkins
# Recipe:: default
#
# Copyright 2015, eGlobalTech, Inc
#
# All rights reserved - Do Not Redistribute
#

case node.platform
when "centos", "redhat"
	include_recipe 'chef-vault'

	vault_item = chef_vault_item('jenkins', 'ssh_keys')

	ssh_authorized_keys = "/root/.ssh/authorized_keys" if node.platform_version.to_i == 6
	ssh_authorized_keys = "/home/centos/.ssh/authorized_keys" if node.platform_version.to_i == 7

	execute "echo '#{vault_item['public_key'].strip}' >> #{ssh_authorized_keys}" do
		not_if "grep '^#{vault_item['public_key'].strip}$' #{ssh_authorized_keys}"
	end
else
	Chef::Log.info("Unsupported platform #{node.platform}")
end
