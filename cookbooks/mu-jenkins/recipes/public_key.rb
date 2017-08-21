#
# Cookbook Name:: mu-jenkins
# Recipe:: default
#
# Copyright 2015, eGlobalTech, Inc
#
# All rights reserved - Do Not Redistribute
#

case node[:platform]
  when "centos", "redhat"
    include_recipe 'chef-vault'

    ssh_vault = chef_vault_item(node[:jenkins_ssh_vault][:vault], node[:jenkins_ssh_vault][:item])

    ssh_authorized_keys = "/root/.ssh/authorized_keys" if node[:platform_version].to_i == 6
    ssh_authorized_keys = "/home/centos/.ssh/authorized_keys" if node[:platform_version].to_i == 7

    execute "echo '#{ssh_vault['public_key'].strip}' >> #{ssh_authorized_keys}" do
      not_if "grep '^#{ssh_vault['public_key'].strip}$' #{ssh_authorized_keys}"
    end
  else
    Chef::Log.info("Unsupported platform #{node[:platform]}")
end
