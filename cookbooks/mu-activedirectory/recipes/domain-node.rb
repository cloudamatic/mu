#
# Cookbook Name:: mu-activedirectory
# Recipe:: domain-node
#
# Copyright 2015, eGlobalTech,
#
# All rights reserved - Do Not Redistribute
#

include_recipe 'chef-vault'
domain_creds = nil
if node.has_key?('ad') and node['ad'].has_key?('join_auth') and node['ad']['join_auth'].has_key?('vault') and node['ad']['join_auth'].has_key?('item') and !node['ad']['join_auth']['vault'].nil? and !node['ad']['join_auth']['item'].nil?
  domain_creds = chef_vault_item(node['ad']['join_auth']['vault'], node['ad']['join_auth']['item'])
end
can_join_domain = false

case node['platform']
  when "windows"
    ::Chef::Recipe.send(:include, Chef::Mixin::PowershellOut)

    require 'chef/win32/version'
    version = Chef::ReservedNames::Win32::Version.new

    if version.windows_server_2012? || version.windows_server_2012_r2? || version.windows_server_2016?
      can_join_domain = true
    else
      Chef::Log.info "Requires Windows Server 2012, 2012R2 or windows_server_2016"
    end
  when platform_family?('rhel')
    if node['platform_version'].to_i >= 6
      can_join_domain = true # just winbind, really
      include_recipe "mu-activedirectory::sssd"
    else
      Chef::Log.info "Requires CentOS/RedHat 6/7. Current version is #{node['platform']} #{node['platform_version'].to_i}"
    end
  else
    Chef::Log.info("Unsupported platform #{node['platform']}")
end

if can_join_domain and !domain_creds.nil?
  mu_activedirectory_domain_node node['ad']['domain_name'] do
    netbios_name node['ad']['netbios_name']
    computer_name node['ad']['computer_name']
    join_user domain_creds[node['ad']['join_auth']['username_field']]
    join_password domain_creds[node['ad']['join_auth']['password_field']]
    computer_ou node['ad']['computer_ou'] if node['ad']['computer_ou']
    dc_ips node['ad']['dc_ips']
    dc_names node['ad']['dcs']
  end
end
