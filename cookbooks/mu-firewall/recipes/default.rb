#
# Cookbook Name:: mu-firewall
# Recipe:: default
#
# Copyright 2016, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#

if ['rhel', 'amazon'].include? node['platform_version']
    package ['iptables', 'iptables-services']  do
		action :install
		only_if node['firewall']['redhat7_iptables']
	end
end

include_recipe 'firewall'
