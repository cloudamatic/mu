#
# Cookbook Name:: mu_wordpress
# Recipe:: wp-cli
#
# Copyright 2015, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#


case node[:platform_family]

when "rhel"	






when "debian"



else

 raise '#{node[:platform_family]} not supported'

end 
