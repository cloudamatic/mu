#
# Cookbook Name:: mu_wordpress
# Recipe:: wp-cli
#
# Copyright 2015, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#


case node[:platform_family]

include_recipe "apache2"
include_recipe "php"

$git_repo_name=node['mu_wordpress']['global']['git_repo_name']
$database=node['deployment']['databases']
$loadbalancer=node['deployment']['loadbalancers']
$lb_url=$loadbalancer['mu-wordpress-lb']['dns'].downcase
$db_name=node['mu_wordpress']['global']['db_name']
$db_host=$database['mu-wordpress-db']['endpoint']
$db_user=$database['mu-wordpress-db']['username']
$db_password=$database['mu-wordpress-db']['password']

when "rhel"	

execute "yum -y install php-mbstring" do
action :run
end




when "debian"

include_recipe "apache2::mod_php5"

execute "apt-get -y install php-mbstring" do
action :run
end

bash "Create mysql database in RDS" do
	user "root"
	code <<-EOH
		mysql -h #{$db_host} -u #{$db_user} -p#{$db_password} -e "CREATE DATABASE IF NOT EXISTS #{$db_name};"
	EOH
end



else

 raise '#{node[:platform_family]} not supported'

end 
