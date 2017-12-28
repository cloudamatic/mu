#
# Cookbook Name:: mu_wordpress
# Recipe:: git
#
# Copyright 2015, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#

case node[:platform_family]

  when "rhel"

    bash "install mysql" do
      user "root"
      code <<-EOH
		cd /opt
		wget http://repo.mysql.com/mysql-community-release-el6-5.noarch.rpm
		rpm -ivh mysql-community-release-el6-5.noarch.rpm
		yum -y install mysql-server
		rm -rf mysql-community-release-el6-5.noarch.rpm
		/etc/init.d/mysqld start
      EOH
    end

  when "debian"


  else

    raise '#{node[:platform_family]} not supported'

end
