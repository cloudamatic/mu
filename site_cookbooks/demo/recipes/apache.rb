#
# Cookbook Name:: Demo
# Recipe:: apache
#
# Copyright 2015, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#


$database=node['deployment']['databases']
$loadbalancer=node['deployment']['loadbalancers']
$lb_url=$loadbalancer['wordpress-demo-lb']['dns'].downcase
$db_name="wordpress_db"
$db_host=$database['wordpress-demo-db']['endpoint']
$db_user=$database['wordpress-demo-db']['username']
$db_password=$database['wordpress-demo-db']['password']

case node[:platform_family]

  when "rhel"


    bash "prep apache files" do
      user "root"
      code <<-EOH
    rm -rf /etc/httpd/sites-available/
    rm -rf /etc/httpd/sites-enabled/
    mkdir -p /etc/httpd/sites-available/
    mkdir -p /etc/httpd/sites-enabled/
      EOH
    end


    template '/etc/httpd/conf/httpd.conf' do
      owner 'root'
      group 'root'
      mode '0644'
      source "apache/conf/httpd.conf.erb"
    end


    template '/etc/httpd/sites-available/wordpress' do
      owner 'root'
      group 'root'
      mode '0644'
      source "apache/sites-available/wordpress.erb"
      variables({
                    :site_url => $lb_url

                })
    end


    link "/etc/httpd/sites-enabled/wordpress" do
      to "/etc/httpd/sites-available/wordpress"
    end


    service "httpd" do
      action :restart
    end


  when "debian"

    bash "prep apache files" do
      user "root"
      code <<-EOH
    rm -rf /etc/httpd/sites-available/
    rm -rf /etc/httpd/sites-enabled/
    mkdir -p /etc/httpd/sites-available/
    mkdir -p /etc/httpd/sites-enabled/
      EOH
    end


    template '/etc/httpd/conf/httpd.conf' do
      owner 'root'
      group 'root'
      mode '0644'
      source "apache/conf/httpd.conf.erb"
    end


    template '/etc/httpd/sites-available/wordpress' do
      owner 'root'
      group 'root'
      mode '0644'
      source "apache/sites-available/wordpress.erb"
      variables({
                    :site_url => $lb_url

                })
    end


    link "/etc/httpd/sites-enabled/wordpress" do
      to "/etc/httpd/sites-available/wordpress"
    end


    service "apache2" do
      action :restart
    end


  else

    raise '#{node[:platform_family]} not supported'

end 
