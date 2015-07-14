#
# Cookbook Name:: mu-jenkins
# Recipe:: default
#
# Copyright 2015, eGlobalTech, Inc
#
# All rights reserved - Do Not Redistribute
#

include_recipe 'mu-utility::iptables'
include_recipe "apache2"
include_recipe "apache2::mod_proxy"
include_recipe "apache2::mod_proxy_http"

apache_port = node.jenkins_port_external
jenkins_port = node.jenkins_port_internal

case node.platform
when "centos", "redhat"
  execute "iptables -I INPUT -p tcp --dport #{apache_port} -j ACCEPT; service iptables save" do
    not_if "iptables -nL | egrep '^ACCEPT.*dpt:#{apache_port}($| )'"
  end

  # Set up SELinux for port
  execute "Allow jenkins port for apache" do
    command "/usr/sbin/semanage port -a -t http_port_t -p tcp #{apache_port}"
    not_if "semanage port -l | grep -ci http_port_t.*#{apache_port}"
  end

  #Set up SELinux for HTTPD scripts and modules to connect to the network
  execute "Allow net connect to local for apache" do
    command "/usr/sbin/setsebool -P httpd_can_network_connect on"
    not_if "/usr/sbin/getsebool httpd_can_network_connect | grep -cim1 ^.*on$"
  end

  web_app "jenkins" do
      server_name "localhost"
      server_aliases [ node.fqdn, node.hostname ]
      template "jenkinsvhost.conf.erb"
      variables({
          :apache_port => apache_port,
          :jenkins_port => jenkins_port
      })
  end
else
  Chef::Log.info("Unsupported platform #{node.platform}")
end
