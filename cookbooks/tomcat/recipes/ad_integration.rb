#
# Cookbook Name:: tomcat
# Recipe:: ad_integration
#
# Copyright 2015, eGlobalTech
#
# All rights reserved - Do Not Redistribute
#

include_recipe 'chef-vault'
node.normal.tomcat.ldap_enabled = true
# auth_info = chef_vault_item("activedirectory", "tomcat_svc")

template "#{node.tomcat.webapp_dir}/manager/WEB-INF/web.xml" do
  source "manager_web.xml.erb"
  owner 'tomcat'
  group 'tomcat'
  mode 0644
  variables(
      :ad_group => node.tomcat.ldap_group
  )
end
