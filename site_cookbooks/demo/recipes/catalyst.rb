#
# Cookbook Name:: demo
# Recipe:: catalyst
#
# Copyright 2015, eGlobalTech
#
# All rights reserved - Do Not Redistribute

include_recipe "apache2::mod_ssl"
include_recipe "apache2::mod_proxy"
include_recipe "apache2::mod_proxy_http"
include_recipe "apache2::mod_expires"
include_recipe "apache2::mod_deflate"
include_recipe "chef-vault"

app_dir = "/home/catalyst"

# We use Apache to redirect ports and front things with SSL
execute "setsebool -P httpd_can_network_connect on" do
  not_if "getsebool httpd_can_network_connect | grep ' on$'"
  notifies :reload, "service[apache2]", :delayed
end

[80, 443].each { |port|
  bash "Allow #{port} through iptables" do
    user "root"
    not_if "/sbin/iptables -nL | egrep '^ACCEPT.*dpt:#{port}($| )'"
    code <<-EOH
      iptables -I INPUT -p tcp --dport #{port} -j ACCEPT
      service iptables save
    EOH
  end
}

master = search(:node, 'name:"MU-MASTER"').first
bash "Allow all Mu Master public traffic through iptables" do
  user "root"
  not_if "/sbin/iptables -nL | egrep '^ACCEPT.*#{node.tags['MU-MASTER-IP']}'"
  code <<-EOH
    iptables -I INPUT -p tcp -s #{node.tags['MU-MASTER-IP']} -j ACCEPT
    service iptables save
  EOH
end

bash "Allow all Mu Master private traffic through iptables" do
  user "root"
  not_if "/sbin/iptables -nL | egrep '^ACCEPT.*#{master.ipaddress}'"
  code <<-EOH
    iptables -I INPUT -p tcp -s #{master.ipaddress} -j ACCEPT
    service iptables save
  EOH
end

ssl_cert = chef_vault_item(Chef::Config[:node_name], "ssl_cert")
file "/etc/httpd/ssl/egt-labs-wildcard.crt" do
  content ssl_cert['data']['node.crt']
  mode 0400
end
file "/etc/httpd/ssl/egt-labs-wildcard.key" do
  content ssl_cert['data']['node.key']
  mode 0400
end


github_keys = chef_vault_item("gsa_ssh_keys", "egt-gsa-proto-github")

file "/root/.ssh/egt-gsa-proto-github" do
  content github_keys['private']
  mode 0400
end

file "/root/.ssh/config" do
  content "Host github.com\n  User git\n  IdentityFile /root/.ssh/egt-gsa-proto-github\n"
  mode 0600
end

execute "ssh-keyscan github.com >> ~/.ssh/known_hosts" do
  not_if "grep github.com ~/.ssh/known_hosts"
end

include_recipe 'java'

build_keys = chef_vault_item("gsa_ssh_keys", "egt-gsa-proto-jenkins")
execute "append build key to root's authorized_keys" do
  command "echo '#{build_keys['public']}' >> /root/.ssh/authorized_keys"
  not_if "grep '^#{build_keys['public']}' /root/.ssh/authorized_keys"
end

['nodejs', 'nodejs-devel', 'npm', 'git'].each do |pkg|
  package pkg
end

execute "npm install npm -g -y" do
  not_if "npm -v | grep 2.1.2"
end

['block-stream', 'fstream', 'fstream-ignore', 'fstream-npm', 'glob', 'npmconf', 'tar', 'bower', 'gulp', 'forever'].each do |lib|
  execute "npm install #{lib} -g -y" do
    not_if "npm list -g #{lib} --depth=0 | grep ' #{lib}@'"
  end
end

execute "git clone git@github.com:eGT-Labs/egt-gsa-proto.git #{app_dir}" do
  not_if { File.exists?(app_dir) }
end

template "/etc/rc.d/init.d/egt-fda-catalyst" do
  source "fda-data-init.erb"
  mode '0755'
  owner 'root'
  group 'root'
  variables(:details => { :dir => "/apps/egt-gsa-proto", :service => "eGT FDA Catalyst Engine" })
  notifies :restart, "service[egt-fda-catalyst]", :delayed
end

service "egt-fda-catalyst" do
  action [:start, :enable]
end

web_app "app" do
  server_name "gsa-fda-proto.egt-labs.com"
  server_aliases [ node.fqdn, node.hostname ]
  docroot "/var/www/html"
  cookbook "fda-proto"
  allow_override "All"
  template "appvhost.conf.erb"
end
