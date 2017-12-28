#
# Cookbook Name:: demo
# Recipe:: wp-web
#
# Copyright 2014, eGlobalTech
#
# All rights reserved - Do Not Redistribute
#
include_recipe 'chef-vault'
include_recipe "apache2::mod_proxy"
include_recipe "apache2::mod_proxy_http"
include_recipe "apache2::mod_expires"
include_recipe "apache2::mod_deflate"
include_recipe "apache2::mod_ssl"
include_recipe "apache2::mod_php5"
include_recipe "apache2::mod_cgi"

# Fetch important values from node
$database=node['deployment']['databases'].first.last.first.last
$loadbalancer=node['deployment']['loadbalancers']
$lb_url=$loadbalancer['lb']['dns'].downcase
$db_schema_name="wordpress_db"
$db_user=$database.username
$db_password=chef_vault_item($database.vault_name, $database.vault_item)[$database.password_field]
$db_endpoint=$database.endpoint
$loadbalancer=node['deployment']['loadbalancers']
$app_url=$loadbalancer['lb']['dns'].downcase
$title="mu wordpress demo"
$admin_user="admin"
$admin_password="admin"
$admin_email="admin@example.com"

package "php-mysql"
package "mysql"

# Create the db if brand new
bash "Create mysql database in RDS" do
  user "root"
  code <<-EOH
                mysql -h #{$db_endpoint} -u #{$db_user} -p#{$db_password} -e "CREATE DATABASE IF NOT EXISTS #{$db_schema_name};"
  EOH
end

# The apache2 cookbook doesn't support mod_ext_filter for some reason, but it
# comes with the package, so that's easy enough.
link "/etc/httpd/mods-enabled/ext_filter.load" do
  to "/etc/httpd/mods-available/ext_filter.load"
  notifies :reload, "service[apache2]", :delayed
end
=begin
cookbook_file "/etc/fema_banner.html" do
        source "fema_banner.html"
        mode "0644"
end
=end

remote_file "#{Chef::Config[:file_cache_path]}/wordpress.tar.gz" do
  source "http://wordpress.org/latest.tar.gz"
  if node.deployment.environment == 'dev'
    notifies :run, "execute[install latest Wordpress]", :immediately
  end
end

execute "install latest Wordpress" do
  command "tar --strip-components=1 -xzf #{Chef::Config[:file_cache_path]}/wordpress.tar.gz"
  cwd "/var/www/html"
  not_if { ::File.exists?("/var/www/html/wp-config.php") }
end

# Install heartbeat for ELB
template '/var/www/html/heartbeat.php' do
  owner 'root'
  group 'root'
  mode '0644'
  source "heartbeat.php.erb"
end

# Install .htaccess for redirects
template '/var/www/html/.htaccess' do
  owner 'root'
  group 'root'
  mode '0644'
  source "wp-htaccess.erb"
end

execute "chown -R apache:apache /var/www/html"

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
            service iptables restart
    EOH
  end
}

#include_recipe 'chef-vault'
#dbpass = chef_vault_item("wordpress", "dbpass")['password']

template "/var/www/html/wp-config.php" do
  source "wp-config.php.erb"
  variables(
      :dbname => $db_schema_name,
      :dbuser => $db_user,
      :dbpass => $db_password,
      :dbhost => $db_endpoint,
      :dbport => 3306
  )
  mode 0644
  sensitive true
end

=begin
femadata_cert_auth_info = chef_vault_item("certs", ".femadata.crt")
femadata_cert_key_auth_info = chef_vault_item("certs", ".femadata.key")

file "/etc/httpd/ssl/femadata.crt" do
        content femadata_cert_auth_info['file-content']
        mode 0600
        sensitive true
        notifies :reload, "service[apache2]", :delayed
end
file "/etc/httpd/ssl/femadata.key" do
        content femadata_cert_key_auth_info['file-content']
        mode 0600
        sensitive true
        notifies :reload, "service[apache2]", :delayed
end
=end
web_app "wordpress" do
  server_name "www.cloudamatic.com"
  server_aliases [node.fqdn, node.hostname, node.hostname+".cloudamatic.com", $lb_url]
=begin
        if node.deployment.environment == 'dev' or node.deployment.environment == 'development'
                server_aliases [ node.fqdn, node.hostname, node.hostname+".cloudamatic.com", "www.dev.cloudamatic.com", node.ec2.public_ip_address ]
        else
                server_aliases [ node.fqdn, node.hostname, node.hostname+".cloudamatic.com", "cloudamatic.com", node.deployment.loadbalancers.wordpress.dns ]
        end
=end #cookbook "femadata-mgmt"
  docroot "/var/www/html"
  allow_override "All"
  template "wp-vhost.conf.erb"
  notifies :reload, "service[apache2]", :delayed
end
=begin
# Parts and pieces for our LIDAR data S3 browser
remote_file "#{Chef::Config[:file_cache_path]}/ruby-2.1.rpm" do
        action :create
        source "https://s3.amazonaws.com/cap-public/ruby212-2.1.2p205-1.el6.x86_64.rpm"
end

execute "fix perms on Ruby" do
        command "chmod -R 755 /opt/rubies ; chcon -R -h -t httpd_sys_content_t /opt/rubies"
        action :nothing
end

rpm_package "Ruby RPM" do
        source "#{Chef::Config[:file_cache_path]}/ruby-2.1.rpm"
        notifies :run, "execute[fix perms on Ruby]", :immediately
end

gem_package "aws-sdk-core" do
        gem_binary "/opt/rubies/ruby212-2.1.2-p205/bin/gem"
        notifies :run, "execute[fix perms on Ruby]", :immediately
end

directory "/var/www/lidar" do
        mode 0755
end
execute "chcon -h -t httpd_sys_content_t /var/www/lidar"

cookbook_file "/var/www/lidar/index.rb" do
  source "index.rb"
        mode 0755
end
execute "chcon -h -t httpd_sys_content_t /var/www/lidar/index.rb"


web_app "lidar" do
        server_name "lidar.femadata.com"
        server_aliases [ "www.lidar.femadata.com" ]
        directory_index [ "index.rb" ]
        cookbook "femadata-mgmt"
        docroot "/var/www/lidar"
        allow_override "All"
        template "lidar.conf.erb"
        notifies :reload, "service[apache2]", :delayed
end

if node.deployment.environment == 'dev' or node.deployment.environment == 'development'
        include_recipe "femadata-ad::linux"
end
=end

ruby_block "Notify_Users" do
    block do
        puts "\n######################################## End of Run Information ########################################"
        puts "# Your WordPress deploy's loadbalancer is running at http://#{node['deployment']['loadbalancers']['lb']['dns']}"
        puts "########################################################################################################\n\n"
    end
    action :create
end
