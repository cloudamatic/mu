#
# Cookbook Name:: nginx
# Recipe:: default
#


%w{ nginx nginx-light nginx-full nginx-extras }.each do |pkg|
  package pkg do
    action :remove
  end
end

# Install nginx-common (contains the init-scripts) and packages needed for compilation
%w{ nginx-common build-essential libcurl4-openssl-dev libssl-dev zlib1g-dev libpcre3-dev }.each do |pkg|
  package pkg
end


remote_file 'download nginx' do
  action :create_if_missing
  owner 'root'
  group 'root'
  mode '0644'
  path "/usr/src/nginx-#{node['nginx']['version']}.tar.gz"
  source "http://nginx.org/download/nginx-#{node['nginx']['version']}.tar.gz"
end

execute 'extract nginx' do
  command "tar xvfz nginx-#{node['nginx']['version']}.tar.gz"
  cwd '/usr/src'
  not_if do
    File.directory? "/usr/src/nginx-#{node['nginx']['version']}"
  end
end

# Install passenger
bash "install passenger" do
  user "root"
  code <<-EOH
          gem install passenger -v 4.0.37

          passenger-install-nginx-module  --auto --prefix=/etc/nginx-1.4.4 --nginx-source-dir=/usr/src/nginx-1.4.4 --extra-configure-flags='--with-ipv6 --with-http_realip_module'
  EOH
end


# Setup nginx environment
link '/usr/sbin/nginx' do
  to "/etc/nginx-1.4.4/sbin/nginx"
end

link '/etc/nginx/logs' do
  to '/var/log/nginx'
end

# Configuration files
template '/etc/default/nginx' do
  owner 'root'
  group 'root'
  mode '0644'
  source 'nginx.erb'
  notifies :reload, "service[nginx]"
end

template '/etc/nginx/nginx.conf' do
  owner 'root'
  group 'root'
  mode '0644'
  source 'nginx.conf.erb'
  notifies :reload, "service[nginx]"
end

service "nginx" do
  supports :status => true, :restart => true, :reload => true
  action [:enable, :start]
end



