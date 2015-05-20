#
# Cookbook Name:: tomcat
# Recipe:: default
#
# Copyright 2010, Chef Software, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# required for the secure_password method from the openssl cookbook
::Chef::Recipe.send(:include, Opscode::OpenSSL::Password)

if node['tomcat']['base_version'].to_i == 7 and platform_family?('rhel') and node[:platform_version].to_i == 6
  remote_file "#{Chef::Config[:file_cache_path]}/tomcat7-7.0.57-1.x86_64.rpm" do
    source node['tomcat']['package_url']
  end

  package 'tomcat7' do
    source "#{Chef::Config[:file_cache_path]}/tomcat7-7.0.57-1.x86_64.rpm"
  end
elsif platform_family?('windows')
  windows_zipfile node.tomcat.home do
    source node['tomcat']['package_url']
    action :unzip
    not_if { File.exists?("#{node.tomcat.home}\\conf") }
	not_if { File.exists?("#{node.tomcat.home}\\#{node.tomcat.version}\\conf") }
  end
  
  execute "powershell -Command \"& {mv #{node.tomcat.home}\\#{node.tomcat.version}\\* #{node.tomcat.home}}\"" do
    only_if { File.exists?("#{node.tomcat.home}\\#{node.tomcat.version}\\conf") }
  end

  directory "#{node.tomcat.home}\\#{node.tomcat.version}" do
    action :delete
  end

  execute "service install" do
    cwd "#{node.tomcat.home}\\bin"
    not_if "sc qc tomcat#{node.tomcat.base_version} | findstr tomcat#{node.tomcat.base_version}"
  end
else
  node['tomcat']['packages'].each do |pkg|
    package pkg do
      action :install
    end
  end

  node['tomcat']['deploy_manager_packages'].each do |pkg|
    package pkg do
      action :install
    end
  end
end

unless node['tomcat']['deploy_manager_apps']
  directory "#{node['tomcat']['webapp_dir']}/manager" do
    action :delete
    recursive true
  end
  file "#{node['tomcat']['config_dir']}/Catalina/localhost/manager.xml" do
    action :delete
  end
  directory "#{node['tomcat']['webapp_dir']}/host-manager" do
    action :delete
    recursive true
  end
  file "#{node['tomcat']['config_dir']}/Catalina/localhost/host-manager.xml" do
    action :delete
  end
end

node.set['tomcat']['keystore_password'] = secure_password unless node['tomcat']['keystore_password']
node.set['tomcat']['truststore_password'] = secure_password unless node['tomcat']['truststore_password']

if node['tomcat']['run_base_instance']
  tomcat_instance "base" do
    port node['tomcat']['port']
    proxy_port node['tomcat']['proxy_port']
    ssl_port node['tomcat']['ssl_port']
    app_base node['tomcat']['app_base']
    ssl_proxy_port node['tomcat']['ssl_proxy_port']
    ajp_port node['tomcat']['ajp_port']
    shutdown_port node['tomcat']['shutdown_port']
  end
end

node['tomcat']['instances'].each do |name, attrs|
  tomcat_instance "#{name}" do
    port attrs['port']
    proxy_port attrs['proxy_port']
    ssl_port attrs['ssl_port']
    ssl_proxy_port attrs['ssl_proxy_port']
    ajp_port attrs['ajp_port']
    shutdown_port attrs['shutdown_port']
    config_dir attrs['config_dir']
    log_dir attrs['log_dir']
    work_dir attrs['work_dir']
    context_dir attrs['context_dir']
    webapp_dir attrs['webapp_dir']
    app_base attrs['app_base']
    catalina_options attrs['catalina_options']
    java_options attrs['java_options']
    use_security_manager attrs['use_security_manager']
    authbind attrs['authbind']
    max_threads attrs['max_threads']
    ssl_max_threads attrs['ssl_max_threads']
    generate_ssl_cert attrs['generate_ssl_cert']
    ssl_cert_file attrs['ssl_cert_file']
    ssl_key_file attrs['ssl_key_file']
    ssl_chain_files attrs['ssl_chain_files']
    keystore_file attrs['keystore_file']
    keystore_type attrs['keystore_type']
    truststore_file attrs['truststore_file']
    truststore_type attrs['truststore_type']
    certificate_dn attrs['certificate_dn']
    loglevel attrs['loglevel']
    tomcat_auth attrs['tomcat_auth']
    user attrs['user']
    group attrs['group']
    home attrs['home']
    base attrs['base']
    tmp_dir attrs['tmp_dir']
    lib_dir attrs['lib_dir']
    endorsed_dir attrs['endorsed_dir']
    jndi_connections attrs['jndi_connections']
    jndi attrs['jndi']
	cors_enabled attrs['cors_enabled']
	ldap_enabled attrs['ldap_enabled']
	ldap_servers attrs['ldap_servers']
	ldap_port attrs['ldap_port']
	ldap_bind_user attrs['ldap_bind_user']
	ldap_bind_pwd attrs['ldap_bind_pwd']
	ldap_user_base attrs['ldap_user_base']
	ldap_role_base attrs['ldap_role_base']
	ldap_domain_name attrs['ldap_domain_name']
	ldap_group attrs['ldap_group']
	ldap_user_search attrs['ldap_user_search']
	ldap_role_search attrs['ldap_role_search']
  end
end
