#
# Cookbook Name:: tomcat
# Recipe:: default
#
# Copyright 2010-2015, Chef Software, Inc.
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

if node['tomcat']['install_method'] == 'package'
  def package_installation
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

  case node['platform']
    when 'centos', 'redhat'
      if node['platform_version'].to_i == 6
        if node['tomcat']['base_version'].to_i == 6
          package_installation
        elsif node['tomcat']['base_version'].to_i == 7
          remote_file "#{Chef::Config[:file_cache_path]}/tomcat7-7.0.57-1.x86_64.rpm" do
            source node['tomcat']['package_url']
          end

          package 'tomcat7' do
            source "#{Chef::Config[:file_cache_path]}/tomcat7-7.0.57-1.x86_64.rpm"
          end
        else
          Chef::Log.info("Tomcat package version #{node['tomcat']['base_version'].to_i} not supported on #{node['platform']} #{node['platform_version'].to_i} ")
        end
      elsif node['platform_version'].to_i == 7
        package_installation
      end
    when 'windows'
      Chef::Log.info("Tomcat package installation not supported on #{node['platform']}")
    else
      package_installation
  end

elsif node['tomcat']['install_method'] == 'archive'
  case node['platform']
    when "windows"
      windows_zipfile node.tomcat.home do
        source node['tomcat']['archive_url']
        action :unzip
        not_if { File.exists?("#{node.tomcat.home}\\conf") }
        not_if { File.exists?("#{node.tomcat.home}\\#{node.tomcat.version}\\conf") }
      end

      execute "powershell -Command \"& {robocopy #{node.tomcat.home}\\#{node.tomcat.version} #{node.tomcat.home} /e /move}\"" do
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
      group node['tomcat']['group']

      user node['tomcat']['user'] do
        gid node['tomcat']['group']
        shell '/bin/false'
      end

      tomcat_archive_path = "#{Chef::Config[:file_cache_path]}/tomcat#{node['tomcat']['base_version'].to_i}.tar.gz"
      tomcat_temp_path = "#{Chef::Config[:file_cache_path]}/tomcat#{node['tomcat']['base_version'].to_i}"

      remote_file tomcat_archive_path do
        source node['tomcat']['archive_url']
      end

      directory tomcat_temp_path

      execute "tar xfz #{tomcat_archive_path} -C #{tomcat_temp_path} --strip-components=1" do
        not_if { Dir.exists?("#{tomcat_temp_path}/bin") }
      end

      [node['tomcat']['home'], node['tomcat']['base'], node['tomcat']['config_dir'], node['tomcat']['log_dir'], node['tomcat']['tmp_dir'], node['tomcat']['work_dir'], node['tomcat']['context_dir'],
       node['tomcat']['webapp_dir'], node['tomcat']['lib_dir'], node['tomcat']['endorsed_dir'], "#{node['tomcat']['home']}/bin", "#{node['tomcat']['home']}/temp", "#{node['tomcat']['home']}/work"].each { |dir|
        directory dir do
          owner node['tomcat']['user']
          group node['tomcat']['group']
          mode 0755
          recursive true
        end
      }

      execute "cp #{tomcat_temp_path}/conf/* #{node['tomcat']['config_dir']}" do
        not_if { File.exists?("#{node['tomcat']['config_dir']}/server.xml") }
        only_if { File.exists?("#{tomcat_temp_path}/conf/server.xml") }
      end

      execute "cp #{tomcat_temp_path}/bin/* #{node['tomcat']['base']}/bin" do
        not_if { File.exists?("#{node['tomcat']['base']}/bin/catalina.sh") }
        only_if { File.exists?("#{tomcat_temp_path}/bin/catalina.sh") }
      end

      execute "cp #{tomcat_temp_path}/lib/* #{node['tomcat']['base']}/lib" do
        not_if { File.exists?("#{node['tomcat']['base']}/lib/tomcat-util.jar") }
        only_if { File.exists?("#{tomcat_temp_path}/lib/tomcat-util.jar") }
      end

      execute "cp -r #{tomcat_temp_path}/webapps/* #{node['tomcat']['webapp_dir']}" do
        not_if { Dir.exists?("#{node['tomcat']['webapp_dir']}/ROOT") }
        only_if { Dir.exists?("#{tomcat_temp_path}/webapps/ROOT") }
      end

      execute "find #{node['tomcat']['base']} -type d -exec chmod 755 {} +; find #{node['tomcat']['base']} -type f -exec chmod 644 {} +; chown -R #{node['tomcat']['user']}:#{node['tomcat']['group']} #{node['tomcat']['base']} #{node['tomcat']['config_dir']}" do
        returns [0, 1]
      end

      execute "find #{node['tomcat']['base']}/bin -type f -name '*.sh' -exec chmod 755 {} +" do
        returns [0, 1]
      end

      link "#{node['tomcat']['home']}/logs" do
        to node['tomcat']['log_dir']
      end

      link "#{node['tomcat']['home']}/conf" do
        to node['tomcat']['config_dir']
      end

      template "/etc/logrotate.d/#{node['tomcat']['base_instance']}" do
        source "logrotate.erb"
        mode 0644
      end

      template "/etc/rc.d/init.d/#{node['tomcat']['base_instance']}" do
        source "initd.erb"
        mode 0755
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

node.set_unless['tomcat']['keystore_password'] = secure_password
node.set_unless['tomcat']['truststore_password'] = secure_password
node.save

def create_service(instance)
  service instance do
    case node['platform_family']
    when 'rhel', 'fedora'
      service_name instance
      supports restart: true, status: true
    when 'debian'
      service_name instance
      supports restart: true, reload: false, status: true
    when 'suse'
      service_name 'tomcat'
      supports restart: true, status: true
      init_command '/usr/sbin/rctomcat'
    when 'smartos'
      # SmartOS doesn't support multiple instances
      service_name 'tomcat'
      supports restart: false, reload: false, status: true
    else
      service_name instance
    end
    action [:start, :enable]
    notifies :run, "execute[wait for #{instance}]", :immediately
    retries 4
    retry_delay 30
  end
end

if node['tomcat']['run_base_instance']
  tomcat_instance 'base' do
    port node['tomcat']['port']
    proxy_port node['tomcat']['proxy_port']
    proxy_name node['tomcat']['proxy_name']
    secure node['tomcat']['secure']
    scheme node['tomcat']['scheme']
    ssl_port node['tomcat']['ssl_port']
    app_base node['tomcat']['app_base']
    ssl_proxy_port node['tomcat']['ssl_proxy_port']
    ajp_port node['tomcat']['ajp_port']
    ajp_redirect_port node['tomcat']['ajp_redirect_port']
    shutdown_port node['tomcat']['shutdown_port']
  end
  instance = node['tomcat']['base_instance']
  create_service(instance)
end

node['tomcat']['instances'].each do |name, attrs|
  tomcat_instance name do
    port attrs['port']
    proxy_port attrs['proxy_port']
    proxy_name attrs['proxy_name']
    secure attrs['secure']
    scheme attrs['scheme']
    ssl_port attrs['ssl_port']
    ssl_proxy_port attrs['ssl_proxy_port']
    ajp_port attrs['ajp_port']
    ajp_redirect_port attrs['ajp_redirect_port']
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
    client_auth attrs['client_auth']
    user attrs['user']
    group attrs['group']
    home attrs['home']
    base attrs['base']
    tmp_dir attrs['tmp_dir']
    lib_dir attrs['lib_dir']
    endorsed_dir attrs['endorsed_dir']
    ajp_packetsize attrs['ajp_packetsize']
    uriencoding attrs['uriencoding']
    jndi_connections attrs['jndi_connections']
    jndi attrs['jndi']
    cors_enabled attrs['cors_enabled']
    redirect_http_to_https attrs['redirect_http_to_https']
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

  instance = "#{node['tomcat']['base_instance']}-#{name}"
  create_service(instance)
end

execute "wait for #{instance}" do
  command 'sleep 5' if node.platform_family != 'windows'
  command 'powershell -Command "& {sleep 5}"' if node.platform_family == 'windows'
  action :nothing
end
