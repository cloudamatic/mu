#
# Cookbook Name:: mu-jenkins
# Recipe:: jenkins-apache
#
# Copyright 2015, eGlobalTech, Inc
#
# All rights reserved - Do Not Redistribute
#

include_recipe 'mu-utility::iptables'
include_recipe "apache2"
include_recipe "apache2::mod_proxy"
include_recipe "apache2::mod_proxy_http"
include_recipe "chef-vault"

apache_port = node.jenkins_port_external

case node.platform
  when "centos", "redhat"
    admin_vault = chef_vault_item(node.jenkins_admin_vault[:vault], node.jenkins_admin_vault[:item])

    execute "iptables -I INPUT -p tcp --dport #{apache_port} -j ACCEPT; service iptables save" do
      not_if "iptables -nL | egrep '^ACCEPT.*dpt:#{apache_port}($| )'"
    end

    # Upload mu artifacts so jenkins can be a deployer
    execute "runuser -l jenkins -c 'cd #{node.jenkins.master.home} && mu-upload-chef-artifacts -n -r mu'" do
      not_if { node.application_attributes.attribute?('jenkins_chef_initial_upload') }
      notifies :create, 'ruby_block[set-jenkins-initial-chef-artifacts-upload]', :immediately
    end

    ruby_block "set-jenkins-initial-chef-artifacts-upload" do
      block do
        node.normal.application_attributes.jenkins_chef_initial_upload = true
        node.save
      end
      action :nothing
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

    # Adding it here, but it could fail
    ruby_block 'set jenkins private key' do
      block do
        node.run_state[:jenkins_private_key] = admin_vault['private_key'].strip
      end
      only_if { node.application_attributes.attribute?('jenkins_auth') }
    end

=begin
    #Set up our standard Jenkins Jobs
    %w{deploy cleanup_deploy}.each { |job|
      cookbook_file "#{Chef::Config[:file_cache_path]}/#{job}_config.xml" do
        source "#{job}_config.xml"
      end

      jenkins_job job do
        config "#{Chef::Config[:file_cache_path]}/#{job}_config.xml"
      end
    }
=end

    # Now the web app virtual host
    web_app "jenkins" do
      server_name ENV['CHEF_PUBLIC_IP']
      server_aliases [node.fqdn, node.hostname]
      server_admin ENV['MU_ADMIN_EMAIL']
      cookbook "mu-jenkins"
      template "jenkinsvhost.conf.erb"
      apache_port apache_port
      jenkins_port node.jenkins_port_internal
      version node.apache.version
      base_dir node.apache.dir
      log_dir node.apache.log_dir
    end


    # Finally, insert the jenkins_port_external into ports, and save the node
    node.normal.jenkins_port_external = node.jenkins_port_external
    node.normal.apache["listen_ports"] = [80, 8443, node.jenkins_port_external]
    node.save
  else
    Chef::Log.info("Unsupported platform #{node.platform}")
end
