#
# Cookbook Name:: mu-jenkins
# Recipe:: default
#
# Copyright 2015, eGlobalTech, Inc
#
# All rights reserved - Do Not Redistribute
#

include_recipe 'mu-utility::disable-requiretty'
include_recipe 'mu-utility::iptables'
include_recipe 'chef-vault'
#include_recipe "apache2::mod_proxy"
#include_recipe "apache2::mod_proxy_http"

# Apache setup if indicated
unless node['jenkins_apache_port'].nil?
  jenkins_apache_port = node.jenkins_apache_port
  include_recipe "mu-jenkins::jenkins_apache"
end


admin_vault = chef_vault_item(node.jenkins_admin_vault[:vault], node.jenkins_admin_vault[:item])

case node.platform
when "centos", "redhat"
	%w{node.jenkins_ports}.each { |port|
		execute "iptables -I INPUT -p tcp --dport #{port} -j ACCEPT; service iptables save" do
			not_if "iptables -nL | egrep '^ACCEPT.*dpt:#{port}($| )'"
		end
	}
=begin
	# Set up SELinux for port
	execute "Allow 9443 for apache" do
	command "/usr/sbin/semanage port -a -t http_port_t -p tcp 9443"
	not_if "/usr/sbin/semanage port -l | grep 9443"
	end

	#Set up SELinux for HTTPD scripts and modules to connect to the network
	execute "Allow net connect to local for apache" do
	command "/usr/sbin/setsebool -P httpd_can_network_connect on"
	not_if "/usr/sbin/getsebool httpd_can_network_connect | grep on"
	end


	web_app "jenkins" do
	    server_name "localhost"
	    server_aliases [ node.fqdn, node.hostname ]

	    template "jenkinsvhost.conf.erb"
	end
=end
	%w{git bzip2}.each { |pkg|
		package pkg
	}

	ruby_block 'Use private key for Jenkins auth' do
		block do
			node.run_state[:jenkins_private_key] = admin_vault['private_key'].strip
		end
		only_if { node.application_attributes.attribute?('jenkins_auth') }
	end

	jenkins_user admin_vault['username'] do
		full_name "Admin User"
		email "mu-developers@googlegroups.com"
		public_keys [admin_vault['public_key'].strip]
		notifies :execute, 'jenkins_script[Configure Jenkins auth]', :immediately
	end

	node.jenkins_users.each { |user|
		user_vault = chef_vault_item(user[:vault], user[:vault_item])

		jenkins_user user[:user_name] do
			full_name user[:fullname]
			email user[:email]
			password user_vault["#{user[:user_name]}_password"]
			sensitive true
		end	
	}

	jenkins_script 'Configure Jenkins auth' do
		# Need to add a guard to this
		command <<-EOH.gsub(/^ {4}/, '')
			import jenkins.model.*
			import hudson.security.*
			def instance = Jenkins.getInstance()
			def realm = new HudsonPrivateSecurityRealm(false)
			def strategy = new hudson.security.FullControlOnceLoggedInAuthorizationStrategy()
			instance.setSecurityRealm(realm)
			instance.setAuthorizationStrategy(strategy)
			instance.save()
		EOH
		notifies :create, 'ruby_block[Set Jenkins auth attribute]', :immediately
		action :nothing
	end

	ruby_block 'Set Jenkins auth attribute' do
		block do
			node.run_state[:jenkins_private_key] = admin_vault['private_key'].strip
			node.normal.application_attributes.jenkins_auth = true
			node.save
		end
		action :nothing
	end

	node.jenkins_plugins.each { |plugin|
		jenkins_plugin plugin do
			notifies :restart, 'service[jenkins]', :delayed
		end
	}
else
	Chef::Log.info("Unsupported platform #{node.platform}")
end
