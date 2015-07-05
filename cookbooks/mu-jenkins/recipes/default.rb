#
# Cookbook Name:: mu-jenkins
# Recipe:: default
#
# Copyright 2015, eGlobalTech, Inc
#
# All rights reserved - Do Not Redistribute
#

include_recipe 'mu-jenkins::public_key'
include_recipe 'mu-utility::disable-requiretty'
include_recipe 'mu-utility::iptables'
include_recipe 'chef-vault'

admin_vault = chef_vault_item(node.jenkins_admin_vault[:vault], node.jenkins_admin_vault[:item])
ssh_vault = chef_vault_item(node.jenkins_ssh_vault[:vault], node.jenkins_ssh_vault[:item])

case node.platform
when "centos", "redhat"
	%w{8080 8443}.each { |port|
		execute "iptables -I INPUT -p tcp --dport #{port} -j ACCEPT; service iptables save" do
			not_if "iptables -nL | egrep '^ACCEPT.*dpt:#{port}($| )'"
		end
	}

	ssh_user = "root" if node.platform_version.to_i == 6
	ssh_user = "centos" if node.platform_version.to_i == 7

	directory "#{node.jenkins.master.home}/.ssh" do
		owner "jenkins"
		group "jenkins"
		mode 0700
	end

	ssh_key_path = "#{node.jenkins.master.home}/.ssh/jenkins_ssh"

	template "#{node.jenkins.master.home}/.ssh/config" do
		source "ssh_config.erb"
		owner "jenkins"
		group "jenkins"
		mode 0600
		variables(
			:ssh_user => ssh_user,
			:ssh_key_path => ssh_key_path,
			:ssh_urls => node.jenkins_ssh_urls
		)
	end

	file ssh_key_path do
		owner "jenkins"
		group "jenkins"
		mode 0400
		content ssh_vault['private_key'].strip
		sensitive true
	end

	%w{npm git bzip2}.each { |pkg|
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
			password user_vault['password']
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

	%w{nodejs github ssh deploy}.each { |plugin|
		jenkins_plugin plugin do
			notifies :restart, 'service[jenkins]', :delayed
		end
	}
else
	Chef::Log.info("Unsupported platform #{node.platform}")
end
