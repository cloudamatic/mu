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

admin_user_vault = chef_vault_item('jenkins', 'admin')
jenkins_ssh_vault = chef_vault_item('jenkins', 'ssh_keys')
github_vault = chef_vault_item('git', 'keys')

case node.platform
when "centos", "redhat"
	execute "sed -i 's_jenkins:/bin/false_jenkins:/bin/bash_' /etc/passwd" do
		not_if "grep jenkins:/bin/bash /etc/passwd"
	end

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
		content jenkins_ssh_vault['private_key'].strip
		sensitive true
	end

	%w{npm git bzip2}.each { |pkg|
		package pkg
	}

	ruby_block 'Use private key for Jenkins auth' do
		block do
			node.run_state[:jenkins_private_key] = admin_user_vault['private_key'].strip
		end
		only_if { node.application_attributes.attribute?('jenkins_auth') }
	end

	jenkins_user admin_user_vault['username'] do
		full_name "Admin User"
		email "mu-developers@googlegroups.com"
		public_keys [admin_user_vault['public_key'].strip]
		notifies :execute, 'jenkins_script[Configure Jenkins auth]', :immediately
	end

	node.jenkins_users.each { |usr|
		auth_info_user = chef_vault_item('jenkins', usr)

		jenkins_user auth_info_user['username'] do
			full_name auth_info_user['fullname']
			email auth_info_user['email']
			password auth_info_user['password']
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
			node.run_state[:jenkins_private_key] = admin_user_vault['private_key'].strip
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

	jenkins_private_key_credentials 'github' do
		id "7c1402e6-c358-4182-b03e-5333a7e6363d"
		description 'github'
		private_key github_vault['private_key'].strip
		sensitive true
	end

	# To do - Replace templates with native Jenkins Groovy API
	# %w{org.jvnet.hudson.plugins.SSHBuildWrapper.xml com.cloudbees.jenkins.GitHubPushTrigger.xml nodejs.xml hudson.tasks.Maven.xml jenkins.model.JenkinsLocationConfiguration.xml hudson.plugins.git.GitSCM.xml hudson.plugins.git.GitTool.xml}.each { |tpl|
		# template "#{node.jenkins.master.home}/#{tpl}" do
			# source "#{tpl}.erb"
			# notifies :restart, 'service[jenkins]', :delayed
		# end
	# }
	
	template "#{node.jenkins.master.home}/org.jvnet.hudson.plugins.SSHBuildWrapper.xml" do
		source "org.jvnet.hudson.plugins.SSHBuildWrapper.xml.erb"
		variables(
			:ssh_user => ssh_user,
			:node_ip => node.ipaddress,
			:ssh_key_path => ssh_key_path
		)
		sensitive true
	end

	template "#{Chef::Config[:file_cache_path]}/example_job.config.xml" do
		source "example_job.config.xml.erb"
		variables(
			:ssh_user => ssh_user,
			:node_ip => node.ipaddress
		)
		sensitive true
	end

	jenkins_job "example_job" do
		config "#{Chef::Config[:file_cache_path]}/example_job.config.xml"
		sensitive true
	end
else
	Chef::Log.info("Unsupported platform #{node.platform}")
end
