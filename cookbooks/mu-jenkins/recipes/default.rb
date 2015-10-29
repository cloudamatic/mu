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

admin_vault = chef_vault_item(node.jenkins_admin_vault[:vault], node.jenkins_admin_vault[:item])

case node.platform
  when "centos", "redhat"


    %w{git bzip2}.each { |pkg|
      package pkg
    }

    # If security was enabled in a previous chef run then set the private key in the run_state
    # now as required by the Jenkins cookbook
    ruby_block 'set jenkins private key' do
      block do
        Chef::Log.info("Setting the previously enabled jenkins private key")
        node.run_state[:jenkins_private_key] = admin_vault['private_key'].strip
      end
    end

    # Add the admin user only if it has not been added already then notify the resource
    # to configure the permissions for the admin user.  Note that we check for existence of jenkins_auth_set,
    # not value
    jenkins_user admin_vault['username'] do
      full_name admin_vault['username']
      email "mu-developers@googlegroups.com"
      public_keys [admin_vault['public_key'].strip]
      not_if { node.application_attributes.attribute?('jenkins_auth_set') }
      #notifies :execute, 'jenkins_script[configure_jenkins_auth]', :immediately
      #For some reason notifies not working on jenkins_script so using guard
    end

    # Configure the permissions so that login is required and the admin user is an administrator
    # after this point the private key will be required to execute jenkins scripts (including querying
    # if users exist) so we notify the `set the security_enabled flag` resource to set this up.
    # Also note that since Jenkins 1.556 the private key cannot be used until after the admin user
    # has been added to the security realm

    jenkins_script 'configure_jenkins_auth' do
      command <<-EOH.gsub(/^ {4}/, '')
      import jenkins.model.*
      import hudson.security.*
      def instance = Jenkins.getInstance()
      def hudsonRealm = new HudsonPrivateSecurityRealm(false)
      instance.setSecurityRealm(hudsonRealm)
      def strategy = new ProjectMatrixAuthorizationStrategy()
      strategy.add(Jenkins.ADMINISTER,  "#{admin_vault['username']}")
      strategy.add(Jenkins.ADMINISTER, "mu_user")
      strategy.add(Jenkins.READ, "authenticated")
      instance.setAuthorizationStrategy(strategy)
      instance.save()
      EOH
      not_if { node.application_attributes.attribute?('jenkins_auth_set') }
      notifies :create, 'ruby_block[configure_jenkins_auth_set]', :immediately
      action :execute
    end

    # Set the security enabled flag and set the run_state to use the configured private key
    ruby_block 'configure_jenkins_auth_set' do
      block do
        node.run_state[:jenkins_private_key] = admin_vault['private_key'].strip
        node.normal.application_attributes.jenkins_auth_set = true
        node.save
      end
      action :nothing
    end

    # Configure users from the vault
    node.jenkins_users.each { |user|
      user_vault = chef_vault_item(user[:vault], user[:vault_item])

      jenkins_user user[:user_name] do
        full_name user[:fullname]
        email user[:email]
        password user_vault["#{user[:user_name]}_password"]
        sensitive true
      end
    }

    node.jenkins_plugins.each { |plugin|
      jenkins_plugin plugin do
        notifies :restart, 'service[jenkins]', :delayed
      end
    }

# Specific version plugins that don't come as default
      jenkins_plugin 'matrix-auth' do
        version '1.2'
        notifies :restart, 'service[jenkins]', :delayed
      end

      jenkins_plugin 'matrix-project' do
        version '1.6'
        notifies :restart, 'service[jenkins]', :delayed
      end

    # Setup apache or else open direct ports
#    if node.attribute?('jenkins_port_external')
#          include_recipe "mu-jenkins::jenkins_apache"
#    else
#      %w{node.jenkins_ports_direct}.each { |port|
#        execute "iptables -I INPUT -p tcp --dport #{port} -j ACCEPT; service iptables save" do
#          not_if "iptables -nL | egrep '^ACCEPT.*dpt:#{port}($| )'"
#        end
#      }
#    end
  else
    Chef::Log.info("Unsupported platform #{node.platform}")
end
