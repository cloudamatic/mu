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

    directory node.jenkins.master.home do
      owner "jenkins"
      recursive true
      notifies :restart, 'service[jenkins]', :immediately
    end

    %w{git bzip2}.each { |pkg|
      package pkg
    }
    execute "pin standard Credentials plugin" do
      command "touch #{node.jenkins.master.home}/plugins/credentials.jpi.pinned ; curl -o #{node.jenkins.master.home}/credentials.jpi http://updates.jenkins-ci.org/latest/credentials.hpi"
      not_if "test -f #{node.jenkins.master.home}/plugins/credentials.jpi.pinned"
    end

    # If security was enabled in a previous chef run then set the private key in the run_state
    # now as required by the Jenkins cookbook
    ruby_block 'set jenkins private key' do
      block do
        Chef::Log.info("Setting the previously enabled jenkins private key")
        node.run_state[:jenkins_private_key] = admin_vault['private_key'].strip
      end
    end

    chef_gem "simple-password-gen"
    # The Jenkins service user that this cookbook uses MUST exist in our directory
    MU::Master::LDAP.manageUser(admin_vault['username'], name: admin_vault['username'], password: MU.generateWindowsPassword, admin: false, email: "mu-developers@googlegroups.com")

    # Add the admin user only if it has not been added already then notify the resource
    # to configure the permissions for the admin user.  Note that we check for existence of jenkins_auth_set,
    # not value
    jenkins_user admin_vault['username'] do
      full_name admin_vault['username']
      email "mu-developers@googlegroups.com"
      public_keys [admin_vault['public_key'].strip]
      not_if { node.application_attributes.attribute?('jenkins_auth_set') }
    end


    node.jenkins_plugins.each { |plugin|
      jenkins_plugin plugin do
        notifies :restart, 'service[jenkins]', :delayed
        not_if { ::File.exists?("#{node.jenkins.master.home}/plugins/#{plugin}.jpi") }
      end
    }

    jenkins_private_key_credentials admin_vault['username'] do
      description admin_vault['username']
      private_key admin_vault['private_key'].strip
    end

    # Configure the permissions so that login is required and the admin user is an administrator
    # after this point the private key will be required to execute jenkins scripts (including querying
    # if users exist) so we notify the `set the security_enabled flag` resource to set this up.
    # Also note that since Jenkins 1.556 the private key cannot be used until after the admin user
    # has been added to the security realm
    uidsearch = "uid={0}"
    uidsearch = "sAMAccountName={0}" if $MU_CFG['ldap']['type'] == "Active Directory"
    membersearch = "(| (member={0}) (uniqueMember={0}) (memberUid={1}))"
    membersearch = "memberUid={0}" if $MU_CFG['ldap']['type'] == "389 Directory Services"
    bind_creds = chef_vault_item($MU_CFG['ldap']['bind_creds']['vault'], $MU_CFG['ldap']['bind_creds']['item'])
    jenkins_script 'configure_jenkins_auth' do
      command <<-EOH.gsub(/^ {4}/, '')
      import jenkins.model.*
      import hudson.security.*
      import org.jenkinsci.plugins.*
      def instance = Jenkins.getInstance()
      def hudsonRealm = new HudsonPrivateSecurityRealm(false)
      String groupSearchFilter = 'memberUid={0}'
      SecurityRealm ldapRealm = new LDAPSecurityRealm(server='ldap://#{$MU_CFG['ldap']['dcs'].first}', rootDN = '#{$MU_CFG['ldap']['base_dn']}', userSearchBase='#{$MU_CFG['ldap']['user_ou'].sub(/,.*/, "")}', userSearch="#{uidsearch}", groupSearchBase='#{$MU_CFG['ldap']['group_ou'].sub(/,.*/, "")}', groupSearchFilter="", groupMembershipFilter = '#{membersearch}', managerDN = '#{bind_creds[$MU_CFG['ldap']['bind_creds']['username_field']]}', managerPasswordSecret = '#{bind_creds[$MU_CFG['ldap']['bind_creds']['password_field']]}', inhibitInferRootDN = false, disableMailAddressResolver = false, cache = null)
      instance.setSecurityRealm(ldapRealm)
      def strategy = new ProjectMatrixAuthorizationStrategy()
      strategy.add(Jenkins.ADMINISTER, "#{$MU_CFG['ldap']['admin_group_name']}")
      strategy.add(Jenkins.ADMINISTER, "#{admin_vault['username']}")
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

      # XXX This is dangerous. What if we stupidly step on the account of a
      # "real" user?
      MU::Master::LDAP.manageUser(user[:user_name], name: user[:fullname], password: user_vault[user[:user_name]+"_password"], admin: false, email: user[:email])
      jenkins_user user[:user_name] do
        full_name user[:fullname]
        email user[:email]
        password user_vault["#{user[:user_name]}_password"]
        sensitive true
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

  else
    Chef::Log.info("Unsupported platform #{node.platform}")
end
