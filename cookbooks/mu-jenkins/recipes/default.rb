# Cookbook Name:: mu-jenkins
# Recipe:: default
#
# Copyright 2015, eGlobalTech, Inc
#
# All rights reserved - Do Not Redistribute
#

include_recipe 'mu-tools::disable-requiretty'
include_recipe 'chef-vault'

directory "/opt/java_jce" do
  mode 0755
end

admin_vault = chef_vault_item(node['jenkins_admin_vault'][:vault], node['jenkins_admin_vault'][:item])

directory node['jenkins']['master']['home'] do
  owner "jenkins"
  recursive true
  notifies :restart, 'service[jenkins]', :immediately
end

package %w{git bzip2}

#remote_file "#{node['jenkins']['master']['home']}/plugins/mailer.jpi" do
#  source "http://updates.jenkins-ci.org/latest/mailer.hpi"
#  owner "jenkins"
#end

ruby_block 'wait for jenkins' do
  block do
    sleep 30
  end
  action :nothing
end


# If security was enabled in a previous chef run then set the private key in the run_state
# now as required by the Jenkins cookbook
if node['application_attributes']['jenkins_auth_set']
ruby_block 'set jenkins private key' do
  block do
    Chef::Log.info("Setting the previously enabled jenkins private key")
    node.run_state[:jenkins_private_key] = admin_vault['private_key'].strip
  end
end
end

restart_jenkins = false

node['jenkins_plugins'].each { |plugin|
#  if !::File.exists?("#{node['jenkins']['master']['home']}/plugins/#{plugin}.jpi")
#    restart_jenkins = true
#  end
  jenkins_plugin plugin
  # do
    # notifies :restart, 'service[jenkins]', :delayed
    #not_if { ::File.exists?("#{node['jenkins']['master']['home']}/plugins/#{plugin}.jpi") }
  # end
}

if !node['application_attributes']['jenkins_auth_set']
  jenkins_command 'safe-restart'
  jenkins_private_key_credentials admin_vault['username'] do
    id '1671945-9fa7-4d24-ac87-51ea3b2aef4c'
    description admin_vault['username']
    private_key admin_vault['private_key'].strip
  end
end

# The Jenkins service user that this cookbook uses MUST exist in our directory
mu_master_user admin_vault['username'] do
  realname admin_vault['username']
#  email $MU_CFG['jenkins']['admin_email'] || $MU_CFG['admin_email']
  email "mu-developers@googlegroups.com"
end

# Add the admin user only if it has not been added already then notify the resource
# to configure the permissions for the admin user.  Note that we check for existence of jenkins_auth_set,
# not value
jenkins_user admin_vault['username'] do
  full_name admin_vault['username']
  email "mu-developers@googlegroups.com"
  public_keys [admin_vault['public_key'].strip]
  #not_if { node['application_attributes'].attribute?('jenkins_auth_set') }
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
jenkins_admins = ::MU::Master.listUsers.delete_if { |u, data| !data['admin'] }.keys
#jenkins_regular = ::MU::Master.listUsers.delete_if { |u, data| data['admin'] or u == "jenkins" }.keys
regular_user_perms = ["Item.BUILD", "Item.CREATE", "Item.DISCOVER", "Item.READ"]
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
  #{jenkins_admins.map { |u| "strategy.add(Jenkins.ADMINISTER, \"#{u}\")" }.join("\n")}
  strategy.add(Jenkins.READ, "authenticated")
  #{regular_user_perms.map { |p| "strategy.add(hudson.model.#{p}, \"authenticated\")" }.join("\n")}
  instance.setAuthorizationStrategy(strategy)
  instance.save()
  EOH
#  not_if "grep managerDN #{node['jenkins']['master']['home']}/config.xml | grep #{bind_creds[$MU_CFG['ldap']['bind_creds']['username_field']]}"
  notifies :create, 'ruby_block[configure_jenkins_auth_set]', :immediately
  action :nothing unless !::File.size?("#{node['jenkins']['master']['home']}/config.xml") or !::File.read("#{node['jenkins']['master']['home']}/config.xml").match(bind_creds[$MU_CFG['ldap']['bind_creds']['username_field']])
end

file "#{node['jenkins']['master']['home']}/user-list-chef-guard" do
  content "
#{jenkins_admins.map { |u| "strategy.add(Jenkins.ADMINISTER, \"#{u}\")" }.join("\n")}
#{regular_user_perms.map { |p| "strategy.add(Jenkins.#{p}, \"authenticated\")" }.join("\n")}
#{bind_creds[$MU_CFG['ldap']['bind_creds']['username_field']]}
"
  notifies :execute, "jenkins_script[configure_jenkins_auth]", :immediately
end

# Set the security enabled flag and set the run_state to use the configured private key
ruby_block 'configure_jenkins_auth_set' do
  block do
    node.run_state[:jenkins_private_key] = admin_vault['private_key'].strip
    node.normal['application_attributes']['jenkins_auth_set'] = true
    node.save
  end
  action :nothing
end

# Configure users from the vault
#node['jenkins_users'].each { |user|
#  user_vault = chef_vault_item(user[:vault], user[:vault_item])
#
#  # XXX This is dangerous. What if we stupidly step on the account of a
#  # "real" user?
#  ::MU::Master::LDAP.manageUser(user[:user_name], name: user[:fullname], password: user_vault[user[:user_name]+"_password"], admin: false, email: user[:email])
#  jenkins_user user[:user_name] do
#    full_name user[:fullname]
#    email user[:email]
#    password user_vault["#{user[:user_name]}_password"]
#    sensitive true
#  end
#}
