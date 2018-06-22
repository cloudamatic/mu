#
# Cookbook Name:: mu-activedirectory
# Provider:: domain_controller
#
# Copyright 2015, eGlobalTech,
#
# All rights reserved - Do Not Redistribute
#

include Chef::Mixin::PowershellOut
require 'chef/mixin/shell_out'
include Chef::Mixin::ShellOut

def whyrun_supported?
  true
end

action :add do
  case node['platform']
    when "windows"
      install_ad_features
      elevate_remote_access
      join_domain
      promote
      configure_network_interface
      set_replication_static_ports
      set_computer_name(admin_creds)
    when "centos", "redhat"
      # To do: Do Active Directory on Linux
    else
      Chef::Log.info("Unsupported platform #{node['platform']}")
  end
end

action :remove do
  case node['platform']
    when "windows"
      demote
    when "centos", "redhat"
      # To do: Do Active Directory on Linux
    else
      Chef::Log.info("Unsupported platform #{node['platform']}")
  end
end

# def load_current_resource
# @current_resource = @new_resource.dup
# end

def promote
  unless is_domain_controller?(new_resource.computer_name)
    Chef::Log.info("Promoting #{new_resource.computer_name} to domain controller in #{new_resource.dns_name} domain")
    cmd = powershell_out("Stop-Process -ProcessName sshd -force -ErrorAction SilentlyContinue; Install-ADDSDomainController -InstallDns -DomainName #{new_resource.dns_name} -Credential #{admin_creds} -SafeModeAdministratorPassword (convertto-securestring '#{new_resource.restore_mode_password}' -asplaintext -force) -Force -Confirm:$false; Restart-Computer -Force")
    kill_ssh
    Chef::Application.fatal!("Failed to promote #{new_resource.computer_name} to Domain Controller in #{new_resource.dns_name} domain") unless cmd.exitstatus == 0
    Chef::Application.fatal!("Promoted #{new_resource.computer_name} to Domain Controller in #{new_resource.dns_name} domain. Will have to run chef again")
  end
end

def demote
  if is_domain_controller?(new_resource.computer_name)
    Chef::Log.info("Demoting domain controller #{new_resource.computer_name} in #{new_resource.dns_name} domain")
    cmd = powershell_out("Stop-Process -ProcessName sshd -force -ErrorAction SilentlyContinue; Uninstall-WindowsFeature DNS; Uninstall-ADDSDomainController -Credential #{admin_creds} -LocalAdministratorPassword (convertto-securestring '#{new_resource.domain_admin_password}'  -asplaintext -force) -Force -Confirm:$false; Restart-Computer -Force")
    kill_ssh
    Chef::Application.fatal!("Failed to demote Domain Controller #{new_resource.computer_name} in #{new_resource.dns_name} domain") unless cmd.exitstatus == 0
    Chef::Application.fatal!("Demoted Domain Controller #{new_resource.computer_name} in #{new_resource.dns_name} domain. Will have to run chef again")
  end
  powershell_out("Uninstall-WindowsFeature AD-Domain-Services, rsat-adds, FS-DFS-Replication, RSAT-DFS-Mgmt-Con -IncludeManagementTools")
end

def join_domain
  unless in_domain?
    # Workaround for a really crappy issue with cygwin/ssh and windows where we need to end all ssh process,
    # or Mu's SSH session / chef client run won't disconnect even though the client chef run has finished or the SSH session has closed.
    # Running configure_network_interface before joining a domain, and re-running chef-client will cause DNS name resolution to fail if the node wasn't successfully added to the domain,
    # which is why we add the configure_network_interface code to join_domain directly.
    code =<<-EOH
#{network_interface_code}
			Add-Computer -DomainName #{new_resource.dns_name} -Credential #{admin_creds} -Restart -PassThru
			Restart-Computer -Force
    EOH
    Chef::Log.info("Joining #{new_resource.computer_name} node to #{new_resource.dns_name} domain")
    cmd = powershell_out(code)
    # cmd = powershell_out("Add-Computer -DomainName #{new_resource.dns_name} -Credential #{admin_creds} -Restart -PassThru")
    kill_ssh
    Chef::Application.fatal!("Failed to join #{new_resource.computer_name} to #{new_resource.dns_name} domain") unless cmd.exitstatus == 0
    Chef::Application.fatal!("Joined #{new_resource.computer_name} to #{new_resource.dns_name} domain. Will have to run chef again")
  end
end
