#
# Cookbook Name:: active-directory
# Provider:: domain_controller
#
# Copyright 2015, eGlobalTech,
#
# All rights reserved - Do Not Redistribute
#

require 'chef/mixin/shell_out'
include Chef::Mixin::ShellOut

def whyrun_supported?
	true
end

action :add do
	install_ad_features
	configure_network_interface
	elevate_remote_access
	join_domain
	promote
	set_replication_static_ports
	set_computer_name(admin_creds)
end

action :remove do
	demote
end

# def load_current_resource
	# @current_resource = @new_resource.dup
# end

case node.platform
when "windows"
	include Chef::Mixin::PowershellOut

	def promote
		unless is_domain_controller?
			cmd = powershell_out("Install-ADDSDomainController -InstallDns -DomainName #{new_resource.dns_name} -Credential #{admin_creds} -SafeModeAdministratorPassword (convertto-securestring '#{new_resource.restore_mode_password}' -asplaintext -force) -Force -Confirm:$false").run_command
			Chef::Application.fatal!("Failed to promote #{new_resource.computer_name} to Domain Controller in #{new_resource.dns_name} domain") unless cmd.exitstatus == 0
			Chef::Application.fatal!("Promoted #{new_resource.computer_name} to Domain Controller in #{new_resource.dns_name} domain. Will have to run chef again" )
		end
	end

	def demote
		if is_domain_controller?
			cmd = powershell_out("").run_command
			Chef::Application.fatal!("Failed to demote Domain Controller #{new_resource.computer_name} in #{new_resource.dns_name} domain") unless cmd.exitstatus == 0
			Chef::Application.fatal!("Demoted #{new_resource.computer_name} Domain Controller in #{new_resource.dns_name} domain. Will have to run chef again" )
		end
	end

	def join_domain
		unless in_domain?
			cmd = powershell_out("Add-Computer -DomainName #{new_resource.dns_name} -Credential #{admin_creds} -newname #{new_resource.computer_name} -Restart -PassThru").run_command
			Chef::Application.fatal!("Failed to join #{new_resource.computer_name} to #{new_resource.dns_name} domain") unless cmd.exitstatus == 0
			Chef::Application.fatal!("Joined #{new_resource.computer_name} to #{new_resource.dns_name} domain. Will have to run chef again" )
		end
	end
when "centos", "redhat"
	# do something
else
	Chef::Log.info("Unsupported platform #{node.platform}")
end
