#
# Cookbook Name:: mu-tools
# Provider:: windows_client
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

action :run do
	configure_users
	set_ec2config_service
	import_scheduled_tasks
	set_sshd_service
end

def configure_users
	if in_domain?
		if is_domain_controller?(new_resource.computer_name)
			unless domain_user_exist?(new_resource.domain_admin_user)
				powershell_script "Create User #{new_resource.domain_admin_user}" do
					code <<-EOH
						New-ADUser -Name #{new_resource.domain_admin_user} -UserPrincipalName #{new_resource.domain_admin_user}@#{new_resource.domain_name} -AccountPassword (ConvertTo-SecureString -AsPlainText '#{new_resource.password}' -force) -Enabled $true -PasswordNeverExpires $true
						Add-ADGroupMember 'Domain Admins' -Members #{new_resource.domain_admin_user}
					EOH
				end
				Chef::Log.info("Create Domain Admin User #{new_resource.domain_admin_user}")
			end

			unless domain_user_exist?(new_resource.ssh_user)
				powershell_script "Create User #{new_resource.ssh_user}" do
					code <<-EOH
						New-ADUser -Name #{new_resource.ssh_user} -UserPrincipalName #{new_resource.ssh_user}@#{new_resource.domain_name} -AccountPassword (ConvertTo-SecureString -AsPlainText '#{new_resource.ssh_password}' -force) -Enabled $true -PasswordNeverExpires $true
						Add-ADGroupMember 'Domain Admins' -Members #{new_resource.ssh_user}
					EOH
				end
				Chef::Log.info("Create Domain User #{new_resource.ssh_user}")
			end

			### This is a workaround because user data might re-install cygwin and use a random password that we don't know about. This is not idempotent, it just doesn't throw and error.
			powershell_script "Add #{new_resource.ssh_user} user to Domain Admins group" do
				code "Add-ADGroupMember 'Domain Admins' -Members #{new_resource.ssh_user}; Set-ADAccountPassword -Identity #{new_resource.ssh_user} -NewPassword (ConvertTo-SecureString -AsPlainText \"#{new_resource.ssh_password}\" -Force)"
			end

			unless domain_user_exist?(new_resource.ec2config_user)
				powershell_script "Create User #{new_resource.ec2config_user}" do
					code <<-EOH
						New-ADUser -Name #{new_resource.ec2config_user} -UserPrincipalName #{new_resource.ec2config_user}@#{new_resource.domain_name} -AccountPassword (ConvertTo-SecureString -AsPlainText '#{new_resource.ec2config_password}' -force) -Enabled $true -PasswordNeverExpires $true
						Add-ADGroupMember 'Administrators' -Members #{new_resource.ec2config_user}
					EOH
				end
				Chef::Log.info("Create Domain User #{new_resource.ec2config_user}")
			end

			# Ugh! we can't run this because at this point the sshd service is running under a user that doesn't have sufficient privileges in the domain. Need to RDP at this point. Why aren't we bootstrapping with WinRM???????
			# Another problem with cygwin is that gpo_exist? fails on "secondary" domain controllers although it works fine in native powershell.
			# Using WinRM here doesn't work for multiple reasons so instead we're going to run it only on the schemamaster which is hopefully still the first domain controller.
			# Also need to chagne this to re-import the GPO even if the GPO exist. The SSH user that is running the service might change, and the GPO will have the old SID. 
			gpo_name = "ec2config-ssh-privileges"
			if is_schemamaster?(new_resource.domain_name, new_resource.computer_name)
				unless gpo_exist?(gpo_name)
					["Machine\\microsoft\\windows nt\\SecEdit", "Machine\\Scripts\\Shutdown", "Machine\\Scripts\\Startup", "User"].each { |dir|
						directory "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\DomainSysvol\\GPO\\#{dir}" do
							recursive true
						end
					}

					ssh_user_sid = powershell_out("(New-Object System.Security.Principal.NTAccount('#{new_resource.netbios_name}', '#{new_resource.ssh_user}')).Translate([System.Security.Principal.SecurityIdentifier]).value").stdout.strip
					ec2config_user_sid = powershell_out("(New-Object System.Security.Principal.NTAccount('#{new_resource.netbios_name}', '#{new_resource.ec2config_user}')).Translate([System.Security.Principal.SecurityIdentifier]).value").stdout.strip
					# ssh_user_sid = powershell_out("Invoke-Command -ScriptBlock { (New-Object System.Security.Principal.NTAccount('#{new_resource.netbios_name}', '#{new_resource.ssh_user}')).Translate([System.Security.Principal.SecurityIdentifier]).value } -ComputerName #{node.ipaddress} -Credential (New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.domain_admin_user}', (ConvertTo-SecureString '#{new_resource.password}' -AsPlainText -Force)))").stdout.strip
					# ec2config_user_sid = powershell_out("Invoke-Command -ScriptBlock { (New-Object System.Security.Principal.NTAccount('#{new_resource.netbios_name}', '#{new_resource.ec2config_user}')).Translate([System.Security.Principal.SecurityIdentifier]).value } -ComputerName #{node.ipaddress} -Credential (New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.domain_admin_user}', (ConvertTo-SecureString '#{new_resource.password}' -AsPlainText -Force)))").stdout.strip

					Chef::Log.info("ssh_user_sid #{ssh_user_sid}")
					Chef::Log.info("ec2config_user_sid #{ec2config_user_sid}")

					template "#{Chef::Config[:file_cache_path]}\\gpo\\manifest.xml" do
						source "manifest.xml.erb"
						variables(
							:domain_name => new_resource.domain_name,
							:computer_name => new_resource.computer_name
						)
					end

					template "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\Backup.xml" do
						source "Backup.xml.erb"
						variables(
							:domain_name => new_resource.domain_name,
							:computer_name => new_resource.computer_name,
							:netbios_name => new_resource.netbios_name
						)
					end

					template "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\bkupInfo.xml" do
						source "bkupInfo.xml.erb"
						variables(
							:domain_name => new_resource.domain_name,
							:computer_name => new_resource.computer_name
						)
					end

					template "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\gpreport.xml" do
						source "gpreprt.xml.erb"
						variables(
							:domain_name => new_resource.domain_name,
							:computer_name => new_resource.computer_name,
							:netbios_name => new_resource.netbios_name,
							:ssh_sid => ssh_user_sid,
							:ec2config_sid => ec2config_user_sid
						)
					end

					template "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\DomainSysvol\\GPO\\Machine\\microsoft\\windows nt\\SecEdit\\GptTmpl.inf" do
						source "gptmpl.inf.erb"
						variables(
							:ssh_sid => ssh_user_sid,
							:ec2config_sid => ec2config_user_sid
						)
					end

					# We might not have sufficient permissions to import the GPO correctly with Cygwin/SSH at this point. Lets use WinRM to authenticate to the local machine
					powershell_script "import #{gpo_name} gpo" do
						guard_interpreter :powershell_script
						code <<-EOH
							Invoke-Command -ScriptBlock { Import-GPO -BackupId 24E13F41-7118-4FB6-AE8B-45D48AFD6AFE -TargetName #{gpo_name} -path #{Chef::Config[:file_cache_path]}\\gpo -CreateIfNeeded } -ComputerName #{node.ipaddress} -Credential (New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.domain_admin_user}', (ConvertTo-SecureString '#{new_resource.password}' -AsPlainText -Force)))
							new-gplink -name #{gpo_name} -target 'dc=#{new_resource.domain_name.gsub(".", ",dc=")}'
							gpupdate /force
						EOH
					end

					# powershell_out("Import-GPO -BackupId 24E13F41-7118-4FB6-AE8B-45D48AFD6AFE -TargetName #{gpo_name} -path #{Chef::Config[:file_cache_path]}\\gpo -CreateIfNeeded").run_command
					# powershell_out("new-gplink -name #{gpo_name} -target 'dc=#{new_resource.domain_name.gsub(".", ",dc=")}'").run_command
				end
			end
		else
			[new_resource.ssh_user, new_resource.ec2config_user].each { |user|
				powershell_script "Add domain SSH service user to local Administrators group" do
					code <<-EOH
						$domain_user = [ADSI]("WinNT://#{new_resource.netbios_name}/#{user}")
						$local_admin_group = [ADSI]("WinNT://./Administrators")
						$local_admin_group.PSBase.Invoke("Add",$domain_user.PSBase.Path)
					EOH
					not_if "net localgroup Administrators | findstr #{new_resource.netbios_name}\\#{user}"
				end
			}
		end

		template "#{Chef::Config[:file_cache_path]}\\set_ad_dns_scheduled_task.ps1" do
			source 'set_ad_dns_scheduled_task.ps1.erb'
			variables(
				:dc_ips => node.ad.dc_ips
			)
		end

		windows_task 'set-ad-dns' do
			user "SYSTEM"
			command "powershell -ExecutionPolicy RemoteSigned -File '#{Chef::Config[:file_cache_path]}\\set_ad_dns_scheduled_task.ps1'"
			run_level :highest
			frequency :onstart
		end
	else 
		# We want to run ec2config as admin user so Windows userdata executes as admin, however the local admin account doesn't have Logon As a Service right. Domain privileges are set separately	 
		cookbook_file "c:\\Windows\\SysWOW64\\ntrights.exe" do
			source "ntrights"
		end

		[new_resource.ssh_user, new_resource.ec2config_user].each { |usr|
			user usr do
				password new_resource.ec2config_password if usr == new_resource.ec2config_user
				password new_resource.ssh_password if usr == new_resource.ssh_user
			end

			group "Administrators" do
				action :modify
				members usr
				append true
			end

			%w{SeDenyRemoteInteractiveLogonRight SeDenyInteractiveLogonRight SeServiceLogonRight}.each { |privilege|
				batch "Grant local user #{usr} logon as service right" do
					code "C:\\Windows\\SysWOW64\\ntrights +r #{privilege} -u #{usr}"
				end
			}

			if usr == new_resource.ssh_user
				%w{SeCreateTokenPrivilege SeTcbPrivilege SeAssignPrimaryTokenPrivilege}.each { |privilege|
				batch "Grant local user #{usr} logon as service right" do
					code "C:\\Windows\\SysWOW64\\ntrights +r #{privilege} -u #{usr}"
				end
				}
			end
		}
	end
end

def set_ec2config_service
	execute "Set ec2config service to login with ec2config user" do
		not_if "sc qc Ec2Config | findstr SERVICE_START_NAME | findstr #{new_resource.ec2config_guard}"
		command "sc config Ec2Config obj= \"#{new_resource.ec2config_service_user}\" password= \"#{new_resource.ec2config_password}\""
		notifies :restart, "service[Ec2Config]", :delayed
		# notifies :request, 'windows_reboot[1]'
		sensitive true
	end

	service "Ec2Config" do
		action :nothing
	end
end

def import_scheduled_tasks
	# To do: Replace existing guard with guard that checks if the user running the task is admin.
	# Or allow userdata to be rerun everytime the recipe is run
	powershell_script "Import run-userdata scheduled task" do
		guard_interpreter :powershell_script
		code "Register-ScheduledTask -Xml (get-content '#{Chef::Config[:file_cache_path]}/run-userdata_scheduledtask.xml' | out-string) -TaskName 'run-userdata' -User #{new_resource.user_name} -Password '#{new_resource.password}' -Force"
		only_if "((schtasks /TN 'run-userdata' /query /FO LIST -v | Select-String 'Run As User') -replace '`n|`r').split(':')[1].trim() -ne '#{new_resource.user_name}'"
		# not_if "Get-ScheduledTask -TaskName 'run-userdata'"
	end

	# Need to add a guard to this.
	powershell_script "Import run-chef-client scheduled task" do
		guard_interpreter :powershell_script
		code "Register-ScheduledTask -Xml (get-content '#{Chef::Config[:file_cache_path]}/run_chefclient_scheduledtask.xml' | out-string) -TaskName 'run-chef-client' -User #{new_resource.user_name} -Password '#{new_resource.password}' -Force"
		# only_if "((schtasks /TN 'run-chef-client' /query /FO LIST -v | Select-String 'Run As User') -replace '`n|`r').split(':')[1].trim() -ne '#{new_resource.user_name}'"
		# not_if "Get-ScheduledTask -TaskName 'run-chef-client'"
	end

	windows_task 'run-userdata' do
		action :nothing
	end

	windows_task 'run-chef-client' do
		action :nothing
	end
end

def set_sshd_service
	ssh_user_set = ssh_user_set?(new_resource.ssh_guard)

	cmd = powershell_out("$sshd_service = Get-WmiObject Win32_service | Where-Object {$_.Name -eq 'sshd'}; $sshd_service.Change($Null,$Null,$Null,$Null,$Null,$Null,'#{new_resource.ssh_service_user}','#{new_resource.ssh_password}',$Null,$Null,$Null)")
	unless ssh_user_set
		cmd = powershell_out("c:/bin/cygwin/bin/bash --login -c 'chown -R #{new_resource.ssh_user} /var/empty && chown #{new_resource.ssh_user} /var/log/sshd.log /etc/ssh*\'; Stop-Process -ProcessName sshd -force; Stop-Service sshd -Force; Start-Service sshd; sleep 5; Start-Service sshd")
		Chef::Application.fatal!("Cygwin sux")
	end
end
