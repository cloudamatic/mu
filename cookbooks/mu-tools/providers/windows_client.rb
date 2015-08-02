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
				script =<<-EOH
					New-ADUser -Name #{new_resource.domain_admin_user} -UserPrincipalName #{new_resource.domain_admin_user}@#{new_resource.domain_name} -AccountPassword (ConvertTo-SecureString -AsPlainText '#{new_resource.password}' -force) -Enabled $true -PasswordNeverExpires $true -PassThru
					Add-ADGroupMember 'Domain Admins' -Members #{new_resource.domain_admin_user} -PassThru
				EOH
				cmd = powershell_out(script)
			end

			unless domain_user_exist?(new_resource.ssh_user)
				script =<<-EOH
					New-ADUser -Name #{new_resource.ssh_user} -UserPrincipalName #{new_resource.ssh_user}@#{new_resource.domain_name} -AccountPassword (ConvertTo-SecureString -AsPlainText '#{new_resource.ssh_password}' -force) -Enabled $true -PasswordNeverExpires $true -PassThru
					Add-ADGroupMember 'Domain Admins' -Members #{new_resource.ssh_user} -PassThru
				EOH
				cmd = powershell_out(script)
				Chef::Log.info("Create Domain User #{new_resource.ssh_user}")
			end

			# This is a workaround because user data might re-install cygwin and use a random password that we don't know about. This is not idempotent, it just doesn't throw and error.
			script =<<-EOH
				Add-ADGroupMember 'Domain Admins' -Members #{new_resource.ssh_user} -PassThru
				Set-ADAccountPassword -Identity #{new_resource.ssh_user} -NewPassword (ConvertTo-SecureString -AsPlainText '#{new_resource.ssh_password}' -Force) -PassThru
			EOH
			cmd = powershell_out(script)
			Chef::Log.info("Added #{new_resource.ssh_user} to Domain Admin group and reset its password")

			unless domain_user_exist?(new_resource.ec2config_user)
				script =<<-EOH
						New-ADUser -Name #{new_resource.ec2config_user} -UserPrincipalName #{new_resource.ec2config_user}@#{new_resource.domain_name} -AccountPassword (ConvertTo-SecureString -AsPlainText '#{new_resource.ec2config_password}' -force) -Enabled $true -PasswordNeverExpires $true -PassThru
						Add-ADGroupMember 'Administrators' -Members #{new_resource.ec2config_user} -PassThru
				EOH
				cmd = powershell_out(script)
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
					# We're giving the Administrators group all the privileges the SSH user needs to make sure the local SSH user still has privileges after joining the domain so we can complete our chef run without relying on the run-chef-client  scheduled task to exist/run
					administrators_group_sid = powershell_out("(New-Object System.Security.Principal.NTAccount('Administrators')).Translate([System.Security.Principal.SecurityIdentifier]).value").stdout.strip
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
							:ec2config_sid => ec2config_user_sid,
							:admin_group_sid => administrators_group_sid
						)
					end

					template "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\DomainSysvol\\GPO\\Machine\\microsoft\\windows nt\\SecEdit\\GptTmpl.inf" do
						source "gptmpl.inf.erb"
						variables(
							:ssh_sid => ssh_user_sid,
							:ec2config_sid => ec2config_user_sid,
							:admin_group_sid => administrators_group_sid
						)
					end

					# We might not have sufficient permissions to import the GPO correctly with Cygwin/SSH at this point. Lets use WinRM to authenticate to the local machine

					# Chef::Log.info("import #{gpo_name} GPO")
					# script =<<-EOH
						# Invoke-Command -ScriptBlock { Import-GPO -BackupId 24E13F41-7118-4FB6-AE8B-45D48AFD6AFE -TargetName #{gpo_name} -path #{Chef::Config[:file_cache_path]}\\gpo -CreateIfNeeded } -ComputerName #{node.ipaddress} -Credential (New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.domain_admin_user}', (ConvertTo-SecureString '#{new_resource.password}' -AsPlainText -Force)))
						# new-gplink -name #{gpo_name} -target 'dc=#{new_resource.domain_name.gsub(".", ",dc=")}'
						# gpupdate /force
					# EOH
					# cmd = powershell_out(script)

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
				unless user_in_local_admin_group?(user)
					code =<<-EOH
						$domain_user = [ADSI]('WinNT://#{new_resource.netbios_name}/#{user}')
						$local_admin_group = [ADSI]('WinNT://./Administrators')
						$local_admin_group.PSBase.Invoke('Add',$domain_user.PSBase.Path)
					EOH

					Chef::Log.info("Added domain user #{user} to local Administrators group")
					powershell_out(code)
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
	unless service_user_set?("Ec2Config", new_resource.ec2config_service_user)
		Chef::Log.info("Trying to configure Ec2Config service to run under #{new_resource.ec2config_service_user}")
		cmd = powershell_out("(Get-WmiObject Win32_service | Where-Object {$_.Name -eq 'Ec2Config'}).StartName")
		Chef::Log.info("ec2config Service start name before change: #{cmd.stdout}")

		cmd = powershell_out("$ec2config_service = Get-WmiObject Win32_service | Where-Object {$_.Name -eq 'Ec2Config'}; $ec2config_service.Change($Null,$Null,$Null,$Null,$Null,$Null,'#{new_resource.ec2config_service_user}','#{new_resource.ec2config_password}',$Null,$Null,$Null)")
		Chef::Log.error("Error configuring Ec2Config service: #{cmd.stderr}") unless cmd.exitstatus == 0
		cmd = powershell_out("(Get-WmiObject Win32_service | Where-Object {$_.Name -eq 'Ec2Config'}).StartName")
		Chef::Log.info("ec2config Service start name after change: #{cmd.stdout}")
		# service "Ec2Config" do
			# action :restart
		# end
	end
end

def import_scheduled_tasks
	# To do: Add guards
	Chef::Log.info("Configuring run-chef-client Scheduled Task")
	cmd = powershell_out("Register-ScheduledTask -Xml (get-content '#{Chef::Config[:file_cache_path]}/run_chefclient_scheduledtask.xml' | out-string) -TaskName 'run-chef-client' -User #{new_resource.user_name} -Password '#{new_resource.password}' -Force")
	# Chef::Log.info("Register-ScheduledTask -Xml (get-content '#{Chef::Config[:file_cache_path]}/run_chefclient_scheduledtask.xml' | out-string) -TaskName 'run-chef-client' -User #{new_resource.user_name} -Password '#{new_resource.password}' -Force")
	# Chef::Application.fatal!("Failed to configure run-chef-client Scheduled Task: #{cmd.stderr}") unless cmd.exitstatus == 0

	Chef::Log.info("Configuring run-userdata Scheduled Task")
	cmd = powershell_out("Register-ScheduledTask -Xml (get-content '#{Chef::Config[:file_cache_path]}/run-userdata_scheduledtask.xml' | out-string) -TaskName 'run-userdata' -User #{new_resource.user_name} -Password '#{new_resource.password}' -Force")
	Chef::Log.error("Failed to configure run-userdata Scheduled Task: #{cmd.stderr}") unless cmd.exitstatus == 0

	# trying to make sure the run-chef-client scheduled task gets created because we can't SSH into a node that was added into a domain without changing the user the SSHD service is running under
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
	Chef::Log.info("Configuring SSH service to start under #{new_resource.ssh_service_user} user")
	cmd = powershell_out("(Get-WmiObject Win32_service | Where-Object {$_.Name -eq 'sshd'}).StartName")
	Chef::Log.info("SSHD Service start name before change : #{cmd.stdout}")
	ssh_user_set =  service_user_set?("sshd", new_resource.ssh_service_user)

	cmd = powershell_out("$sshd_service = Get-WmiObject Win32_service | Where-Object {$_.Name -eq 'sshd'}; $sshd_service.Change($Null,$Null,$Null,$Null,$Null,$Null,'#{new_resource.ssh_service_user}','#{new_resource.ssh_password}',$Null,$Null,$Null)")
	# Chef::Application.fatal!("Failed to configure sshd service: #{cmd.stderr}") unless cmd.exitstatus == 0
	cmd = powershell_out("(Get-WmiObject Win32_service | Where-Object {$_.Name -eq 'sshd'}).StartName")
	Chef::Log.info("SSHD Service start name after change : #{cmd.stdout}")
	# if cmd.exitstatus == 0 and !ssh_user_set
	unless ssh_user_set
		# cmd = powershell_out("c:/bin/cygwin/bin/bash --login -c 'chown -R #{new_resource.ssh_user} /var/empty && chown #{new_resource.ssh_user} /var/log/sshd.log /etc/ssh*\'; Stop-Process -ProcessName sshd -force; Stop-Service sshd -Force; Start-Service sshd; sleep 5; Start-Service sshd")
		# We would much prefer to use the above because that wouldn't  require another reboot, but in some cases the session dosen't get terminated from  Mu. Throwing Chef::Application.fatal seems to work more reliably
		cmd = powershell_out("c:/bin/cygwin/bin/bash --login -c 'chown -R #{new_resource.ssh_user} /var/empty && chown #{new_resource.ssh_user} /var/log/sshd.log /etc/ssh*\'; Restart-Computer -force")
		kill_ssh
		Chef::Application.fatal!("Cygwin sux")
	end
end
