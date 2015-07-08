# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#	  http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

case node.platform
when "windows"
	include_recipe 'windows::reboot_handler'
	::Chef::Recipe.send(:include, Chef::Mixin::PowershellOut)

	include_recipe 'chef-vault'

	%w{run-userdata_scheduledtask.xml run_chefclient_scheduledtask.xml}.each { |file|
		remote_file "#{Chef::Config[:file_cache_path]}/#{file}" do
			source "https://s3.amazonaws.com/cap-public/#{file}"
		end
	}

	windows_vault = chef_vault_item(node.windows_auth_vault, node.windows_auth_item)
	ec2config_username = windows_vault[node.windows_ec2config_username_field]
	ec2config_password = windows_vault[node.windows_ec2config_password_field]
	sshd_username = windows_vault[node.windows_sshd_username_field]
	sshd_password = windows_vault[node.windows_sshd_password_field]

	if in_domain?
		ad_vault = chef_vault_item(node.ad.domain_admin_vault, node.ad.domain_admin_item)
		username = "#{node.ad.netbios_name}\\#{ad_vault[node.ad.domain_admin_username_field]}"
		password = ad_vault[node.ad.domain_admin_password_field]
		ec2config_guard = "#{node.ad.netbios_name}\\\\#{ec2config_username}"
		ec2config_service_username = "#{node.ad.netbios_name}\\#{ec2config_username}"
		sshd_guard = "#{node.ad.netbios_name}\\\\#{sshd_username}"
		sshd_service_username = "#{node.ad.netbios_name}\\#{sshd_username}"
	else
		username = node.windows_admin_username
		password = windows_vault[node.windows_auth_password_field]
		ec2config_guard = ".\\\\#{ec2config_username}"
		ec2config_service_username = ".\\#{ec2config_username}"
		sshd_guard = ".\\\\#{sshd_username}"
		sshd_service_username = ".\\#{sshd_username}"
	end rescue NoMethodError

	%w{sshd Ec2Config}.each {|svc|
		service svc do
			action :nothing
		end
	}

	if in_domain?
		if is_domain_controller?(node.ad.computer_name)
			unless domain_user_exist?(ad_vault[node.ad.domain_admin_username_field])
				powershell_script "Create User #{ad_vault[node.ad.domain_admin_username_field]}" do
					code <<-EOH
						New-ADUser -Name #{ad_vault[node.ad.domain_admin_username_field]} -UserPrincipalName #{ad_vault[node.ad.domain_admin_username_field]}@#{node.ad.domain_name} -AccountPassword (ConvertTo-SecureString -AsPlainText '#{password}' -force) -Enabled $true -PasswordNeverExpires $true
						Add-ADGroupMember 'Domain Admins' -Members #{ad_vault[node.ad.domain_admin_username_field]}
					EOH
				end
				Chef::Log.info("Create Domain Admin User #{ad_vault[node.ad.domain_admin_username_field]}")
			end

			unless domain_user_exist?(sshd_username)
				powershell_script "Create User #{sshd_username}" do
					code <<-EOH
						New-ADUser -Name #{sshd_username} -UserPrincipalName #{sshd_username}@#{node.ad.domain_name} -AccountPassword (ConvertTo-SecureString -AsPlainText '#{sshd_password}' -force) -Enabled $true -PasswordNeverExpires $true
						Add-ADGroupMember 'Domain Admins' -Members #{sshd_username}
					EOH
				end
				Chef::Log.info("Create Domain User #{user}")
			end

			### This is a workaround because user data might re-install cygwin and use a random password that we don't know about. This is not idempotent, it just doesn't throw and error.
			powershell_script "Add sshd to group" do
				code "Add-ADGroupMember 'Domain Admins' -Members #{sshd_username}; Set-ADAccountPassword -Identity #{sshd_username} -NewPassword (ConvertTo-SecureString -AsPlainText \"#{sshd_password}\" -Force)"
			end

			unless domain_user_exist?(ec2config_username)
				powershell_script "Create User #{sshd_username}" do
					code <<-EOH
						New-ADUser -Name #{ec2config_username} -UserPrincipalName #{ec2config_username}@#{node.ad.domain_name} -AccountPassword (ConvertTo-SecureString -AsPlainText '#{ec2config_password}' -force) -Enabled $true -PasswordNeverExpires $true
						Add-ADGroupMember 'Administrators' -Members #{ec2config_username}
					EOH
				end
				Chef::Log.info("Create Domain User #{user}")
			end

			# Ugh! we can't run this because at this point the sshd service is running under a user that doesn't have sufficient privileges in the domain. Need to RDP at this point. Why aren't we bootstrapping with WinRM???????
			# Another problem with cygwin is that gpo_exist? fails on "secondary" domain controllers although it works fine in native powershell.
			# Using WinRM here doesn't work for multiple reasons so instead we're going to run it only on the schemamaster which is hopefully still the first domain controller.
			# Also need to chagne this to re-import the GPO even if the GPO exist. The SSH user that is running the service might change, and the GPO will have the old SID. 
			gpo_name = "ec2config-ssh-privileges"
			if is_schemamaster?(node.ad.domain_name, node.ad.computer_name)
				unless gpo_exist?(gpo_name)
					["Machine\\microsoft\\windows nt\\SecEdit", "Machine\\Scripts\\Shutdown", "Machine\\Scripts\\Startup", "User"].each { |dir|
						directory "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\DomainSysvol\\GPO\\#{dir}" do
							recursive true
						end
					}

					ssh_user_sid = powershell_out("(New-Object System.Security.Principal.NTAccount('#{node.ad.netbios_name}', '#{sshd_username}')).Translate([System.Security.Principal.SecurityIdentifier]).value").stdout.strip
					ec2config_user_sid = powershell_out("(New-Object System.Security.Principal.NTAccount('#{node.ad.netbios_name}', '#{ec2config_username}')).Translate([System.Security.Principal.SecurityIdentifier]).value").stdout.strip
					# ssh_user_sid = powershell_out("Invoke-Command -ScriptBlock { (New-Object System.Security.Principal.NTAccount('#{node.ad.netbios_name}', '#{sshd_username}')).Translate([System.Security.Principal.SecurityIdentifier]).value } -ComputerName #{node.ipaddress} -Credential (New-Object System.Management.Automation.PSCredential('#{node.ad.netbios_name}\\#{ad_vault[node.ad.domain_admin_username_field]}', (ConvertTo-SecureString '#{password}' -AsPlainText -Force)))").stdout.strip
					# ec2config_user_sid = powershell_out("Invoke-Command -ScriptBlock { (New-Object System.Security.Principal.NTAccount('#{node.ad.netbios_name}', '#{ec2config_username}')).Translate([System.Security.Principal.SecurityIdentifier]).value } -ComputerName #{node.ipaddress} -Credential (New-Object System.Management.Automation.PSCredential('#{node.ad.netbios_name}\\#{ad_vault[node.ad.domain_admin_username_field]}', (ConvertTo-SecureString '#{password}' -AsPlainText -Force)))").stdout.strip

					Chef::Log.info("ssh_user_sid #{ssh_user_sid}")
					Chef::Log.info("ec2config_user_sid #{ec2config_user_sid}")

					template "#{Chef::Config[:file_cache_path]}\\gpo\\manifest.xml" do
						source "manifest.xml.erb"
						variables(
							:domain_name => node.ad.domain_name,
							:computer_name => node.ad.computer_name
						)
					end

					template "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\Backup.xml" do
						source "Backup.xml.erb"
						variables(
							:domain_name => node.ad.domain_name,
							:computer_name => node.ad.computer_name,
							:netbios_name => node.ad.netbios_name
						)
					end

					template "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\bkupInfo.xml" do
						source "bkupInfo.xml.erb"
						variables(
							:domain_name => node.ad.domain_name,
							:computer_name => node.ad.computer_name
						)
					end

					template "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\gpreport.xml" do
						source "gpreprt.xml.erb"
						variables(
							:domain_name => node.ad.domain_name,
							:computer_name => node.ad.computer_name,
							:netbios_name => node.ad.netbios_name,
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
							Invoke-Command -ScriptBlock { Import-GPO -BackupId 24E13F41-7118-4FB6-AE8B-45D48AFD6AFE -TargetName #{gpo_name} -path #{Chef::Config[:file_cache_path]}\\gpo -CreateIfNeeded } -ComputerName #{node.ipaddress} -Credential (New-Object System.Management.Automation.PSCredential('#{node.ad.netbios_name}\\#{ad_vault[node.ad.domain_admin_username_field]}', (ConvertTo-SecureString '#{password}' -AsPlainText -Force)))
							new-gplink -name #{gpo_name} -target 'dc=#{node.ad.domain_name.gsub(".", ",dc=")}'
							gpupdate /force
						EOH
					end

					# powershell_out("Import-GPO -BackupId 24E13F41-7118-4FB6-AE8B-45D48AFD6AFE -TargetName #{gpo_name} -path #{Chef::Config[:file_cache_path]}\\gpo -CreateIfNeeded").run_command
					# powershell_out("new-gplink -name #{gpo_name} -target 'dc=#{node.ad.domain_name.gsub(".", ",dc=")}'").run_command
				end
			end
		else
			[sshd_username, ec2config_username].each { |user|
				powershell_script "Add domain SSH service user to local Administrators group" do
					code <<-EOH
						$domain_user = [ADSI]("WinNT://#{node.ad.netbios_name}/#{user}")
						$local_admin_group = [ADSI]("WinNT://./Administrators")
						$local_admin_group.PSBase.Invoke("Add",$domain_user.PSBase.Path)
					EOH
					not_if "net localgroup Administrators | findstr #{node.ad.netbios_name}\\#{user}"
				end
			}
		end
	else 
		# We want to run ec2config as admin user so Windows userdata executes as admin, however the local admin account doesn't have Logon As a Service right. Domain privileges are set separately	 
		cookbook_file "c:\\Windows\\SysWOW64\\ntrights.exe" do
			source "ntrights"
		end

		[sshd_username, ec2config_username].each { |usr|
			user usr do
				password ec2config_password if usr == ec2config_username
				password sshd_password if usr == sshd_username
			end

			group "Administrators" do
				action :modify
				members usr
				append true
			end

			%w{SeDenyRemoteInteractiveLogonRight SeDenyInteractiveLogonRight SeServiceLogonRight}.each { |privilege|
				batch "Grant local Admin user #{usr} logon as service right" do
					code "C:\\Windows\\SysWOW64\\ntrights +r #{privilege} -u #{usr}"
				end
			}

			if usr == sshd_username
				%w{SeCreateTokenPrivilege SeTcbPrivilege SeAssignPrimaryTokenPrivilege}.each { |privilege|
				batch "Grant local Admin user #{usr} logon as service right" do
					code "C:\\Windows\\SysWOW64\\ntrights +r #{privilege} -u #{usr}"
				end
				}
			end
		}
	end

	execute "Set ec2config service to login with ec2config user" do
		not_if "sc qc Ec2Config | findstr SERVICE_START_NAME | findstr #{ec2config_guard}"
		command "sc config Ec2Config obj= \"#{ec2config_service_username}\" password= \"#{ec2config_password}\""
		notifies :restart, "service[Ec2Config]", :delayed
		# notifies :request, 'windows_reboot[1]'
		sensitive true
	end

	# To do: Replace existing guard with guard that checks if the user running the task is admin.
	# Or allow userdata to be rerun everytime the recipe is run
	powershell_script "Import run-userdata scheduled task" do
		guard_interpreter :powershell_script
		code "Register-ScheduledTask -Xml (get-content '#{Chef::Config[:file_cache_path]}/run-userdata_scheduledtask.xml' | out-string) -TaskName 'run-userdata' -User #{username} -Password '#{password}' -Force"
		only_if "((schtasks /TN 'run-userdata' /query /FO LIST -v | Select-String 'Run As User') -replace '`n|`r').split(':')[1].trim() -ne '#{username}'"
		# not_if "Get-ScheduledTask -TaskName 'run-userdata'"
		notifies :delete, "file[C:\\bin\\cygwin\\sshd_installed_by.txt]", :immediately
		# notifies :run, "powershell_script[kill sshd processes]", :immediately
		notifies :run, "windows_task[run-userdata]", :immediately
		# notifies :run, "execute[Taskkill /im sshd.exe /f /t]", :immediately #windows userdata should already be killing the any running ssh sessions. Killing SSH sessions at this point is problematic for AD nodes
	end

	# Need to add a guard to this.
	powershell_script "Import run-chef-client scheduled task" do
		guard_interpreter :powershell_script
		code "Register-ScheduledTask -Xml (get-content '#{Chef::Config[:file_cache_path]}/run_chefclient_scheduledtask.xml' | out-string) -TaskName 'run-chef-client' -User #{username} -Password '#{password}' -Force"
		# only_if "((schtasks /TN 'run-chef-client' /query /FO LIST -v | Select-String 'Run As User') -replace '`n|`r').split(':')[1].trim() -ne '#{username}'"
		# not_if "Get-ScheduledTask -TaskName 'run-chef-client'"
	end

	execute "Set sshd service to login with ssh user" do
		not_if "sc qc sshd | findstr SERVICE_START_NAME | findstr #{sshd_guard}"
		command "sc config sshd obj= \"#{sshd_service_username}\" password= \"#{sshd_password}\""
		# notifies :restart, "service[sshd]", :immediately
		notifies :run, "powershell_script[restart sshd service]", :immediately
		sensitive true
	end

	execute "Taskkill /im sshd.exe /f /t" do
		action :nothing
		returns [0, 128]
	end

	powershell_script "kill sshd processes" do
		code "Stop-Process -ProcessName sshd -force"
		action :nothing
		returns [0, 1]
	end

	powershell_script "restart sshd service" do
		code "Invoke-Expression '& C:/bin/cygwin/bin/bash --login -c \"chown #{sshd_username} /var/empty\"'; Stop-Process -ProcessName sshd -force; Stop-Service sshd -Force; Start-Service sshd; sleep 5; Start-Service sshd"
		action :nothing
	end
	

	if node.aws.instance_id
		file "C:\\bin\\cygwin\\#{node.aws.instance_id}" do 
			action :nothing
		end
	end rescue NoMethodError

	file "C:\\bin\\cygwin\\sshd_installed_by.txt" do 
		action :nothing
	end

	windows_task 'run-userdata' do
		action :nothing
	end

	windows_task 'run-chef-client' do
		action :nothing
	end

	# just making sure, pointless for the most part because notifies doesn't seem to work on windows_task.
	# The password is set correctly
	windows_task "run-userdata" do
		action :change
		user username
		password "\"#{password}\""
		sensitive true
		notifies :run, "windows_task[run-userdata]", :immediately
	end

	windows_reboot 1 do
		reason 'Applying updates'
		action :nothing
	end

	if registry_key_exists?("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired")
		ruby_block "restart windows" do
			block do
				puts "Restarting Windows"
			end
			notifies :request, 'windows_reboot[1]'
		end
		execute "shutdown -r -f -t 0"
	end
end
