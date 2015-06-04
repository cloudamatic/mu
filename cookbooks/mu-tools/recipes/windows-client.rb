# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#     http://egt-labs.com/mu/LICENSE.html
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

	def in_domain
		cmd = powershell_out("((Get-WmiObject win32_computersystem).partofdomain -eq $true)").run_command
		return cmd.stdout.match(/True/)
	end

	remote_file "#{Chef::Config[:file_cache_path]}/run-userdata.xml" do
		source "https://s3.amazonaws.com/cap-public/run-userdata_scheduledtask.xml"
	end
	
	if in_domain
		windows_vault = chef_vault_item(node.ad.auth_vault, node.ad.auth_item)
		username = "#{node.ad.netbios_name}\\#{windows_vault[node.ad.auth_username_field]}"
		password = windows_vault[node.ad.auth_password_field]
		ec2config_guard = "#{node.ad.netbios_name}\\\\#{windows_vault[node.ad.auth_username_field]}}"
		ec2config_username = username
	else
		username = node.windows_admin_username
		windows_vault = chef_vault_item(node.windows_auth_vault, node.windows_auth_item)
		password = windows_vault[node.windows_auth_password_field]
		ec2config_guard = ".\\\\#{username}"
		ec2config_username = ".\\#{username}"
	end rescue NoMethodError

	service "Ec2Config" do
		action :nothing
	end

	if !in_domain
		# We want to run ec2config as admin user so Windows userdata executes as admin, however the local admin account doesn't have Logon As a Service right. Domain privileges are set separately  
        cookbook_file "c:\\Windows\\SysWOW64\\ntrights.exe" do
            source "ntrights"
        end

        batch "Grant local Admin user #{username} logon as service right" do
            code "C:\\Windows\\SysWOW64\\ntrights +r SeServiceLogonRight -u #{username}"
        end
	end

	batch "Change ec2config service to run as admin user" do
		code "sc config Ec2Config obj= \"#{ec2config_username}\" password= \"#{password}\""
		not_if "sc qc Ec2Config | findstr SERVICE_START_NAME | findstr #{ec2config_guard}"
		notifies :restart, "service[Ec2Config]", :delayed
		# notifies :request, 'windows_reboot[1]'
		sensitive true
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
	
	# To do: Replace existing guard with guard that checks if the user running the task is admin.
	# Or allow userdata to be rerun everytime the recipe is run
	powershell_script "Import run-userdata scheduled task" do
		guard_interpreter :powershell_script
		code "Register-ScheduledTask -Xml (get-content '#{Chef::Config[:file_cache_path]}/run-userdata.xml' | out-string) -TaskName 'run-userdata' -User #{username} -Password '#{password}' -Force"
		only_if "((schtasks /TN 'run-userdata' /query /FO LIST -v | Select-String 'Run As User') -replace '`n|`r').split(':')[1].trim() -ne '#{username}'"
		# not_if "Get-ScheduledTask -TaskName 'run-userdata'"
		notifies :delete, "file[C:\\bin\\cygwin\\#{node.ec2.instance_id}]", :immediately
		notifies :delete, "file[C:\\bin\\cygwin\\sshd_installed_by.txt]", :immediately
		# notifies :run, "powershell_script[kill sshd processes]", :immediately
		notifies :run, "windows_task[run-userdata]", :immediately
		notifies :run, "execute[Taskkill /im sshd.exe /f /t]", :immediately
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

	file "C:\\bin\\cygwin\\#{node.ec2.instance_id}" do 
		action :nothing
	end
	
	file "C:\\bin\\cygwin\\sshd_installed_by.txt" do 
		action :nothing
	end

	windows_task 'run-userdata' do
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
end
