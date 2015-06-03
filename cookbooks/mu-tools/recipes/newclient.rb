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

unless node[:recipes].include?("chef-server")
  file Chef::Config[:validation_key] do
    action :delete
    backup false
    only_if { ::File.exists?(Chef::Config[:client_key]) }
  end
end

include_recipe "mu-tools::updates"
if !node.ad.nil? and node.ad.size > 1
	if node.ad.domain_operation == "join"
		include_recipe "active-directory::domain-node"
	elsif node.ad.domain_operation == "create"
		include_recipe "active-directory::domain"
	elsif node.ad.domain_operation == "add_controller"
		include_recipe "active-directory::domain-controller"
	end
end rescue NoMethodError

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
		source 'https://s3.amazonaws.com/cap-public/run-userdata_scheduledtask.xmll'
	end
	
	if in_domain
		windows_vault = chef_vault_item(node.ad.auth_vault, node.ad.auth_item)
		username = "#{node.ad.netbios_name}\\#{windows_vault[node.ad.auth_username_field]}"
		password = windows_vault[node.ad.auth_password_field]
		ec2config_guard = "#{node.ad.netbios_name}\\\\#{windows_vault[node.ad.auth_username_field]}}"
	else
		username = node.windows_admin_username
		windows_vault = chef_vault_item(node.windows_auth_vault, node.windows_auth_item)
		password = windows_vault[node.windows_auth_password_field]
		ec2config_guard = ".\\\\#{username}"
	end rescue NoMethodError

	windows_task "run-userdata" do
		action :change
		user username
		password password
		sensitive true
		only_if "schtasks /TN 'run-userdata' /query"
		notifies :run, "windows_task[run-userdata]", :immediately
	end

	powershell_script "Import run-userdata scheduled task" do
		guard_interpreter :powershell_script
		code "Register-ScheduledTask -Xml (get-content '#{Chef::Config[:file_cache_path]}/run-userdata.xml' | out-string) -TaskName 'run-userdata' -User #{username} -Password '#{password}' -Force"
		not_if "Get-ScheduledTask -TaskName 'run-userdata'"
		notifies :run, "windows_task[run-userdata]", :immediately
	end

	windows_task 'run-userdata' do
		action :nothing
	end
	
	service "Ec2Config" do
		action :nothing
	end

	batch "Change ec2config service to run as admin user" do
		code "sc config Ec2Config obj= \"#{username}\" password= \"#{password}\""
		not_if "sc qc Ec2Config | findstr SERVICE_START_NAME | findstr #{ec2config_guard}"
		notifies :restart, "service[Ec2Config]", :delayed
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
end
