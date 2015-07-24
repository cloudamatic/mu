require 'chef/mixin/shell_out'
include Chef::Mixin::PowershellOut
include Chef::Mixin::ShellOut

module Mutools
	module Helper
		def ssh_user_set?(ssh_user_guard)
			cmd = powershell_out("$sshd_service = Get-WmiObject Win32_service | Where-Object {$_.Name -eq 'sshd'}; $sshd_service.startname -eq '#{ssh_user_guard}'")
			return cmd.stdout.match(/True/)
		end

		def service_user_set?(service, user)
			cmd = powershell_out("$service = Get-WmiObject Win32_service | Where-Object {$_.Name -eq '#{service}'}; $service.startname -eq '#{user}'")
			return cmd.stdout.match(/True/)
		end
		
		def user_in_local_admin_group?(user)
			cmd = powershell_out("$group = [ADSI]('WinNT://./Administrators'); $group.IsMember('WinNT://#{new_resource.netbios_name}/#{user}')")
			return cmd.stdout.match(/True/)
		end
	end
end

Chef::Recipe.send(:include, Mutools::Helper)
Chef::Resource.send(:include, Mutools::Helper)
Chef::Provider.send(:include, Mutools::Helper)
