require 'chef/mixin/shell_out'
include Chef::Mixin::ShellOut
include Chef::Mixin::PowershellOut

def whyrun_supported?
	true
end

action :add do
	install_ad_features
	configure_network_interface
	join_domain
	promote
	set_replication_static_ports
	set_computer_name
end

action :remove do
	demote
end

def load_current_resource
	@current_resource = @new_resource.dup
end

case node.platform
when "windows"
	def admin_creds
		"(New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.domain_admin_user}', (ConvertTo-SecureString '#{new_resource.domain_admin_password}' -AsPlainText -Force)))"
	end

	def promote
		unless is_domain_controller?
			cmd = powershell_out("Install-ADDSDomainController -InstallDns -DomainName #{new_resource.dns_name} -Credential #{admin_creds} -SafeModeAdministratorPassword (convertto-securestring '#{new_resource.restore_mode_password}' -asplaintext -force) -Force -Confirm:$false").run_command
			#Lets make sure the run breaks here
			execute "shutdown -r -f -t 0"
		end
	end

	def demote
		if is_domain_controller?
			cmd = powershell_out("").run_command
			#Lets make sure the run breaks here
			execute "shutdown -r -f -t 0"
		end
	end

	def join_domain
		unless in_domain?
			cmd = powershell_out("Add-Computer -DomainName #{new_resource.dns_name} -Credential #{admin_creds} -newname #{new_resource.computer_name} -Restart -PassThru").run_command
			#Let's make sure the run breaks here
			execute "shutdown -r -f -t 0"
		end
	end

	def configure_network_interface
		if dhcp_enabled?
			code =<<-EOH
				$netipconfig = Get-NetIPConfiguration
				$netadapter = Get-NetAdapter
				$netipaddress = $netadapter | Get-NetIPAddress -AddressFamily IPv4
				$netadapter | Set-NetIPInterface -Dhcp Disabled
				$netadapter | New-NetIPAddress -IPAddress #{node.ec2.private_ip_address} -PrefixLength $netipaddress.PrefixLength -DefaultGateway $netipconfig.IPv4DefaultGateway.NextHop
			EOH
			cmd = powershell_out(code).run_command
		end

		cmd = powershell_out("Get-NetAdapter | Set-DnsClientServerAddress -PassThru -ServerAddresses #{new_resource.existing_dc_ips.join(",")}").run_command if !new_resource.existing_dc_ips.empty?
	end

	def install_ad_features
		cmd = powershell_out("Install-WindowsFeature AD-Domain-Services, rsat-adds, FS-DFS-Replication, RSAT-DFS-Mgmt-Con -IncludeAllSubFeature").run_command
	end

	def set_replication_static_ports
		cmd = powershell_out("New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters -Name 'TCP/IP Port' -PropertyType DWord -Force -Value #{new_resource.ntds_static_port}").run_command unless replication_tcp_port_set?
		cmd = powershell_out("New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTFRS\\Parameters -Name 'RPC TCP/IP Port Assignment' -PropertyType DWord -Force -Value #{new_resource.ntfrs_static_port}").run_command unless replication_rpc_port_set?
		cmd = powershell_out("New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters -Name 'DCTcpipPort' -PropertyType DWord -Force -Value #{new_resource.netlogon_static_port}").run_command unless netlogon_port_set?
		cmd = powershell_out("Set-DfsrServiceConfiguration -RPCPort #{new_resource.dfsr_static_port}").run_command unless dfsr_rpc_port_set?
	end

	def set_computer_name
		# Theoretically this should have been done for us already, but let's cover the oddball cases.
		if node.hostname != new_resource.computer_name
			cmd = powershell_out("Rename-Computer -NewName '#{new_resource.computer_name}' -Force -PassThru -Restart -DomainCredential#{admin_creds}").run_command
			execute "shutdown -r -f -t 0"
		end
	end
	
	def elevate_remote_access
		cmd = powershell_out("New-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name 'LocalAccountTokenFilterPolicy' -PropertyType DWord -Force -Value 1").run_command unless uac_remote_restrictions_enabled?
	end

	def in_domain?
		cmd = powershell_out("((Get-WmiObject win32_computersystem).partofdomain -eq $true)").run_command
		return cmd.stdout.match(/True/)
	end

	def is_domain_controller?
		cmd = powershell_out("(Get-ADDomainController).name -eq '#{new_resource.computer_name}'").run_command
		return cmd.stdout.match(/True/)
	end

	def dhcp_enabled?
		cmd = powershell_out("(Get-NetIPInterface -InterfaceAlias Ethernet* -AddressFamily IPv4).Dhcp -eq 'Enabled'").run_command
		return cmd.stdout.match(/True/)
	end

	def replication_rpc_port_set?
		cmd = powershell_out("(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTFRS\\Parameters 'RPC TCP/IP Port Assignment').'RPC TCP/IP Port Assignment' -eq \"#{new_resource.ntfrs_static_port}\"").run_command
		return cmd.stdout.match(/True/)
	end

	def replication_tcp_port_set?
		cmd = powershell_out("(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters 'TCP/IP Port').'TCP/IP Port' -eq \"#{new_resource.ntds_static_port}\"").run_command
		return cmd.stdout.match(/True/)
	end

	def dfsr_rpc_port_set?
		cmd = powershell_out("(Get-DfsrServiceConfiguration).RPCPort -eq #{new_resource.dfsr_static_port}").run_command
		return cmd.stdout.match(/True/)
	end

	def netlogon_port_set?
		cmd = powershell_out("(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters 'DCTcpipPort').'DCTcpipPort' -eq \"#{new_resource.netlogon_static_port}\"").run_command
		return cmd.stdout.match(/True/)
	end

	def uac_remote_restrictions_enabled?
		cmd = powershell_out("(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System 'LocalAccountTokenFilterPolicy').'LocalAccountTokenFilterPolicy' -eq 1").run_command
		return cmd.stdout.match(/True/)
	end

when "centos", "redhat"
	# do something
else
	Chef::Log.info("Unsupported platform #{node.platform}")
end
