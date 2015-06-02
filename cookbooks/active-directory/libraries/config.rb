require 'chef/mixin/shell_out'
include Chef::Mixin::PowershellOut
include Chef::Mixin::ShellOut

module Activedirectory
	module Config
		def inspect_exit_status(output, description)
			Chef::Application.fatal!("Failed to #{description}: #{output.stderr}") unless output.exitstatus == 0
			Chef::Log.info(description)
		end

		def admin_creds
			"(New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.domain_admin_user}', (ConvertTo-SecureString '#{new_resource.domain_admin_password}' -AsPlainText -Force)))"
		end

		def set_computer_name(creds)
			# Theoretically this should have been done for us already, but let's cover the oddball cases.
			if node.hostname.upcase != new_resource.computer_name.upcase
				cmd = powershell_out("Rename-Computer -NewName '#{new_resource.computer_name}' -Force -PassThru -Restart -DomainCredential #{creds}").run_command
				Chef::Application.fatal!("Failed to rename computer to #{new_resource.computer_name}") unless cmd.exitstatus == 0
				Chef::Application.fatal!("Renamed computer to #{new_resource.computer_name}, rebooting. Will have to run chef again")
			end
		end

		def elevate_remote_access
			unless uac_remote_restrictions_enabled?
				cmd = powershell_out("New-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name 'LocalAccountTokenFilterPolicy' -PropertyType DWord -Force -Value 1").run_command
				inspect_exit_status(cmd, "UAC remote access")
			end
		end

		def configure_network_interface
			if dhcp_enabled?
				code =<<-EOH
					$netipconfig = Get-NetIPConfiguration
					$netadapter = Get-NetAdapter
					$netipaddress = $netadapter | Get-NetIPAddress -AddressFamily IPv4
					$netadapter | Set-NetIPInterface -Dhcp Disabled
					$netadapter | New-NetIPAddress -IPAddress #{node.ipaddress} -PrefixLength $netipaddress.PrefixLength -DefaultGateway $netipconfig.IPv4DefaultGateway.NextHop
				EOH
				cmd = powershell_out(code).run_command
				inspect_exit_status(cmd, "set network interface")
			end

			unless new_resource.existing_dc_ips.empty?
				cmd = powershell_out("Get-NetAdapter | Set-DnsClientServerAddress -PassThru -ServerAddresses #{new_resource.existing_dc_ips.join(",")}").run_command
				inspect_exit_status(cmd, "set DNS addresses to #{new_resource.existing_dc_ips.join(",")}")
			end
		end

		def install_ad_features
			# Can't inspect exist code. Windows is reporting wrong exit code
			powershell_out("Install-WindowsFeature AD-Domain-Services, rsat-adds, FS-DFS-Replication, RSAT-DFS-Mgmt-Con -IncludeAllSubFeature").run_command
		end

		def set_replication_static_ports
			# Can't inspect exist code of any of those. Windows is reporting wrong exit code
			powershell_out("New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters -Name 'TCP/IP Port' -PropertyType DWord -Force -Value #{new_resource.ntds_static_port}").run_command unless replication_tcp_port_set?
			powershell_out("New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTFRS\\Parameters -Name 'RPC TCP/IP Port Assignment' -PropertyType DWord -Force -Value #{new_resource.ntfrs_static_port}").run_command unless replication_rpc_port_set?
			powershell_out("New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters -Name 'DCTcpipPort' -PropertyType DWord -Force -Value #{new_resource.netlogon_static_port}").run_command unless netlogon_port_set?
			powershell_out("Set-DfsrServiceConfiguration -RPCPort #{new_resource.dfsr_static_port}").run_command unless dfsr_rpc_port_set?
		end
	end
end

Chef::Recipe.send(:include, Activedirectory::Config)
Chef::Resource.send(:include, Activedirectory::Config)
Chef::Provider.send(:include, Activedirectory::Config)
