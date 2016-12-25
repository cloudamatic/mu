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
      Chef::Log.info("node_hostname: #{node.hostname.downcase}, computer_name: #{new_resource.computer_name.downcase}")
      if node.hostname.downcase != new_resource.computer_name.downcase
        cmd = powershell_out("Rename-Computer -NewName '#{new_resource.computer_name}' -Force -PassThru -Restart -DomainCredential #{creds}")
        Chef::Application.fatal!("Failed to rename computer to #{new_resource.computer_name}") if cmd.exitstatus != 0
        execute "kill ssh for reboot" do
          command "Taskkill /im sshd.exe /f /t"
          returns [0, 128]
          action :nothing
        end
        reboot "Renaming computer to #{new_resource.computer_name}" do
          action :reboot_now
          reason "Renaming computer to #{new_resource.computer_name}"
          notifies :run, "execute[kill ssh for reboot]", :immediately
        end
        kill_ssh
      end
    end

    def elevate_remote_access
      unless uac_remote_restrictions_enabled?
        cmd = powershell_out("New-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name 'LocalAccountTokenFilterPolicy' -PropertyType DWord -Force -Value 1")
        Chef::Log.info("Allowing remote access with UAC")
        # inspect_exit_status(cmd, "UAC remote access")
      end
    end

    def network_interface_code
      dc_ips = nil
      dc_ips = new_resource.existing_dc_ips.join(",") unless new_resource.existing_dc_ips.empty?
      code =<<-EOH
				Stop-Process -ProcessName sshd -force -ErrorAction SilentlyContinue
				$netipconfig = Get-NetIPConfiguration
				$netadapter = Get-NetAdapter
				$netipaddress = $netadapter | Get-NetIPAddress -AddressFamily IPv4
				$netadapter | Set-NetIPInterface -Dhcp Disabled
				$netadapter | New-NetIPAddress -IPAddress #{node.ipaddress} -PrefixLength $netipaddress.PrefixLength -DefaultGateway $netipconfig.IPv4DefaultGateway.NextHop
				$netadapter | Set-DnsClientServerAddress -PassThru -ServerAddresses #{dc_ips}
      EOH
      return code
    end

    def configure_network_interface
      dc_ips = nil
      dc_ips = new_resource.existing_dc_ips.join(",") unless new_resource.existing_dc_ips.empty?

      if dhcp_enabled?
        code =<<-EOH
#{network_interface_code}
					Start-Service sshd -ErrorAction SilentlyContinue
        EOH
        cmd = powershell_out(code)
        Chef::Log.info("Set network interface to use static address")
        # inspect_exit_status(cmd, "set network interface")
      end

      unless dc_ips.nil?
        cmd = powershell_out("Get-NetAdapter | Set-DnsClientServerAddress -PassThru -ServerAddresses #{dc_ips}")
        Chef::Log.info("set DNS addresses to #{new_resource.existing_dc_ips.join(",")}")
        # inspect_exit_status(cmd, "set DNS addresses to #{new_resource.existing_dc_ips.join(",")}")
      end
    end

    def install_ad_features
      # Can't inspect exist code. Windows is reporting wrong exit code
      powershell_out("Install-WindowsFeature AD-Domain-Services, rsat-adds, FS-DFS-Replication, RSAT-DFS-Mgmt-Con -IncludeAllSubFeature")
    end

    def set_replication_static_ports
      # Can't inspect exist code of any of those. exit code 0 doesn't seem to mean what it should mean on Windows
      powershell_out("New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters -Name 'TCP/IP Port' -PropertyType DWord -Force -Value #{new_resource.ntds_static_port}") unless replication_tcp_port_set?
      powershell_out("New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTFRS\\Parameters -Name 'RPC TCP/IP Port Assignment' -PropertyType DWord -Force -Value #{new_resource.ntfrs_static_port}") unless replication_rpc_port_set?
      powershell_out("New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters -Name 'DCTcpipPort' -PropertyType DWord -Force -Value #{new_resource.netlogon_static_port}") unless netlogon_port_set?
      powershell_out("Set-DfsrServiceConfiguration -RPCPort #{new_resource.dfsr_static_port}") unless dfsr_rpc_port_set?
    end

    # Workaround for a really crappy issue with cygwin/ssh and windows where we need to end all ssh process,
    # or Mu's SSH session / chef client run won't disconnect even though the client chef run has finished or the SSH session has closed.
    def kill_ssh
      execute "Taskkill /im sshd.exe /f /t" do
        returns [0, 128]
      end
    end

  end
end

Chef::Recipe.send(:include, Activedirectory::Config)
Chef::Resource.send(:include, Activedirectory::Config)
Chef::Provider.send(:include, Activedirectory::Config)
