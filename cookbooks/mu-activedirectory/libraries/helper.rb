require 'chef/mixin/shell_out'
include Chef::Mixin::PowershellOut
include Chef::Mixin::ShellOut

module Activedirectory
  module Helper
    def elversion
      return 6 if node['platform_version'].to_i == 2013
      return 6 if node['platform_version'].to_i == 2014
      return 6 if node['platform_version'].to_i == 2015
      return 6 if node['platform_version'].to_i == 2016
      node['platform_version'].to_i
    end

    def in_domain?
      cmd = powershell_out("((Get-WmiObject win32_computersystem).partofdomain -eq $true)")
      return cmd.stdout.match(/True/)
    end

    def domain_controller?(hostname)
      # cmd = powershell_out("(Get-ADDomainController).name -eq '#{new_resource.computer_name}'")
      cmd = powershell_out("(Get-ADDomainController).name -eq '#{hostname}'")
      return cmd.stdout.match(/True/)
    end

    def dhcp_enabled?
      cmd = powershell_out("(Get-NetIPInterface -InterfaceAlias Ethernet* -AddressFamily IPv4).Dhcp -eq 'Enabled'")
      return cmd.stdout.match(/True/)
    end

    def domain_exists?
      cmd = powershell_out("(Get-ADDomain).DNSRoot -eq '#{new_resource.dns_name}'")
      return cmd.stdout.match(/True/)
    end

    def replication_rpc_port_set?
      cmd = powershell_out("(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTFRS\\Parameters 'RPC TCP/IP Port Assignment').'RPC TCP/IP Port Assignment' -eq \"#{new_resource.ntfrs_static_port}\"")
      return cmd.stdout.match(/True/)
    end

    def replication_tcp_port_set?
      cmd = powershell_out("(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters 'TCP/IP Port').'TCP/IP Port' -eq \"#{new_resource.ntds_static_port}\"")
      return cmd.stdout.match(/True/)
    end

    def dfsr_rpc_port_set?
      cmd = powershell_out("(Get-DfsrServiceConfiguration).RPCPort -eq #{new_resource.dfsr_static_port}")
      return cmd.stdout.match(/True/)
    end

    def netlogon_port_set?
      cmd = powershell_out("(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters 'DCTcpipPort').'DCTcpipPort' -eq \"#{new_resource.netlogon_static_port}\"")
      return cmd.stdout.match(/True/)
    end

    def domain_user_exist?(user)
      cmd = powershell_out("(Get-ADUser -Filter {Name -eq '#{user}'}).Name -eq '#{user}'")
      return cmd.stdout.match(/True/)
    end

    def uac_remote_restrictions_enabled?
      cmd = powershell_out("(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System 'LocalAccountTokenFilterPolicy').'LocalAccountTokenFilterPolicy' -eq 1")
      return cmd.stdout.match(/True/)
    end

    def default_site_name_set?
      cmd = powershell_out("(Get-ADReplicationSite).name -eq '#{new_resource.site_name}'")
      return cmd.stdout.match(/True/)
    end

    def gpo_exist?(gpo_name)
      cmd = powershell_out("(Get-GPO -Name #{gpo_name}).DisplayName -eq '#{gpo_name}'")
      return cmd.stdout.match(/True/)
    end

    def schemamaster?(domain_name, hostname)
      cmd = powershell_out("(Get-ADForest #{domain_name}).SchemaMaster -eq '#{hostname.downcase}.#{domain_name}'")
      return cmd.stdout.match(/True/)
    end
  end
end

Chef::Node.send(:include, Activedirectory::Helper)
Chef::Recipe.send(:include, Activedirectory::Helper)
Chef::Resource.send(:include, Activedirectory::Helper)
Chef::Provider.send(:include, Activedirectory::Helper)
