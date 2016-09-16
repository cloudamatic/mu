require 'chef/mixin/shell_out'
include Chef::Mixin::PowershellOut
include Chef::Mixin::ShellOut

module Mutools
  module Helper
    def elversion
      return 6 if node.platform_version.to_i == 2013
      return 6 if node.platform_version.to_i == 2014
      return 6 if node.platform_version.to_i == 2015
      return 6 if node.platform_version.to_i == 2016
      node.platform_version.to_i
    end

    def service_user_set?(service, user)
      cmd = powershell_out("$service = Get-WmiObject Win32_service | Where-Object {$_.Name -eq '#{service}'}; $service.startname -eq '#{user}'")
      return cmd.stdout.match(/True/)
    end

    def user_in_local_admin_group?(user)
      cmd = powershell_out("$group = [ADSI]('WinNT://./Administrators'); $group.IsMember('WinNT://#{new_resource.netbios_name}/#{user}')")
      return cmd.stdout.match(/True/)
    end

    def get_mu_master_ips
      master_ips = []
      master_ips << "127.0.0.1" if node.name == "MU-MASTER"
      master = search(:node, "name:MU-MASTER")
      master.each { |server|
        next if !server.has_key?("ec2")
        master_ips << server['ec2']['public_ipv4'] if server['ec2'].has_key?('public_ipv4') and !server['ec2']['public_ipv4'].nil? and !server['ec2']['public_ipv4'].empty?
        master_ips << server['ec2']['local_ipv4'] if !server['ec2']['local_ipv4'].nil? and !server['ec2']['local_ipv4'].empty?
      }

      return master_ips
    end
  end
end

Chef::Recipe.send(:include, Mutools::Helper)
Chef::Resource.send(:include, Mutools::Helper)
Chef::Provider.send(:include, Mutools::Helper)
