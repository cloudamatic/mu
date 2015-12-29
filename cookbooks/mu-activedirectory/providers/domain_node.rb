#
# Cookbook Name:: mu-activedirectory
# Provider:: domain_node
#
# Copyright 2015, eGlobalTech,
#
# All rights reserved - Do Not Redistribute
#

require 'chef/mixin/shell_out'
include Chef::Mixin::ShellOut
include Chef::Mixin::PowershellOut

def whyrun_supported?
  true
end

action :add do
  case node.platform
    when "windows"
      set_client_dns
      elevate_remote_access
      join_domain_windows
      set_computer_name(join_domain_creds)
    when "centos", "redhat"
      install_ad_client_packages
      join_domain_linux
    else
      Chef::Log.info("Unsupported platform #{node.platform}")
  end
end

action :remove do
  case node.platform
    when "windows"
      unjoin_domain_windows
    when "centos", "redhat"
      unjoin_domain_linux
    else
      Chef::Log.info("Unsupported platform #{node.platform}")
  end
end

# def load_current_resource
# @current_resource = @new_resource.dup
# end

def join_domain_creds
  "(New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.join_user}', (ConvertTo-SecureString '#{new_resource.join_password}' -AsPlainText -Force)))"
end

def join_domain_windows
  unless in_domain?
    # This will allow us to add a new computer account to the correct OU so the right group policy is applied
    new_name = nil
    new_name = "-NewName #{new_resource.computer_name}" if node.hostname.downcase != new_resource.computer_name.downcase

    if new_resource.computer_ou
      code = "Add-Computer -DomainName #{new_resource.dns_name} -Credential#{join_domain_creds} #{new_name} -OUPath '#{new_resource.computer_ou}' -PassThru -Restart -Verbose -Force"
    else
      code = "Add-Computer -DomainName #{new_resource.dns_name} -Credential#{join_domain_creds} #{new_name} -PassThru -Restart -Verbose -Force"
    end

    Chef::Log.info("Joining #{new_resource.computer_name} node to #{new_resource.dns_name} domain")
    cmd = powershell_out(code)

    if cmd.stdout.include?("HasSucceeded") && cmd.stdout.include?("True")
      Chef::Log.info("Domain Join was successful")
      kill_ssh
      Chef::Application.fatal!("Successfully joined #{new_resource.computer_name} to #{new_resource.dns_name} domain, rebooting. Will have to run chef again")
    elsif cmd.stdout.include?("HasSucceeded") && cmd.stdout.include?("False")
      Chef::Log.fatal("Domain Join was NOT successful")
      Chef::Log.fatal("Domain join stderr #{cmd.stderr}")
      Chef::Application.fatal!("Failed to join #{new_resource.computer_name} to #{new_resource.dns_name} domain")
    else
      Chef::Log.fatal("Something went wrong during domain join. Command to join domain was: #{code}")
      Chef::Log.fatal("Domain join stderr #{cmd.stderr}")
      Chef::Application.fatal!("Failed to join #{new_resource.computer_name} to #{new_resource.dns_name} domain")
    end
  end
end

def set_client_dns
  cmd = powershell_out("Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses #{new_resource.dc_ips.join(", ")}")
  Chef::Log.info("Set DNS addresses to #{new_resource.dc_ips.join(", ")}")
end

def unjoin_domain_windows
  if in_domain?
    Chef::Log.info("Removing #{new_resource.computer_name} node from #{new_resource.dns_name} domain")
    cmd = powershell_out("Remove-Computer -UnjoinDomaincredential #{join_domain_creds} -Passthru -Verbose -Restart -Force")
    kill_ssh
    Chef::Application.fatal!("Failed to remove #{new_resource.computer_name} from #{new_resource.dns_name} domain") unless cmd.exitstatus == 0
    Chef::Application.fatal!("Removed #{new_resource.computer_name} from #{new_resource.dns_name} domain, rebooting. Will have to run chef again")
  end
end

def join_domain_linux
  %w{sshd winbind smb}.each { |svc|
    service svc do
      action :nothing
    end
  }

  service "messagebus" do
    action [:enable, :start]
  end

  set_selinux_policies
  config_ssh_ntp_dns
  create_pam_winbind_directories
  pam_winbind_lib
  configure_winbind_kerberos_authentication

  execute "Join domain #{new_resource.dns_name}" do
    command "net ads join #{new_resource.dns_name.downcase} -U #{new_resource.join_user}%#{new_resource.join_password}"
    sensitive true
    not_if "net ads testjoin | grep OK"
  end

  directory "#{node.ad.samba_conf_dir}/includes" do
    mode 0755
  end

  template "#{node.ad.samba_conf_dir}/smb.conf" do
    source "smb.conf.erb"
    owner "root"
    group "root"
    mode 0644
    notifies :restart, "service[smb]"
    notifies :restart, "service[winbind]"
    variables(
        :domain_name => new_resource.dns_name,
        :dcs => new_resource.dc_names,
        :netbios_name => new_resource.netbios_name,
        :include_file => "#{node.ad.samba_conf_dir}/includes/#{node.ad.samba_include_file}"
    )
  end
end

def install_ad_client_packages
# This is repo with a copy of the Samba packages hosted in the GlusterFS repo at http://download.gluster.org/pub/gluster/glusterfs/samba/EPEL.repo/epel-6/x86_64
  yum_repository "mu-platform" do
    description 'Mu-Platform Repo'
    url "https://s3.amazonaws.com/cap-public/repo/el/$releasever/$basearch/"
    enabled true
    gpgcheck false
  end

  %w{samba-winbind-modules authconfig krb5-workstation pam_krb5 samba-common oddjob-mkhomedir samba-winbind-clients}.each { |pkg|
    package pkg
  }

  if %w{centos redhat}.include?(node.platform) && node.platform_version.to_i == 7
    # execute "systemctl enable smb.service "
    package "samba"
    service "smb" do 
      action :enable
    end
  end
end

def set_selinux_policies
  # Disable SELinux. Need to test if existing policies below work without having to disabling SELinux.
  execute "setenforce 0"
  # Add Policies to SELinux to allow winbind and ssh to work correctly. TO DO - TEST THIS
  %w{winbindpol sshd_pol}.each { |policy_file|
    %w{te pp}.each { |ext|
      cookbook_file "#{Chef::Config[:file_cache_path]}/#{policy_file}.#{ext}" do
        source "#{policy_file}.#{ext}"
      end
    }

    execute "semodule -i #{policy_file}.pp" do
      cwd Chef::Config[:file_cache_path]
      not_if "semodule -l | grep #{policy_file}"
      notifies :restart, "service[winbind]", :immediately
      notifies :restart, "service[sshd]", :immediately
    end
  }

  execute "setsebool -P ssh_chroot_rw_homedirs 1" do
    not_if "grep ssh_chroot_rw_homedirs=1 /etc/selinux/targeted/modules/active/booleans.local"
  end
end

def config_ssh_ntp_dns
  template "/etc/ntp.conf" do
    source "ntp.conf.erb"
    owner "root"
    group "root"
    mode 0644
    variables(
        :dcs => new_resource.dc_names
    )
  end

  template "/etc/ssh/sshd_config" do
    source "sshd_config.erb"
    owner "root"
    group "root"
    cookbook "mu-tools"
    mode 0600
    notifies :restart, "service[sshd]", :immediately
    # variables(
    # :allow_password_auth => new_resource.allow_password_auth,
    # :allow_groups => new_resource.allow_groups,
    # :sftp_only_group => new_resource.sftp_only_group,
    # :sftp_chroot => new_resource.sftp_chroot
    # )
  end

  new_resource.dc_ips.each { |ip|
    execute "sed -i '2i nameserver #{ip}' /etc/resolv.conf" do
      not_if "grep #{ip} /etc/resolv.conf"
    end
  }
end

def create_pam_winbind_directories
  directory "/home/#{new_resource.dns_name}" do
    owner "root"
    group "root"
    mode 0755
  end

  %w[/run /run/samba /run/samba/winbindd].each { |path|
    directory path do
      owner "root"
      group "root"
      mode 0755
    end
  }

  directory "/etc/skel" do
    owner "root"
    group "root"
    mode 0700
  end

  %w{.bashrc .bash_profile .bash_logout}.each { |file|
    file "/etc/skel/#{file}" do
      owner "root"
      group "root"
      mode 0600
    end
  }
end

def pam_winbind_lib
  link "/lib64/security/pam_winbind.so" do
    to "/usr/lib64/security/pam_winbind.so"
  end

  execute "echo 'session optional pam_umask.so umask=0077' >> /etc/pam.d/sshd" do
    not_if "grep pam_umask.so /etc/pam.d/sshd"
  end
end

def configure_winbind_kerberos_authentication
  execute "authconfig --disablecache --enablewinbind --enablewinbindauth --smbsecurity=ads --smbworkgroup=#{new_resource.netbios_name.upcase} --smbrealm=#{new_resource.dns_name.upcase} --enablewinbindusedefaultdomain --winbindtemplatehomedir=/home/#{new_resource.dns_name.downcase}/%U --winbindtemplateshell=/bin/bash --enablekrb5 --krb5realm=#{new_resource.dns_name.upcase} --smbservers='#{new_resource.dc_names.join(" ")}' --enablekrb5kdcdns --enablekrb5realmdns --enablelocauthorize --enablemkhomedir --enablepamaccess --updateall" do
    not_if "grep pam_krb5.so /etc/pam.d/system-auth"
  end

  template "/etc/krb5.conf" do
    source "krb5.conf.erb"
    owner "root"
    group "root"
    mode 0644
    variables(
        :domain_name => new_resource.dns_name,
        :dcs => new_resource.dc_names
    )
    notifies :restart, "service[winbind]"
  end

  # Because authconfig doesn't always update those
  %w{password-auth system-auth}.each { |file|
    cookbook_file "/etc/pam.d/#{file}" do
      source file
      manage_symlink_source true
    end
  }
end

def unjoin_domain_linux
  execute "Unjoin domain #{new_resource.dns_name}" do
    command "net ads leave -U #{new_resource.join_user}%#{new_resource.join_password}"
    sensitive true
    only_if "net ads testjoin | grep OK"
  end
end
