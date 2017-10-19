resource_name :windows_users

property :computer_name, String, name_property: true
property :password, String, required: true
property :username, String, required: true
property :ssh_user, String, required: true
property :ssh_password, String, required: true
property :ec2config_user, String, required: true
property :ec2config_password, String, required: true
property :domain_name, String
property :netbios_name, String
property :dc_ips, Array

default_action :config

action :config do

  cookbook_file "c:\\Windows\\SysWOW64\\ntrights.exe" do
    source "ntrights"
  end

  if is_domain_controller?(new_resource.computer_name)
    [new_resource.username, new_resource.ssh_user, new_resource.ec2config_user].each { |user|
      unless domain_user_exist?(user)
        pwd = 
          if user == new_resource.username
            new_resource.password
          elsif user == new_resource.ssh_user
            new_resource.ssh_password
          elsif user == new_resource.ec2config_user
            new_resource.ec2config_password
          end

        group = 
          if user == new_resource.username
            "Domain Admins"
          elsif user == new_resource.ssh_user
            "Domain Admins"
          elsif user == new_resource.ec2config_user
            "Administrators"
          end

        script =<<-EOH
          New-ADUser -Name #{user} -UserPrincipalName #{user}@#{new_resource.domain_name} -AccountPassword (ConvertTo-SecureString -AsPlainText '#{pwd}' -force) -Enabled $true -PasswordNeverExpires $true -PassThru
          Add-ADGroupMember '#{group}' -Members #{user} -PassThru
        EOH

        converge_by("Create Domain user #{user}") do
          cmd = powershell_out(script)
        end
      end
    }

    # This is a workaround because user data might re-install cygwin and use a random password that we don't know about. This is not idempotent, it just doesn't throw an error.
    # XXX I think this has been resetting the domain sshd user's password, which
    # is bad. Either that, or Cygwin has been, and this is the thing trying to
    # solve that problem.
    script =<<-EOH
      Add-ADGroupMember 'Domain Admins' -Members #{new_resource.ssh_user} -PassThru
#      Set-ADAccountPassword -Identity #{new_resource.ssh_user} -NewPassword (ConvertTo-SecureString -AsPlainText '#{new_resource.ssh_password}' -Force) -PassThru
    EOH

    converge_by("Added #{new_resource.ssh_user} to Domain Admin group and reset its password") do
      cmd = powershell_out(script)
    end

    # Ugh! we can't run this because at this point the sshd service is running under a user that doesn't have sufficient privileges in the domain. Need to RDP at this point. Why aren't we bootstrapping with WinRM???????
    # Another problem with cygwin is that gpo_exist? fails on "secondary" domain controllers although it works fine in native powershell.
    # Using WinRM here doesn't work for multiple reasons so instead we're going to run it only on the schemamaster which is hopefully still the first domain controller.
    # Also need to chagne this to re-import the GPO even if the GPO exist. The SSH user that is running the service might change, and the GPO will have the old SID.
    gpo_name = "ec2config-ssh-privileges"
    if is_schemamaster?(new_resource.domain_name, new_resource.computer_name)
      unless gpo_exist?(gpo_name)
        ["Machine\\microsoft\\windows nt\\SecEdit", "Machine\\Scripts\\Shutdown", "Machine\\Scripts\\Startup", "User"].each { |dir|
          directory "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\DomainSysvol\\GPO\\#{dir}" do
            recursive true
          end
        }

        ssh_user_sid = powershell_out("(New-Object System.Security.Principal.NTAccount('#{new_resource.netbios_name}', '#{new_resource.ssh_user}')).Translate([System.Security.Principal.SecurityIdentifier]).value").stdout.strip
        ec2config_user_sid = powershell_out("(New-Object System.Security.Principal.NTAccount('#{new_resource.netbios_name}', '#{new_resource.ec2config_user}')).Translate([System.Security.Principal.SecurityIdentifier]).value").stdout.strip
        # We're giving the Administrators group all the privileges the SSH user needs to make sure the local SSH user still has privileges after joining the domain so we can complete our chef run without relying on the run-chef-client  scheduled task to exist/run
        administrators_group_sid = powershell_out("(New-Object System.Security.Principal.NTAccount('Administrators')).Translate([System.Security.Principal.SecurityIdentifier]).value").stdout.strip
        # ssh_user_sid = powershell_out("Invoke-Command -ScriptBlock { (New-Object System.Security.Principal.NTAccount('#{new_resource.netbios_name}', '#{new_resource.ssh_user}')).Translate([System.Security.Principal.SecurityIdentifier]).value } -ComputerName #{node[:ipaddress]} -Credential (New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.username}', (ConvertTo-SecureString '#{new_resource.password}' -AsPlainText -Force)))").stdout.strip
        # ec2config_user_sid = powershell_out("Invoke-Command -ScriptBlock { (New-Object System.Security.Principal.NTAccount('#{new_resource.netbios_name}', '#{new_resource.ec2config_user}')).Translate([System.Security.Principal.SecurityIdentifier]).value } -ComputerName #{node[:ipaddress]} -Credential (New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.username}', (ConvertTo-SecureString '#{new_resource.password}' -AsPlainText -Force)))").stdout.strip

        template "#{Chef::Config[:file_cache_path]}\\gpo\\manifest.xml" do
          source "manifest.xml.erb"
          variables(
            domain_name: new_resource.domain_name,
            computer_name: new_resource.computer_name
          )
        end

        template "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\Backup.xml" do
          source "Backup.xml.erb"
          variables(
            domain_name: new_resource.domain_name,
            computer_name: new_resource.computer_name,
            netbios_name: new_resource.netbios_name
          )
        end

        template "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\bkupInfo.xml" do
          source "bkupInfo.xml.erb"
          variables(
            domain_name: new_resource.domain_name,
            computer_name: new_resource.computer_name
          )
        end

        template "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\gpreport.xml" do
          source "gpreprt.xml.erb"
          variables(
            domain_name: new_resource.domain_name,
            computer_name: new_resource.computer_name,
            netbios_name: new_resource.netbios_name,
            ssh_sid: ssh_user_sid,
            ec2config_sid: ec2config_user_sid,
            admin_group_sid: administrators_group_sid
          )
        end

        template "#{Chef::Config[:file_cache_path]}\\gpo\\{24E13F41-7118-4FB6-AE8B-45D48AFD6AFE}\\DomainSysvol\\GPO\\Machine\\microsoft\\windows nt\\SecEdit\\GptTmpl.inf" do
          source "gptmpl.inf.erb"
          variables(
            ssh_sid: ssh_user_sid,
            ec2config_sid: ec2config_user_sid,
            admin_group_sid: administrators_group_sid
          )
        end

        # We might not have sufficient permissions to import the GPO correctly with Cygwin/SSH at this point. Lets use WinRM to authenticate to the local machine

        # Chef::Log.info("import #{gpo_name} GPO")
        # script =<<-EOH
        # Invoke-Command -ScriptBlock { Import-GPO -BackupId 24E13F41-7118-4FB6-AE8B-45D48AFD6AFE -TargetName #{gpo_name} -path #{Chef::Config[:file_cache_path]}\\gpo -CreateIfNeeded } -ComputerName #{node[:ipaddress]} -Credential (New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.username}', (ConvertTo-SecureString '#{new_resource.password}' -AsPlainText -Force)))
        # new-gplink -name #{gpo_name} -target 'dc=#{new_resource.domain_name.gsub(".", ",dc=")}'
        # gpupdate /force
        # EOH
        # cmd = powershell_out(script)

        converge_by("Importing GPO #{gpo_name}") do
          cmd = powershell_out("Invoke-Command -ScriptBlock { Import-GPO -BackupId 24E13F41-7118-4FB6-AE8B-45D48AFD6AFE -TargetName #{gpo_name} -path #{Chef::Config[:file_cache_path]}\\gpo -CreateIfNeeded } -ComputerName #{node[:ipaddress]} -Credential (New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.username}', (ConvertTo-SecureString '#{new_resource.password}' -AsPlainText -Force))) ; new-gplink -name #{gpo_name} -target 'dc=#{new_resource.domain_name.gsub(".", ",dc=")}' ; gpupdate /force")
        end

        # powershell_out("Import-GPO -BackupId 24E13F41-7118-4FB6-AE8B-45D48AFD6AFE -TargetName #{gpo_name} -path #{Chef::Config[:file_cache_path]}\\gpo -CreateIfNeeded").run_command
        # powershell_out("new-gplink -name #{gpo_name} -target 'dc=#{new_resource.domain_name.gsub(".", ",dc=")}'").run_command
      end
    end

    %w{SeCreateTokenPrivilege SeTcbPrivilege SeAssignPrimaryTokenPrivilege}.each { |privilege|
      batch "Grant local user #{new_resource.netbios_name}\\#{new_resource.ssh_user} #{privilege} right" do
        code "C:\\Windows\\SysWOW64\\ntrights +r #{privilege} -u #{new_resource.netbios_name}\\#{new_resource.ssh_user}"
      end
    }
  end

  if in_domain?
    [new_resource.ssh_user, new_resource.ec2config_user, new_resource.username].each { |user|
      unless user_in_local_admin_group?(user)
        code =<<-EOH
          $domain_user = [ADSI]('WinNT://#{new_resource.netbios_name}/#{user}')
          $local_admin_group = [ADSI]('WinNT://./Administrators')
          $local_admin_group.PSBase.Invoke('Add',$domain_user.PSBase.Path)
        EOH

        converge_by("Added domain user #{user} to local Administrators group") do
          cmd = powershell_out(code)
        end
      end
    }


    directory 'C:/chef/cache' do
      rights :full_control, "#{new_resource.netbios_name}\\#{new_resource.username}"
      rights :full_control, "#{new_resource.netbios_name}\\#{new_resource.ssh_user}"
    end

    execute "C:/bin/cygwin/bin/bash --login -c \"chown -R #{new_resource.username} /home/#{new_resource.username}\""

    template "#{Chef::Config[:file_cache_path]}\\set_ad_dns_scheduled_task.ps1" do
      source 'set_ad_dns_scheduled_task.ps1.erb'
      variables(
        dc_ips: new_resource.dc_ips
      )
    end

    windows_task 'set-ad-dns' do
      user "SYSTEM"
      command "powershell -ExecutionPolicy RemoteSigned -File '#{Chef::Config[:file_cache_path]}\\set_ad_dns_scheduled_task.ps1'"
      run_level :highest
      frequency :onstart
    end
  else
    # We want to run ec2config as admin user so Windows userdata executes as admin, however the local admin account doesn't have Logon As a Service right. Domain privileges are set separately

    cookbook_file "c:\\Windows\\SysWOW64\\ntrights.exe" do
      source "ntrights"
    end

    [new_resource.ssh_user, new_resource.ec2config_user].each { |usr|
      user usr do
        password new_resource.ec2config_password if usr == new_resource.ec2config_user
        password new_resource.ssh_password if usr == new_resource.ssh_user
      end

      group "Administrators" do
        action :modify
        members usr
        append true
      end

      %w{SeDenyRemoteInteractiveLogonRight SeDenyInteractiveLogonRight SeServiceLogonRight}.each { |privilege|
        batch "Grant local user #{usr} logon as service right" do
          code "C:\\Windows\\SysWOW64\\ntrights +r #{privilege} -u #{usr}"
        end
      }

      if usr == new_resource.ssh_user
        %w{SeCreateTokenPrivilege SeTcbPrivilege SeAssignPrimaryTokenPrivilege}.each { |privilege|
          batch "Grant local user #{usr} logon as service right" do
            code "C:\\Windows\\SysWOW64\\ntrights +r #{privilege} -u #{usr}"
          end
        }
      end
    }
  end
end
