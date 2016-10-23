resource_name :aws_windows

property :username, String, required: true
property :password, String, required: true
property :service_username, String, required: true

default_action :config

action :config do
  require 'chef/win32/version'
  version = Chef::ReservedNames::Win32::Version.new

  if version.windows_server_2012? || version.windows_server_2012_r2?
    unless service_user_set?("Ec2Config", new_resource.service_username)
    converge_by("configure Ec2Config service to run under #{new_resource.username}") do
      cmd = powershell_out("(Get-WmiObject Win32_service | Where-Object {$_.Name -eq 'Ec2Config'}).StartName")
      Chef::Log.info("ec2config Service start name before change: #{cmd.stdout}")
    end

    converge_by("configure Ec2Config service to run under #{new_resource.username}") do
      cmd = powershell_out("$ec2config_service = Get-WmiObject Win32_service | Where-Object {$_.Name -eq 'Ec2Config'}; $ec2config_service.Change($Null,$Null,$Null,$Null,$Null,$Null,'#{new_resource.service_username}','#{new_resource.password}',$Null,$Null,$Null)")
      Chef::Log.error("Error configuring Ec2Config service: #{cmd.stderr}") unless cmd.exitstatus == 0
      cmd = powershell_out("(Get-WmiObject Win32_service | Where-Object {$_.Name -eq 'Ec2Config'}).StartName")
      Chef::Log.info("ec2config Service start name after change: #{cmd.stdout}")
    end
      # service "Ec2Config" do
      # action :restart
      # end
    end
  elsif version.windows_server_2016?
    # do EC2Launch http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/windows-ami-version-history.html#win2k16-amis
  end
end
