resource_name :scheduled_tasks

property :username, String, required: true
property :password, String, required: true

default_action :config

action :config do
  %w{run-userdata_scheduledtask.xml run_chefclient_scheduledtask.xml}.each { |file|
    remote_file "#{Chef::Config[:file_cache_path]}/#{file}" do
      source "https://s3.amazonaws.com/cap-public/#{file}"
      action :nothing
    end.run_action(:create)
  }

  # To do: Add guards
#  converge_by("Creating run-chef-client Scheduled Task") do
#    cmd = powershell_out("Register-ScheduledTask -Xml (get-content '#{Chef::Config[:file_cache_path]}/run_chefclient_scheduledtask.xml' | out-string) -TaskName 'run-chef-client' -User #{new_resource.username} -Password '#{new_resource.password}' -Force")
#  end

  # TO DO for Windows 2016 create a scheduled task that executes C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Scripts\Invoke-Userdata.ps1 with a username and a password instead of this scheduled task
  converge_by("Creating run-userdata Scheduled Task") do
    cmd = powershell_out("Register-ScheduledTask -Xml (get-content '#{Chef::Config[:file_cache_path]}/run-userdata_scheduledtask.xml' | out-string) -TaskName 'run-userdata' -User #{new_resource.username} -Password '#{new_resource.password}' -Force")
    Chef::Log.error("Failed to configure run-userdata Scheduled Task: #{cmd.stderr}") unless cmd.exitstatus == 0
  end

  windows_task 'run-userdata' do
    action :nothing
  end

#  windows_task 'run-chef-client' do
#    action :nothing
#  end
end
