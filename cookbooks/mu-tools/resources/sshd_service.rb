resource_name :sshd_service

property :name, String, name_property: true # ~FC108
property :username, String, required: true
property :password, String, required: true
property :service_username, String, required: true

default_action :config

action :config do
  converge_by("Configuring SSH service to run under #{new_resource.service_username}") do
    ssh_user_set = service_user_set?(new_resource.name, new_resource.service_username)
    failed = false
  
    cmd = powershell_out("$sshd_service = Get-WmiObject Win32_service | Where-Object {$_.Name -eq '#{new_resource.name}'}; $sshd_service.Change($Null,$Null,$Null,$Null,$Null,$Null,'#{new_resource.service_username}','#{new_resource.password}',$Null,$Null,$Null)")
    if cmd.exitstatus != 0
      Chef::Log.error("Failed to change ssh service user #{cmd.stderr}")
      failed = true
    end

    cmd = powershell_out("(Get-WmiObject Win32_service | Where-Object {$_.Name -eq '#{new_resource.name}'}).StartName")
    if !(cmd.stdout =~ /#{new_resource.username}/)
      Chef::Log.error("Failed to change ssh service user to #{new_resource.username}")
      failed = true
    end

    # if cmd.exitstatus == 0 and !ssh_user_set
    unless ssh_user_set or failed
      # cmd = powershell_out("c:/bin/cygwin/bin/bash --login -c 'chown -R #{new_resource.username} /var/empty && chown #{new_resource.username} /var/log/sshd.log /etc/ssh*\'; Stop-Process -ProcessName #{new_resource.name} -force; Stop-Service #{new_resource.name} -Force; Start-Service #{new_resource.name}; sleep 5; Start-Service #{new_resource.name}")
      # We would much prefer to use the above because that wouldn't  require another reboot, but in some cases the session dosen't get terminated from  Mu. Throwing Chef::Application.fatal seems to work more reliably
      cmd = powershell_out("c:/bin/cygwin/bin/bash --login -c 'chown -R #{new_resource.username} /var/empty && chown #{new_resource.username} /var/log/sshd.log /etc/ssh*\'")
#      execute "kill ssh for reboot" do
#        command "Taskkill /im sshd.exe /f /t"
#        returns [0, 128, 1115]
#        action :nothing
#      end
      reboot "Setting Cygwin ssh user to #{new_resource.username}" do
        action :request_reboot
        reason "Setting Cygwin ssh user to #{new_resource.username}"
#        notifies :run, "execute[kill ssh for reboot]", :immediately
      end
#      kill_ssh
    end
  end
end
