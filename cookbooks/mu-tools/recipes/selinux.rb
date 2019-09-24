#
# Cookbook:: mu-tools
# Recipe:: selinux
#
# Copyright:: 2019, The Authors, All Rights Reserved.

if !node['application_attributes']['skip_recipes'].include?('selinux')

  selinux_state "SELinux Enforcing" do
    action :enforcing
    notifies :request_reboot, 'reboot[now]', :immediately
  end

  reboot 'now' do
    action :nothing
    reason 'Must reboot to enable SELinux.'
  end
 
end
