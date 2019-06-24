#
# Cookbook:: mu-tools
# Recipe:: selinux
#
# Copyright:: 2019, The Authors, All Rights Reserved.

selinux_state "SELinux Enforcing" do
	action :enforcing
	notifies :reboot_now, 'reboot[now]', :immediately
end

reboot 'now' do
	action :nothing
	reason 'Must reboot to enable SELinux.'
end
  