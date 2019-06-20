#
# Cookbook:: mu-tools
# Recipe:: selinux
#
# Copyright:: 2019, The Authors, All Rights Reserved.

selinux_state "SELinux Enforcing" do
    action :enforcing
end