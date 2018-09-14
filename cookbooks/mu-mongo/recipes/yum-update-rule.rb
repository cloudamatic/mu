#
# Cookbook Name:: mu-mongo
# Recipe:: yum-update-rule
#
# Copyright 2015, eGlobalTech
#
# All rights reserved - Do Not Redistribute
#

case node['platform']
  when "centos"
    execute "tell yum not to touch MongoDB" do
      command "echo 'exclude=mongo*' >> /etc/yum.conf"
      not_if "grep ^exclude=mongo /etc/yum.conf"
    end
  else
    Chef::Log.info("Unsupported platform #{node['platform']}")
end
