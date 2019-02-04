#
# Cookbook Name:: mu-glusterfs
# Recipe:: repo
#
# Copyright 2014, eGlobalTech
#
# All rights reserved - Do Not Redistribute
#

case node['platform']
  when "centos"
    package "centos-release-gluster"

  else
    Chef::Log.info("Unsupported platform #{node['platform']}")
end
