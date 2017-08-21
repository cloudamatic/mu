#
# Cookbook Name:: mu-glusterfs
# Recipe:: client
#
# Copyright 2014, eGlobalTech
#
# All rights reserved - Do Not Redistribute
#


case node[:platform]
  when "centos"
    include_recipe "mu-glusterfs"

    %w{glusterfs glusterfs-fuse}.each do |pkg|
      package pkg
    end

    include_recipe 'mu-firewall'

    node[:glusterfs][:fw][:each] { |rule|
      firewall_rule "Allow glusterfs #{rule['usage']}" do
        port rule['port_range']
      end
    }

    directory node[:glusterfs][:client][:mount_path] do
      recursive true
      mode "0755"
    end

    if node[:glusterfs][:discovery] == 'groupname'
      gluster_servers = search(
          :node,
          "glusterfs_is_server:true AND glusterfs_groupname:#{node[:glusterfs_groupname]}"
      )
    end rescue NoMethodError
    if gluster_servers.nil?
      gluster_servers = search(
          :node,
          "glusterfs_is_server:true AND chef_environment:#{node.chef_environment}"
      )
    end

    template "/etc/init.d/mu-gluster-client" do
      source "mu-gluster-client.erb"
      variables(
          :servers => gluster_servers,
          :path => node[:glusterfs][:client][:mount_path],
          :volume => node[:glusterfs][:server][:volume]
      )
      mode 0755
    end

    service "mu-gluster-client" do
      action [:enable, :start]
    end

  else
    Chef::Log.info("Unsupported platform #{node[:platform]}")
end

