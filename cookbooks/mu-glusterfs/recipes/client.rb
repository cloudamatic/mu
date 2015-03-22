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

        %w{glusterfs glusterfs-fuse}.each do |pkg|
            package pkg
        end

		node.glusterfs.fw.each do |rule|
			bash "Allow TCP #{rule['port_range']} through iptables" do
				user "root"
				not_if "/sbin/iptables -nL | egrep '^ACCEPT.*dpts:#{rule['port_range']}($| )'"
				code <<-EOH
					iptables -I INPUT -p tcp --dport #{rule['port_range']} -j ACCEPT
					service iptables save
				EOH
			end
		end

		directory node.glusterfs.client.mount_path do
			recursive true
			mode "0755"
		end

		mount node.glusterfs.client.mount_path do
			device "#{node.application_attributes.glusterfs_master_ip}:#{node.glusterfs.server.volume}"
			fstype "glusterfs"
			options "defaults,_netdev"
			pass 0
			action [:mount, :enable]
		end

    else
        Chef::Log.info("Unsupported platform #{node[:platform]}")
end

