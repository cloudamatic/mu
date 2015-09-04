#
# Cookbook Name:: mu-glusterfs
# Recipe:: repo
#
# Copyright 2014, eGlobalTech
#
# All rights reserved - Do Not Redistribute
#

case node[:platform]
  when "centos"

    yum_repository "glusterfs" do
      description 'Glusterfs latest release repo'
      url "http://download.gluster.org/pub/gluster/glusterfs/LATEST/EPEL.repo/epel-$releasever/$basearch/"
      enabled true
      gpgkey "http://download.gluster.org/pub/gluster/glusterfs/LATEST/EPEL.repo/pub.key"
    end

    yum_repository "glusterfs-samba" do
      description 'Glusterfs Samba repo'
      url "http://download.gluster.org/pub/gluster/glusterfs/samba/EPEL.repo/epel-$releasever/$basearch/"
      enabled true
      gpgkey "http://download.gluster.org/pub/gluster/glusterfs/samba/EPEL.repo/pub.key"
    end

  else
    Chef::Log.info("Unsupported platform #{node[:platform]}")
end
