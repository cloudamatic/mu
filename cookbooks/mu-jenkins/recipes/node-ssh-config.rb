#
# Cookbook Name:: mu-jenkins
# Recipe:: node-ssh-config
#
# Copyright 2015, eGlobalTech, Inc
#
# All rights reserved - Do Not Redistribute
#

include_recipe 'mu-jenkins::public_key'
include_recipe 'mu-utility::disable-requiretty'
include_recipe 'chef-vault'

ssh_vault = chef_vault_item(node.jenkins_ssh_vault[:vault], node.jenkins_ssh_vault[:item])

case node.platform
  when "centos", "redhat"
    if platform?("centos")
      ssh_user = "root" if node.platform_version.to_i == 6
      ssh_user = "centos" if node.platform_version.to_i == 7
    else
      ssh_user = "ec2-user"
    end

    directory "#{node.jenkins.master.home}/.ssh" do
      owner "jenkins"
      group "jenkins"
      mode 0700
    end

    ssh_key_path = "#{node.jenkins.master.home}/.ssh/jenkins_ssh"

    template "#{node.jenkins.master.home}/.ssh/config" do
      source "ssh_config.erb"
      owner "jenkins"
      group "jenkins"
      mode 0600
      variables(
          :ssh_user => ssh_user,
          :ssh_key_path => ssh_key_path,
          :ssh_urls => node.jenkins_ssh_urls
      )
    end

    file ssh_key_path do
      owner "jenkins"
      group "jenkins"
      mode 0400
      content ssh_vault['private_key'].strip
      sensitive true
    end
  else
    Chef::Log.info("Unsupported platform #{node.platform}")
end
