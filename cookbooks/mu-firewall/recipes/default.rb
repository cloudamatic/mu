#
# Cookbook Name:: mu-firewall
# Recipe:: default
#
# Copyright 2025, eGlobalTech
#
# All rights reserved - Do Not Redistribute
#

if node['platform_family'] != "amazon" or node['platform_version'].to_i >= 2023

  # The firewall cookbook needs this, and its chef_gem resource doesn't work
  # for some reason.
  execute "env -i /opt/chef/embedded/bin/gem install ruby-dbus" do
    compile_time true
  end

  include_recipe 'firewall'
end
