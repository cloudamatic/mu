#
# Cookbook Name:: mu-tools
# Resource:: windows_client
#
# Copyright 2015, eGlobalTech,
#
# All rights reserved - Do Not Redistribute
#

actions :run
default_action :run

attribute :computer_name, :kind_of => String, :name_attribute => true, :required => true
attribute :password, :kind_of => String, :required => true
attribute :user_name, :kind_of => String, :required => true
attribute :domain_admin_user, :kind_of => String
attribute :ssh_user, :kind_of => String, :required => true
attribute :ssh_password, :kind_of => String, :required => true
attribute :ec2config_user, :kind_of => String, :required => true
attribute :ec2config_password, :kind_of => String, :required => true
attribute :domain_name, :kind_of => String
attribute :netbios_name, :kind_of => String
attribute :ec2config_guard, :kind_of => String, :required => true
attribute :ec2config_service_user, :kind_of => String, :required => true
attribute :ssh_guard, :kind_of => String, :required => true
attribute :ssh_service_user, :kind_of => String, :required => true
