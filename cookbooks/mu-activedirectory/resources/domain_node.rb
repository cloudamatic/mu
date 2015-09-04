#
# Cookbook Name:: mu-activedirectory
# Resource:: domain_node
#
# Copyright 2015, eGlobalTech,
#
# All rights reserved - Do Not Redistribute
#

actions :add, :remove
default_action :add

attribute :dns_name, :kind_of => String, :name_attribute => true, :required => true
attribute :dc_ips, :kind_of => Array, :required => true
attribute :dc_names, :kind_of => Array, :required => true
attribute :computer_name, :kind_of => String, :required => true
attribute :netbios_name, :kind_of => String, :required => true
attribute :join_user, :kind_of => String, :required => true
attribute :join_password, :kind_of => String, :required => true
attribute :computer_ou, :kind_of => String, :required => false
