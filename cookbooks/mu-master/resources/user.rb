#
# Cookbook Name:: mu-master
# Resource:: mu_user
#
# Copyright 2017, eGlobalTech,
#
# All rights reserved - Do Not Redistribute
#

actions :add, :remove
default_action :add

attribute :username, :kind_of => String, :name_attribute => true, :required => true
attribute :realname, :kind_of => String, :required => true
attribute :email, :kind_of => String, :required => true
attribute :password, :kind_of => String, :required => false
attribute :admin, :kind_of => Boolean, :required => false, :default => false
attribute :orgs, :kind_of => Array, :required => false
attribute :remove_orgs, :kind_of => Array, :required => false
