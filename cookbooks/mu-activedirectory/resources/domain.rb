#
# Cookbook Name:: mu-activedirectory
# Resource:: domain
#
# Copyright 2015, eGlobalTech,
#
# All rights reserved - Do Not Redistribute
#

actions :create, :delete
default_action :create

attribute :dns_name, :kind_of => String, :name_attribute => true, :required => true
attribute :sites, :kind_of => Array, :required => false
attribute :existing_dc_ips, :kind_of => Array, :required => false
attribute :netbios_name, :kind_of => String, :required => true
attribute :domain_admin_user, :kind_of => String, :required => true
attribute :domain_admin_password, :kind_of => String, :required => true
attribute :restore_mode_password, :kind_of => String, :required => true
attribute :site_name, :kind_of => String, :default => node.ad.site_name, :required => false
attribute :computer_name, :kind_of => String, :default => node.ad.computer_name
attribute :ntds_static_port, :kind_of => Fixnum, :default => node.ad.ntds_static_port
attribute :ntfrs_static_port, :kind_of => Fixnum, :default => node.ad.ntfrs_static_port
attribute :dfsr_static_port, :kind_of => Fixnum, :default => node.ad.dfsr_static_port
attribute :netlogon_static_port, :kind_of => Fixnum, :default => node.ad.netlogon_static_port
