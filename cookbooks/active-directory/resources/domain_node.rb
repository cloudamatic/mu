# Join a node to an Active Directory domain

actions :add, :remove
default_action :add

attribute :dns_name, :kind_of => String, :name_attribute => true, :required => true
attribute :dc_ips, :kind_of => Array, :required => true
attribute :dc_names, :kind_of => Array, :required => true
attribute :computer_name, :kind_of => String, :required => true
attribute :netbios_name, :kind_of => String, :required => true
attribute :join_user, :kind_of => String, :required => true
attribute :join_password, :kind_of => String, :required => true
attribute :ou, :kind_of => String, :required => false
