#
# Author:: John Stange (<john.stange@eglobaltech.com>)
# Cookbook Name:: mu-tools
# Resource:: active_directory_domain
# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#     http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Fire up a rudimentary Active Directory domain
#

actions :create, :add_controller, :join

default_action :create

attribute :dns_name, :kind_of => String, :name_attribute => true, :required => true
attribute :sites, :kind_of => Array, :required => false
attribute :existing_dc_ips, :kind_of => Array, :required => false
attribute :netbios_name, :kind_of => String, :required => true
attribute :domain_admin_user, :kind_of => String, :default => node['ad']['admin_user']
attribute :domain_admin_password, :kind_of => String, :required => true
attribute :safe_mode_pw, :kind_of => String, :required => true
attribute :site_name, :kind_of => String, :default => node['ad']['site_name']
attribute :computer_name, :kind_of => String, :default => node['ad']['computer_name']
attribute :ntds_static_port, :kind_of => Fixnum, :default => node['ad']['ntds_static_port']
attribute :ntfrs_static_port, :kind_of => Fixnum, :default => node['ad']['ntfrs_static_port']
attribute :dfsr_static_port, :kind_of => Fixnum, :default => node['ad']['dfsr_static_port']


attr_accessor :exists
attr_accessor :has_ad_features
