#
# Author:: Joshua Sierles <joshua@37signals.com>
# Author:: Joshua Timberman <joshua@chef.io>
# Author:: Nathan Haneysmith <nathan@chef.io>
# Author:: Seth Chisamore <schisamo@chef.io>
# Author:: Tim Smith <tsmith@chef.io>
# Cookbook:: nagios
# Recipe:: server
#
# Copyright:: 2009, 37signals
# Copyright 2009-2016, Chef Software, Inc.
# Copyright 2013-2014, Limelight Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# (COOK-2350) workaround to allow for a nagios server install from source using
# (COOK-2350) the override attribute on debian/ubuntu
nagios_service_name = if platform_family?('debian') &&
                         node['nagios']['server']['install_method'] == 'source'
                        node['nagios']['server']['name']
                      else
                        node['nagios']['server']['service_name']
                      end

# install nagios service either from source of package
include_recipe "nagios::server_#{node['nagios']['server']['install_method']}"

# use the users_helper.rb library to build arrays of users and contacts
nagios_users = NagiosUsers.new(node)

if nagios_users.users.empty?
  Chef::Log.fatal('Could not find users in the ' \
    "\"#{node['nagios']['users_databag']}\"" \
    "databag with the \"#{node['nagios']['users_databag_group']}\"" \
    ' group. Users must be defined to allow for logins to the UI. ' \
    'Make sure the databag exists and, if you have set the ' \
    '"users_databag_group", that users in that group exist.')
end

if node['nagios']['server_auth_method'] == 'htauth'
  # setup htpasswd auth
  directory node['nagios']['conf_dir']

  template "#{node['nagios']['conf_dir']}/htpasswd.users" do
    cookbook node['nagios']['htauth']['template_cookbook']
    source node['nagios']['htauth']['template_file']
    owner node['nagios']['user']
    group node['nagios']['web_group']
    mode '0640'
    variables(nagios_users: nagios_users.users)
  end
end

# Setting all general options
unless node['nagios'].nil?
  unless node['nagios']['server'].nil?
    Nagios.instance.normalize_hostname =
      node['nagios']['server']['normalize_hostname']
  end
end

Nagios.instance.host_name_attribute = node['nagios']['host_name_attribute']

# loading default configuration data
if node['nagios']['server']['load_default_config']
  include_recipe 'nagios::_load_default_config'
end

# loading all databag configurations
if node['nagios']['server']['load_databag_config']
  include_recipe 'nagios::_load_databag_config'
end

directory "#{node['nagios']['conf_dir']}/dist" do
  owner node['nagios']['user']
  group node['nagios']['group']
  mode '0755'
end

# Don't run on RHEL since the state directory is the same as the log directory and causes idempotency issues
directory node['nagios']['state_dir'] do
  owner node['nagios']['user']
  group node['nagios']['group']
  mode '0751'
end unless platform_family?('rhel')

directory "#{node['nagios']['state_dir']}/rw" do
  owner node['nagios']['user']
  group node['nagios']['web_group']
  mode '2710'
end

cfg_files =
  "#{node['nagios']['config_dir']}/*_#{node['nagios']['server']['name']}*.cfg"
execute 'archive-default-nagios-object-definitions' do
  command "mv #{cfg_files} #{node['nagios']['conf_dir']}/dist"
  not_if { Dir.glob(cfg_files).empty? }
end

directory "#{node['nagios']['conf_dir']}/certificates" do
  owner node['nagios']['web_user']
  group node['nagios']['web_group']
  mode '0700'
end

ssl_code = "umask 077
openssl genrsa 2048 > nagios-server.key
openssl req -subj #{node['nagios']['ssl_req']} -new -x509 -nodes -sha1 \
  -days 3650 -key nagios-server.key > nagios-server.crt
cat nagios-server.key nagios-server.crt > nagios-server.pem"

bash 'Create SSL Certificates' do
  cwd "#{node['nagios']['conf_dir']}/certificates"
  code ssl_code
  not_if { ::File.exist?(node['nagios']['ssl_cert_file']) }
end

nagios_conf node['nagios']['server']['name'] do
  config_subdir false
  cookbook node['nagios']['nagios_config']['template_cookbook']
  source node['nagios']['nagios_config']['template_file']
  variables(nagios_config: node['nagios']['conf'])
end

nagios_conf 'cgi' do
  config_subdir false
  cookbook node['nagios']['cgi']['template_cookbook']
  source node['nagios']['cgi']['template_file']
  variables(nagios_service_name: nagios_service_name)
end

# resource.cfg differs on RPM and tarball based systems
if platform_family?('rhel')
  template "#{node['nagios']['resource_dir']}/resource.cfg" do
    cookbook node['nagios']['resources']['template_cookbook']
    source node['nagios']['resources']['template_file']
    owner node['nagios']['user']
    group node['nagios']['group']
    mode '0600'
  end

  directory node['nagios']['resource_dir'] do
    owner 'root'
    group node['nagios']['group']
    mode '0755'
  end
end

nagios_conf 'timeperiods'
nagios_conf 'contacts'
nagios_conf 'commands'
nagios_conf 'hosts'
nagios_conf 'hostgroups'
nagios_conf 'templates'
nagios_conf 'services'
nagios_conf 'servicegroups'
nagios_conf 'servicedependencies'

service 'nagios' do
  service_name nagios_service_name
  if ::File.exist?("#{nagios_config_dir}/services.cfg")
    action [:enable, :start]
  else
    action :enable
  end
end

# Remove distribution included config files that aren't managed via this cookbook
zap_directory nagios_distro_config_dir do
  pattern '*.cfg'
  only_if { ::Dir.exist?(nagios_distro_config_dir) }
end
