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

default['mu']['admin_emails'] = []
default['mu']['user_list'] = []
default['mu']['user_map'] = {}
if !MU.mainDataDir.nil? and !MU.mainDataDir.empty? and
		Dir.exists?("#{MU.mainDataDir}/users")
	admin_list = []
	Dir.foreach("#{MU.mainDataDir}/users") { |username|
		next if username == "." or username == ".."
		if File.exists?("#{MU.mainDataDir}/users/#{username}/email")
			email = File.read("#{MU.mainDataDir}/users/#{username}/email").chomp
			admin_list << "#{username} (#{email})"
			default['mu']['admin_emails'] << email
			default['mu']['user_map'][username] = email
		else
			admin_list << username
		end
	}
	default['mu']['user_list'] = admin_list.join(", ")
# older machines
elsif node['tags'].is_a?(Hash)
	default['mu']['user_list'] = node['tags']['MU-ADMINS']
	default['mu']['admin_emails'] = node['tags']['MU-ADMINS'].split(/,?\s+/)
elsif !ENV['MU_ADMINS'].nil? and !ENV['MU_ADMINS'].empty?
	default['mu']['user_list'] = ENV['MU_ADMINS']
	default['mu']['admin_emails'] = ENV['MU_ADMINS'].split(/,?\s+/)
end

default['apache']['docroot_dir'] = "/var/www/html"
default['apache']['default_site_enabled'] = true
default['apache']['mod_ssl']['cipher_suite'] = "ALL:!ADH:!EXPORT:!SSLv2:!RC4+RSA:+HIGH:!MEDIUM:!LOW"
default['apache']['mod_ssl']['directives']['SSLProtocol'] = "all -SSLv2 -SSLv3"

default['apache']['contact'] = default['mu']['user_map']['mu']
default['apache']['traceenable'] = 'Off'
default["apache"]["listen_ports"] = [80, 8443]

override["nagios"]["http_port"] = 8443
default['nagios']['enable_ssl'] = true
default['nagios']['sysadmin_email'] = default['mu']['user_map']['mu']
default['nagios']['ssl_cert_file'] = "/etc/httpd/ssl/nagios.crt"
default['nagios']['ssl_cert_key'] = "/etc/httpd/ssl/nagios.key"
default["nagios"]["log_dir"] = "/var/log/httpd"
default['nagios']['cgi-bin'] = "/usr/lib/cgi-bin/"
default['nagios']['cgi-path'] = "/cgi-bin/"
default['nagios']['server_role'] = "mu-master"
default['nagios']['server']['install_method'] = 'source'
default['nagios']['multi_environment_monitoring'] = true
default['nagios']['users_databag'] = "nagios_users"
default['nagios']['conf']['enable_notifications'] = 1
default['nagios']['interval_length'] = 1
default['nagios']['conf']['interval_length'] = 1
default['nagios']['notifications_enabled'] = 1
default['nagios']['default_host']['notification_interval'] = 7200
default['nagios']['default_host']['check_interval'] = 180
default['nagios']['default_host']['retry_interval'] = 60
default['nagios']['conf']['service_check_timeout'] = 10
default['nagios']['default_host']['max_check_attempts'] = 4
default['nagios']['default_host']['check_command'] = "check_node_ssh"
default['nagios']['default_service']['check_interval'] = 180
default['nagios']['default_service']['retry_interval'] = 30

# no idea why this attribute isn't set on MU-MASTER, but it isn't.
default['chef_node_name'] = Chef::Config[:node_name]
default['nagios']['host_name_attribute'] = 'chef_node_name'

default[:application_attributes][:logs]["volume_size_gb"] = 50
default[:application_attributes][:logs][:mount_device] = "/dev/xvdl"
default[:application_attributes][:logs][:label] = "#{node.hostname} /Mu_Logs"
default[:application_attributes][:logs][:secure_location] = MU.adminBucketName
default[:application_attributes][:logs][:ebs_keyfile] = "log_vol_ebs_key"
default[:application_attributes][:logs][:mount_directory] = "/Mu_Logs"
