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

default['mu']['user_map'] = MU::Master.listUsers
default['mu']['user_list'] = []
node.mu.user_map.each_pair { |user, data|
  node.default.mu.user_list << "#{user} (#{data['email']})"
}

default['apache']['docroot_dir'] = "/var/www/html"
default['apache']['default_site_enabled'] = true
default['apache']['mod_ssl']['cipher_suite'] = "ALL:!ADH:!EXPORT:!SSLv2:!RC4+RSA:+HIGH:!MEDIUM:!LOW"
default['apache']['mod_ssl']['directives']['SSLProtocol'] = "all -SSLv2 -SSLv3"

default['apache']['contact'] = $MU_CFG['mu_admin_email']
default['apache']['traceenable'] = 'Off'

override["apache"]["listen_ports"] = [80, 443, 8443]

override["nagios"]["http_port"] = 8443
default['nagios']['enable_ssl'] = true
default['nagios']['sysadmin_email'] = $MU_CFG['mu_admin_email']
default['nagios']['ssl_cert_file'] = $MU_CFG['ssl']['cert']
default['nagios']['ssl_cert_key'] = $MU_CFG['ssl']['key']
if $MU_CFG['ssl'].has_key?("chain") and !$MU_CFG['ssl']['chain'].empty?
  default['nagios']['ssl_cert_chain_file'] = $MU_CFG['ssl']['chain']
end
if !$MU_CFG['public_address'].match(/^\d+\.\d+\.\d+\.\d+$/)
  default["nagios"]["server_name"] = $MU_CFG['public_address']
else
  default["nagios"]["server_name"] = node.hostname
  default['nagios']['server']['server_alias'] = $MU_CFG['public_address']
end
#default['nagios']['server']['server_alias'] = node.fqdn+", "+node.hostname+", "+node['local_hostname']+", "+node['local_ipv4']+", "+node['public_hostname']+", "+node['public_ipv4']
default["nagios"]["log_dir"] = "/var/log/httpd"
default['nagios']['cgi-bin'] = "/usr/lib/cgi-bin/"
default['nagios']['cgi-path'] = "/nagios/cgi-bin/"
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
default['nagios']['server']['url'] = "https://assets.nagios.com/downloads/nagioscore/releases/nagios-4.1.1.tar.gz"
default['nagios']['server']['version'] = "4.1.1"
default['nagios']['server']['src_dir'] = "nagios-4.1.1"
default['nagios']['server']['checksum'] = "986c93476b0fee2b2feb7a29ccf857cc691bed7ca4e004a5361ba11f467b0401"
default['nagios']['url'] = "https://#{$MU_CFG['public_address']}/nagios"

# No idea why this is set wrong by default
default['chef_node_name'] = node.name
default['nagios']['host_name_attribute'] = 'chef_node_name'

default['application_attributes']['logs']['volume_size_gb'] = 50
default['application_attributes']['logs']['mount_device'] = "/dev/xvdl"
default['application_attributes']['logs']['label'] = "#{node.hostname} /Mu_Logs"
default['application_attributes']['logs']['secure_location'] = MU.adminBucketName
default['application_attributes']['logs']['ebs_keyfile'] = "log_vol_ebs_key"
default['application_attributes']['logs']['mount_directory'] = "/Mu_Logs"

case node.platform
  when "centos"
    ssh_user = "root" if node.platform_version.to_i == 6
    ssh_user = "centos" if node.platform_version.to_i == 7
  when "redhat"
    ssh_user = "ec2-user"
end

default['application_attributes']['sshd_allow_groups'] = "#{ssh_user} mu-users"
