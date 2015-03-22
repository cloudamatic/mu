#
# Cookbook Name:: mu-tools
# Attributes:: default
#
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
disk_name_str = Chef::Config[:node_name]
if disk_name_str == "CAP-MASTER" or disk_name_str == "MU-MASTER" and !node.hostname.nil?
  disk_name_str = node.hostname
end rescue NoMethodError

default['application_attributes']['application_volume']['mount_directory'] = '/apps'
default['application_attributes']['application_volume']['mount_device'] = '/dev/xvdf'
default['application_attributes']['application_volume']['label'] = "#{disk_name_str} /apps"
default['application_attributes']['application_volume']['filesystem'] = 'ext3'
default['application_attributes']['application_volume']['volume_size_gb'] = '1'

default['application_attributes']['ebs_snapshots']['boto_path'] = '/usr/lib/python2.6/site-packages/boto'
default['application_attributes']['ebs_snapshots']['minute'] = '10'
default['application_attributes']['ebs_snapshots']['hour'] = '6'
default['application_attributes']['ebs_snapshots']['days_to_keep'] = '7'

default['nagios']['server_role'] = "mu-master"
default['nagios']['multi_environment_monitoring'] = true
# no idea why this attribute isn't set on CAP-MASTER, but it isn't.
default['chef_node_name'] = Chef::Config[:node_name]
if node.has_key?("deployment")
	if node.deployment.has_key?("admins")
		default['admins'] = []
		node.deployment.admins.each_value { |data|
			default['admins'] << data['email']
		}
	end
	if node.deployment.has_key?("mu_public_ip")
		default['nagios']['allowed_hosts'] = [node.deployment.mu_public_ip]
	elsif node.deployment.has_key?("cap_public_ip")
		default['nagios']['allowed_hosts'] = [node.deployment.cap_public_ip]
	end
end

if (!node.has_key?("admins") or node.admins.size == 0) and node.tags.is_a?(Hash)
	if node.tags.has_key?("MU-OWNER")
		default['admins'] = []
		default['admins'] << node['tags']['MU-OWNER']+"@localhost"
	elsif node.tags.has_key?("MU-ADMINS")
		default['admins'] = node['tags']['MU-ADMINS'].split(/\s+/)
	end
end

begin
	default['splunk']['receiver_ip'] = node['ec2']['public_ip_address']
rescue NoMethodError
	default['splunk']['receiver_ip'] = node['ipaddress']
end

# Set this to a path to store Splunk's big databases somewhere besides
# /opt/splunk/var/lib/splunk
default['splunk']['splunkdb']['dev'] = nil
default['splunk']['splunkdb']['path'] = "/opt/splunk/var/lib/splunk"
default['splunk']['minfreespace'] = 733
default['splunk']['inputs_conf']['host'] = Chef::Config[:node_name]
default['splunk']['accept_license'] = true
default['splunk']['auth'] = {
	'data_bag' => 'splunk',
	'data_bag_item' => 'admin_user'
}
default['splunk']['ssl_options'] = {
	'enable_ssl' => true,
	'data_bag' => Chef::Config[:node_name],
	'data_bag_item' => 'ssl_cert',
	'keyfile' => 'node.key',
	'crtfile' => 'node.crt'
}

default['maldet']['install'] = true

default['sec']['root_login_disabled'] = false
default['sec']['accnt_lckout'] = 5
default['sec']['accnt_lckout_duration'] = 900
default['sec']['pwd'] = {
	'min_length' => 14,
	'numeric' => -1 ,
	'uppercase' => -1,
	'lowercase' => -1,
	'special' => -1,
	'retry' => 3,
	'remember' => 5
}

# dumb hack, or dumbest hack?
["r", "s", "t", "u", "v", "w", "x", "y", "z"].each { |drive|
	if File.exist?("/dev/xvd#{drive}")
		default[:tmp_dev] = "/dev/xvd#{drive}"
		break
	end
}

default[:application_attributes][:home]["volume_size_gb"] = 2
default[:application_attributes][:home][:mount_device] = "/dev/xvdn"
default[:application_attributes][:home][:label] = "#{disk_name_str} /home"
default[:application_attributes][:home][:mount_directory] = "/home"

default[:application_attributes][:var]["volume_size_gb"] = 2
default[:application_attributes][:var][:mount_device] = "/dev/xvdo"
default[:application_attributes][:var][:label] = "#{disk_name_str} /var"
default[:application_attributes][:var][:mount_directory] = "/var"

default[:application_attributes][:var_log]["volume_size_gb"] = 5
default[:application_attributes][:var_log][:mount_device] = "/dev/xvdp"
default[:application_attributes][:var_log][:label] = "#{disk_name_str} /var/log"
default[:application_attributes][:var_log][:mount_directory] = "/var/log"

default[:application_attributes][:var_log_audit]["volume_size_gb"] = 1
default[:application_attributes][:var_log_audit][:mount_device] = "/dev/xvdq"
default[:application_attributes][:var_log_audit][:label] = "#{disk_name_str} /var/log/audit"
default[:application_attributes][:var_log_audit][:mount_directory] = "/var/log/audit"

default['banner']['path'] = "etc/BANNER"

# Active Directory defaults
default['ad']['netbios_name'] = "mu"
default['ad']['dns_name'] = "mu.local"
default['ad']['site_name'] = "AZ1"
default['ad']['dn_dc_ou'] = "Domain Controllers"
default['ad']['dn_domain_cmpnt'] = "dc=mu,dc=local"
node.deployment.servers.each_pair { |node_class, nodes|
	nodes.each_pair { |name, data|
		if name == Chef::Config[:node_name]
			my_subnet_id = data['subnet_id']
			if !data['cap_windows_name'].nil?
				default['ad']['computer_name'] = data['cap_windows_name']
				default['ad']['node_class'] = node_class
			end
		end
	} rescue NoMethodError
} rescue NoMethodError
default['ad']['sites'] = []
if node.deployment.vpcs.size > 0
	vpc = node.deployment.vpcs[node.deployment.vpcs.keys.first]
	vpc.subnets.each_pair { |name, data|
		default['ad']['sites'] << {
			"name" => data['name'],
			"ip_block" => data['ip_block']
		}
		if !my_subnet_id.nil? and my_subnet_id == data['subnet_id']
			default['ad']['site_name'] = data['name']+"_"+data['ip_block']
		end
	}
end rescue NoMethodError
if default['ad']['sites'].size == 0
	default['ad']['sites'] = [
		{"name" => "AZ1", "ip_block" => "10.20.4.0/24"},
		{"name" => "AZ2", "ip_block" => "10.20.5.0/24"},
		{"name" => "AZ3", "ip_block" => "10.20.6.0/24"}
	]
end

default['ad']['rdgw']['computer_name'] = "RDGW1"
if !node.ec2.private_ip_address.nil?
	default['ad']['dc_ips'] = [node.ec2.private_ip_address]
end rescue NoMethodError
default['ad']['ntds_static_port'] = 50152
default['ad']['ntfrs_static_port'] = 50154
default['ad']['dfsr_static_port'] = 50156
default['ad']['add_to_domain'] = true
default['ad']['auth'] = {
	'data_bag' => 'active_directory',
	'data_bag_item' => "join_domain"
}
