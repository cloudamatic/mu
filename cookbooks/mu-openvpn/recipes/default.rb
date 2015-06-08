#
# Cookbook Name:: mu-openvpn
# Recipe:: default
#
# Copyright 2015, eGlobalTech, Inc
#
# All rights reserved - Do Not Redistribute
#

include_recipe 'chef-vault'
include_recipe 'mu-utility::iptables'

users_vault = chef_vault_item(node.openvpn.users_vault[:vault], node.openvpn.users_vault[:item])

case node.platform
when "centos", "redhat"
	node.openvpn.fw_rules.each { |rule|
		execute "iptables -I INPUT -p #{rule[:protocol]} --dport #{rule[:port]} -j ACCEPT; service iptables save" do
			not_if "iptables -nL | egrep '^ACCEPT.*#{rule[:protocol]}.*dpt:#{rule[:port]}($| )'"
		end
	}

	remote_file "#{Chef::Config[:file_cache_path]}/#{node.openvpn.package}" do
		source "#{node.openvpn.base_url}/#{node.openvpn.package}"
	end

	group "openvpn"

	node.openvpn.users.each { |user|
		if user[:auth] == "os"
			user user[:name] do
				gid "openvpn"
				home "/home/#{user[:name]}"
				shell "/sbin/nologin"
				password users_vault["#{user[:name]}_password_hash"]
			end
		end
	}

	package "openvpn-as" do
		source "#{Chef::Config[:file_cache_path]}/#{node.openvpn.package}"
	end

	service 'openvpnas' do
		action :nothing
	end

	if node.openvpn.use_ca_signed_cert
		certs_vault = chef_vault_item(node.openvpn.cert_vault[:vault], node.openvpn.cert_vault[:item])

		node.openvpn.cert_names.each { |type|
			vault_item = type[:vault_item]
			file "#{node.openvpn.cert_dir}/#{type[:openvpn_name]}" do
				mode 0400
				content certs_vault[vault_item].strip
				sensitive true
				owner "openvpn"
				group "openvpn"
			end
		}
	end

	ldap_vault = chef_vault_item(node.openvpn.ldap_vault[:vault], node.openvpn.cert_vault[:item]) if node.openvpn.configure_ladp_auth

	node.openvpn.vpc_networks.each.with_index { |cidr, i|
		execute "./sacli -k vpn.server.routing.private_network.#{i} -v #{cidr} ConfigPut" do
			cwd node.openvpn.scripts
			not_if "#{node.openvpn.scripts}/sacli ConfigQuery | grep vpn.server.routing.private_network.#{i} | grep #{cidr}"
		end
	}

	node.openvpn.config.each { |key, value|
		execute "./sacli -k #{key} -v #{value} ConfigPut" do
			cwd node.openvpn.scripts
			not_if "#{node.openvpn.scripts}/sacli ConfigQuery | grep #{key} | grep #{value}"
		end
	}

	template "#{Chef::Config[:file_cache_path]}/openvpn_users.json" do
		source "users.json.erb"
		variables(
			:users => node.openvpn.users
		)
	end

	execute "./confdba -ulf #{Chef::Config[:file_cache_path]}/openvpn_users.json" do
		# Change user configuration to create json instead of just using this statically
		# This doesn't create the user accounts, just allows pre existing LDAP/PAM user accounts access to OpenVPN. We limit access to allowed users only.
		# need to add a guard
		cwd node.openvpn.scripts
	end
else
	Chef::Log.info("Unsupported platform #{node.platform}")
end
