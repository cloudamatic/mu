#
# Cookbook Name:: mu-openvpn
# Recipe:: default
#
# Copyright 2015, eGlobalTech, Inc
#
# All rights reserved - Do Not Redistribute
#

include_recipe 'chef-vault'

users_vault = chef_vault_item(node['openvpn']['users_vault']['vault'], node['openvpn']['users_vault']['item'])

case node['platform']
  when platform_family?('rhel')
    include_recipe 'mu-firewall'

    node['openvpn']['fw_rules'].each { |rule|
      firewall_rule "Allow openvpn #{rule[:port]}" do
        port rule[:port]
        protocol rule[:protocol].to_sym
      end
    }

    remote_file "#{Chef::Config[:file_cache_path]}/#{node['openvpn']['package']}" do
      source "#{node['openvpn']['base_url']}/#{node['openvpn']['package']}"
    end

    group "openvpn"

    node['openvpn']['users'].each { |user|
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
      source "#{Chef::Config[:file_cache_path]}/#{node['openvpn']['package']}"
    end

    service 'openvpnas' do
      action :nothing
    end

    if node['openvpn']['use_ca_signed_cert']
      certs_vault = chef_vault_item(node['openvpn']['cert_vault']['vault'], node['openvpn']['cert_vault']['item'])

      node['openvpn']['cert_names'].each { |type|
        vault_item = type[:vault_item]
        file "#{node['openvpn']['cert_dir']}/#{type[:openvpn_name]}" do
          mode 0400
          content certs_vault[vault_item].strip
          sensitive true
          owner "openvpn"
          group "openvpn"
          notifies :restart, "service[openvpnas]"
        end
      }
    end

    if node['openvpn']['configure_ldap_auth']
      ldap_vault = chef_vault_item(node['openvpn']['ldap_vault']['vault'], node['openvpn']['ldap_vault']['item'])
      execute "Setting LDAP bind password" do
        command "./sacli -k auth.ldap.0.bind_pw -v #{ldap_vault[node['openvpn']['ldap_vault']['field']]} ConfigPut"
        cwd node['openvpn']['scripts']
        not_if "#{node['openvpn']['scripts']}/sacli ConfigQuery | grep auth.ldap.0.bind_pw | grep #{ldap_vault[node['openvpn']['ldap_vault']['field']]}"
        notifies :restart, "service[openvpnas]"
        sensitive true
      end
    end

    node['openvpn']['vpc_networks'].each.with_index { |cidr, i|
      execute "./sacli -k vpn.server.routing.private_network.#{i} -v #{cidr} ConfigPut" do
        cwd node['openvpn']['scripts']
        not_if "#{node['openvpn']['scripts']}/sacli ConfigQuery | grep vpn.server.routing.private_network.#{i} | grep #{cidr}"
        notifies :restart, "service[openvpnas]"
      end
    }

    node['openvpn']['config'].each { |key, value|
      execute "./sacli -k #{key} -v #{value} ConfigPut" do
        cwd node['openvpn']['scripts']
        not_if "#{node['openvpn']['scripts']}/sacli ConfigQuery | grep #{key} | grep #{value}"
        notifies :restart, "service[openvpnas]"
      end
    }

    template "#{Chef::Config[:file_cache_path]}/openvpn_users.json" do
      source "users.json.erb"
      variables(
          :users => node['openvpn']['users']
      )
    end

    execute "./confdba -ulf #{Chef::Config[:file_cache_path]}/openvpn_users.json" do
      # Change user configuration to create json instead of just using this statically
      # This doesn't create the user accounts, just allows pre existing LDAP/PAM user accounts access to OpenVPN. We limit access to allowed users only.
      # need to add a guard
      cwd node['openvpn']['scripts']
    end
  else
    Chef::Log.info("Unsupported platform #{node['platform']}")
end
