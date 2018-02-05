default.ad.samba_include_file = "smb_extra.conf"
default.ad.samba_conf_dir = "/etc/samba"
default.ad.netbios_name = "cloudamatic"
default.ad.dns_name = "ad.cloudamatic.com"
default.ad.site_name = "AZ1"
default.ad.dn_dc_ou = "Domain Controllers"
default.ad.dn_domain_cmpnt = "dc=ad,dc=cloudamatic,dc=com"
default.ad.computer_ou = nil
default.ad.domain_controller_names = []
default.ad.computer_name = nil
default.ad.homedir = "/home/%u"

# This is done in Mu.
# node.deployment.servers.each_pair { |node_class, nodes|
# nodes.each_pair { |name, data|
# if name == Chef::Config[:node_name]
# my_subnet_id = data['subnet_id']
# if node.ad.domain_controller_names.empty?
# if data['mu_windows_name']
# default.ad.computer_name = data['mu_windows_name']
# default.ad.node_class = node_class
# end
# end
# end
# } rescue NoMethodError
# } rescue NoMethodError

default.ad.sites = []
if !node['deployment']['vpcs'].empty?
  vpc = node.deployment.vpcs[node.deployment.vpcs.keys.first]
  vpc.subnets.each_pair { |name, data|
    default.ad.sites << {
        :name => data['name'],
        :ip_block => data['ip_block']
    }
  }
end rescue NoMethodError

default.ad.ntds_static_port = 50152
default.ad.ntfrs_static_port = 50154
default.ad.dfsr_static_port = 50156
default.ad.netlogon_static_port = 50158

default.windows_admin_username = "Administrator"
# Credentials for joining an Active Directory domain should be stored in a Chef
# Vault structured like so:
# {
#   "username": "join_domain_user",
#   "password": "join_domain_password"
# }

begin
  default.ad.admin_auth = {
      :vault          => node['ad']['domain_admin_vault'],
      :item           => node['ad']['domain_admin_item'],
      :password_field => node['ad']['domain_admin_password_field'],
      :username_field => node['ad']['domain_admin_username_field']
  }
rescue NoMethodError => e
  default.ad.admin_auth = {
      :vault => "activedirectory",
      :item => "domain_admin",
      :password_field => "password",
      :username_field => "username"
  }
end

begin
  default.ad.join_auth = {
      :vault          => node['ad']['domain_join_vault'],
      :item           => node['ad']['domain_join_item'],
      :password_field => node['ad']['domain_join_password_field'],
      :username_field => node['ad']['domain_join_username_field']
  }
rescue NoMethodError => e
  default.ad.join_auth = {
      :vault => "activedirectory",
      :item => "join_domain",
      :password_field => "password",
      :username_field => "username"
  }
end

default[:ad][:dc_ips] = []
if node['ad']['dc_ips'].empty?
  resolver = Resolv::DNS.new
  node['ad']['dcs'].each { |dc|
    if dc.match(/^\d+\.\d+\.\d+\.\d+$/)
      default[:ad][:dc_ips] << dc
    else
      begin
        default[:ad][:dc_ips] << resolver.getaddress(dc).to_s
      rescue Resolv::ResolvError => e
        Chef::Log.warn ("Couldn't resolve domain controller #{dc}!")
      end
    end
  } rescue NoMethodError
end
