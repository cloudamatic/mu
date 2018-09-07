default['openvpn']['version'] = "2.1.4"
case node['platform_family']
  when "rhel"
    default['openvpn']['package'] = "openvpn-as-#{node['openvpn']['version']}-CentOS#{node['platform_version'].to_i}.x86_64.rpm"
end

default['openvpn']['vpc_networks'] = %w{172.31.0.0/16 10.0.0.0/16}
default['openvpn']['base_url'] = "http://swupdate.openvpn.org/as"
default['openvpn']['url'] = node['ec2']['public_ip_address']
default['openvpn']['base_dir'] = "/usr/local/openvpn_as"
default['openvpn']['scripts'] = "#{node['openvpn']['base_dir']}/scripts"
default['openvpn']['bin'] = "#{node['openvpn']['base_dir']}/bin"
default['openvpn']['cert_dir'] = "#{node['openvpn']['base_dir']}/etc/web-ssl"
default['openvpn']['use_ca_signed_cert'] = false
default['openvpn']['configure_ldap_auth'] = false
default['openvpn']['ldap_bind_dn'] = "OU=org, DC=example, DC=net"
default['openvpn']['ldap_display_name'] = "My LDAP servers"
default['openvpn']['ldap_server1'] = "ldapsvr1"
default['openvpn']['ldap_server2'] = "ldapsvr2"
default['openvpn']['ldap_username_attr'] = "sAMAccountName"
default['openvpn']['ldap_users_base_dn'] = "CN=Users, DC=example, DC=net"
default['openvpn']['ldap_ssl_verify'] = "never"
# ldap_ssl_verify can be set to: demand, allow or never
default['openvpn']['ldap_use_ssl'] = "never"
# ldap_use_ssl can be set to: always, adaptive or never
default['openvpn']['auth_type'] = "pam"
default['openvpn']['tls_version_server'] = 1.0
default['openvpn']['tls_version_client'] = 1.2
default['openvpn']['ssl_lib'] = "openssl"
default['openvpn']['https_port'] = 943
default['openvpn']['daemon_tcp_port'] = 443
default['openvpn']['daemon_udp_port'] = 1194
default['openvpn']['internal_network_ip'] = "172.27.224.0"
default['openvpn']['internal_network_netmask'] = 20
default['openvpn']['routing_method'] = "nat"
default['openvpn']['reroute_all_traffic'] = false
default['openvpn']['ssl_ciphersuites'] = "DEFAULT:!EXP:!PSK:!SRP:!MEDIUM:!LOW:!RC4:!3DES"
default['openvpn']['multiple_user_sessions'] = false

default['openvpn']['fw_rules'] = [
    {:port => 443, :protocol => "tcp"},
    {:port => 1194, :protocol => "udp"}
]
default['openvpn']['cert_names'] = [
    {:openvpn_name => "server.crt", :vault_item => "cert"},
    {:openvpn_name => "server.key", :vault_item => "key"},
    {:openvpn_name => "ca.crt", :vault_item => "bundle"}
]
default['openvpn']['config'] = {
    # bah!
    "cs.tls_version_min" => node['openvpn']['tls_version_client'],
    "cs.ssl_reneg" => false,
    "sa.ssl_lib" => node['openvpn']['ssl_lib'],
    "host.name" => node['openvpn']['url'],
    "vpn.client.routing.inter_client" => false,
    "vpn.client.routing.reroute_dns" => true,
    "vpn.client.routing.reroute_gw" => node['openvpn']['reroute_all_traffic'],
    "vpn.server.routing.gateway_access" => true,
    "vpn.client.config_text" => "'-remote \nremote-random'",
    "vpn.server.tls_version_min" => node['openvpn']['tls_version_server'],
    "admin_ui.https.ip_address" => "eth0",
    "admin_ui.https.port" => node['openvpn']['https_port'],
    "auth.ldap.0.name" => "'#{node['openvpn']['ldap_display_name']}'",
    "auth.ldap.0.ssl_verify" => node['openvpn']['ldap_ssl_verify'],
    "auth.ldap.0.timeout" => 4,
    "auth.ldap.0.use_ssl" => node['openvpn']['ldap_use_ssl'],
    "auth.ldap.0.bind_dn" => "'#{node['openvpn']['ldap_bind_dn']}'",
    "auth.ldap.0.server.0.host" => node['openvpn']['ldap_server1'],
    "auth.ldap.0.server.1.host" => node['openvpn']['ldap_server2'],
    # "auth.ldap.0.ssl_ca_cert" => node['openvpn'][:ldap_ssl_ca_cert],
    "auth.ldap.0.uname_attr" => node['openvpn']['ldap_username_attr'],
    "auth.ldap.0.users_base_dn" => "'#{node['openvpn']['ldap_users_base_dn']}'",
    "auth.module.type" => node['openvpn']['auth_type'],
    "auth.pam.0.service" => "openvpnas",
    "auth.radius.0.acct_enable" => "false",
    "auth.radius.0.name" => "'#{node['openvpn']['ldap_display_name']}'",
    "cs.cws_proto_v2" => true,
    "cs.https.ip_address" => "eth0",
    "cs.https.port" => node['openvpn']['https_port'],
    "cs.prof_sign_web" => true,
    "cs.ssl_method" => "SSLv3",
    "cs.openssl_ciphersuites" => node['openvpn']['ssl_ciphersuites'],
    "sa.initial_run_groups.0" => "web_group",
    "sa.initial_run_groups.1" => "openvpn_group",
    "vpn.daemon.0.client.netmask_bits" => node['openvpn']['internal_network_netmask'],
    "vpn.daemon.0.client.network" => node['openvpn']['internal_network_ip'],
    "vpn.daemon.0.listen.ip_address" => "eth0",
    "vpn.daemon.0.listen.port" => node['openvpn']['daemon_tcp_port'],
    "vpn.daemon.0.listen.protocol" => "tcp",
    "vpn.general.osi_layer" => "3",
    "vpn.daemon.0.server.ip_address" => "eth0",
    "vpn.server.duplicate_cn" => node['openvpn']['multiple_user_sessions'],
    "vpn.server.daemon.enable" => true,
    "vpn.server.daemon.tcp.n_daemons" => 2,
    "vpn.server.daemon.tcp.port" => node['openvpn']['daemon_tcp_port'],
    "vpn.server.daemon.udp.n_daemons" => 2,
    "vpn.server.daemon.udp.port" => node['openvpn']['daemon_udp_port'],
    "vpn.server.group_pool.0" => "172.27.240.0/20",
    "vpn.server.port_share.enable" => true,
    "vpn.server.port_share.ip_address" => "1.2.3.4",
    "vpn.server.port_share.port" => 1234,
    "vpn.server.port_share.service" => "admin+client",
    "vpn.server.routing.private_access" => node['openvpn']['routing_method'],
    "vpn.tls_refresh.do_reauth" => true,
    "vpn.tls_refresh.interval" => 360
}
default['openvpn']['users'] = [
    {:name => "openvpn", :type => "admin", :auth => "os"}
# ,{ :name => "user_name", :type => "user" }
]
default['openvpn']['users_vault'] = {
    :vault => "openvpn", :item => "users"
}
default['openvpn']['cert_vault'] = {
    :vault => "certs", :item => "star_muplatform"
}
default['openvpn']['ldap_vault'] = {
    :vault => "openvpn", :item => "ldap", :field => "bind_password"
}
