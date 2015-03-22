#
# Cookbook Name:: mu-demo
# Recipe:: proxy
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

include_recipe "apache2::mod_proxy"
include_recipe "apache2::mod_proxy_http"
include_recipe "apache2::mod_expires"
include_recipe "apache2::mod_deflate"

$win_url = node.deployment.loadbalancers.winlb.dns
$lnx_apps = node.linux_apps
$lnx_url = node.deployment.loadbalancers.lnxlb.dns
$proxy_url = node.deployment.loadbalancers.proxylb.dns

bash "Allow TCP 80 through iptables" do
	user "root"
	not_if "/sbin/iptables -nL | egrep '^ACCEPT.*dpt:80($| )'"
	code <<-EOH
		iptables -I INPUT -p tcp --dport 80 -j ACCEPT
		service iptables save
	EOH
end

template "/var/www/html/index.html" do
	source "proxyindex.html.erb"
	mode "0644"
end

cookbook_file "/var/www/html/tiered_apps_demo_diagram.png" do
	source "tiered_apps_demo_diagram.png"
	mode "0644"
end

web_app "proxy" do
	server_name node.application_attributes.my_domain
	server_aliases [ node['fqdn'], node['hostname'] ]
	cookbook "mu-demo"
	allow_override "All"
	template "proxy.conf.erb"
end
web_app "vhosts" do
	server_name node.application_attributes.my_domain
	server_aliases [ node['fqdn'], node['hostname'] ]
	docroot "/var/www/html"
	cookbook "mu-demo"
	allow_override "All"
	template "proxyvhosts.conf.erb"
end
