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
include_recipe "apache2::mod_filter"

case node.platform
  when "centos", "redhat"
    execute "iptables -I INPUT -p tcp --dport 80 -j ACCEPT && service iptables save" do
      not_if "iptables -nL | egrep '^ACCEPT.*dpt:80($| )'"
    end

    execute "setsebool -P httpd_can_network_connect 1" do
      not_if "getsebool httpd_can_network_connect | grep ' on$'"
      notifies :reload, "service[apache2]", :delayed
    end

    template "#{node.apache.docroot_dir}/index.html" do
      source "proxyindex.html.erb"
      mode 0644
      owner "apache"
      variables(
          :domain_name => node.application_attributes.my_domain,
          :hostname => node.hostname,
          :drupal_distro => node.application_attributes.drupal_distro,
          :mu_admins => node.deployment.admins,
          :tomcat_app => node.application_attributes.tomcat_app,
          :os_type => "#{node.platform} #{node.platform_version.to_i}"
      )
    end

    cookbook_file "#{node.apache.docroot_dir}/tiered_apps_demo_diagram.png" do
      source "tiered_apps_demo_diagram.png"
      mode 0644
      owner "apache"
    end

    web_app "proxy" do
      server_name node.application_attributes.my_domain
      server_aliases [node.fqdn, node.hostname]
      cookbook "mu-demo"
      allow_override "All"
      template "proxy.conf.erb"
      version node.apache.version
      win_apps node.winapps
      win_lb_url node.deployment.loadbalancers.winlb.dns
      lnx_lb_url node.deployment.loadbalancers.lnxlb.dns
      lnx_apps node.linux_apps
    end

    web_app "vhosts" do
      server_name node.application_attributes.my_domain
      server_aliases [node.fqdn, node.hostname]
      docroot node.apache.docroot_dir
      cookbook "mu-demo"
      allow_override "All"
      template "proxyvhosts.conf.erb"
      version node.apache.version
      log_dir node.apache.log_dir
      base_dir node.apache.dir
    end
  else
    Chef::Log.info("Unsupported platform #{node.platform}")
end
