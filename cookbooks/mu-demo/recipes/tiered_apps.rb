#
# Cookbook Name:: mu-demo
# Recipe:: default
#
#
# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#	  http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


$win_url = node.deployment.loadbalancers.winlb.dns
$lnx_apps = node.linux_apps
$lnx_url = node.deployment.loadbalancers.lnxlb.dns
$proxy_url = node.deployment.loadbalancers.proxylb.dns

include_recipe 'java'
include_recipe 'chef-vault'

case node[:platform]
when "windows"
	include_recipe 'tomcat'

	powershell_script "Allow 8080 traffic" do
		code <<-EOH
			New-NetFirewallRule -DisplayName "Permit Tomcat traffic" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
		EOH
		guard_interpreter :powershell_script
		not_if { WinFW::Helper.firewall_rule_enabled?("Permit Tomcat traffic") }
	end

	# template "#{node.tomcat.home}\\webapps\\manager\\WEB-INF\\web.xml" do
		# source "manager_web.xml.erb"
	# end

	cookbook_file "#{node.tomcat.home}\\lib\\jcr-2.0.jar" do
		source "jcr-2.0.jar"
		notifies :restart, "service[Tomcat7]", :delayed
	end

	node.winapps.each_pair { |app, warfile|
		next if node.application_attributes.tomcat_app != app
		remote_file "#{node.tomcat.home}\\webapps\\#{app}.war" do
			source "#{node.s3_public_url}/#{warfile}"
			notifies :restart, "service[Tomcat7]", :delayed
		end
	}

	service "Tomcat7" do
		action [ :enable, :start ]
	end

when "centos"
	include_recipe "apache2"
	include_recipe "apache2::mod_ssl"
	include_recipe "apache2::mod_php5"
	include_recipe "apache2::logrotate"
	include_recipe "git"
	
	%w{openssl php-mysql php-pear php-drush-drush php-gd}.each { |pkg|
		package pkg
	}

	package "mysql" if node.platform_version.to_i == 6
	
	if node.platform_version.to_i == 7
		%w{mariadb-server mariadb}.each { |pkg|
			package pkg
		}

		service "mariadb" do
			action [ :enable, :start ]
		end
	end

	execute "iptables -I INPUT -p tcp --dport 80 -j ACCEPT && service iptables save" do
		not_if "iptables -nL | egrep '^ACCEPT.*dpt:80($| )'"
	end

	file "#{node.apache.docroot_dir}/index.html" do
	  content "This is #{node.hostname}"
	end

	if !File.exist?("#{node.apache.docroot_dir}/drupal/.htaccess")
		file "/root/drupal-org-core.make" do
			content "
api = 2
core = 7.x
projects[drupal][version] = 7.31
projects[drupal][type] = core
projects[drupal][patch][972536] = http://drupal.org/files/issues/object_conversion_menu_router_build-972536-1.patch
projects[drupal][patch][992540] = http://drupal.org/files/issues/992540-3-reset_flood_limit_on_password_reset-drush.patch
projects[drupal][patch][1355984] = http://drupal.org/files/1355984-timeout_on_install_with_drush_si-make.patch
projects[drupal][patch][1369024] = http://drupal.org/files/1369024-theme-inc-add-messages-id-make-D7.patch
projects[drupal][patch][1369584] = http://drupal.org/files/1369584-form-error-link-from-message-to-element-D7.patch
projects[drupal][patch][1697570] = http://drupal.org/files/drupal7.menu-system.1697570-29.patch
"
		end
		["build-openpublic.make", "drupal-org-core-openpublic.make", "drupal-org-core.make"].each { |makefile|
			cookbook_file "/root/#{makefile}" do
				source makefile
			end
		}

		if node.application_attributes.drupal_distro == "openpublic"
# XXX Buggy for now. See https://www.drupal.org/node/2345595
#				execute "install OpenPublic Drupal" do
#					command "drush make --force-complete --prepare-install /root/build-openpublic.make #{node.apache.docroot_dir}/drupal"
#					cwd "#{node.apache.docroot_dir}"
#				end
			remote_file "/root/openpublic.tar.gz" do
				source "http://ftp.drupal.org/files/projects/openpublic-7.x-1.0-rc5-core.tar.gz"
				not_if "test -f /root/openpublic.tar.gz"
			end
			execute "tar -xzf /root/openpublic.tar.gz && mv openpublic-7.x-1.0-rc5 drupal" do
				cwd "#{node.apache.docroot_dir}"
				not_if "test -d #{node.apache.docroot_dir}/drupal"
			end
		else
			execute "install Vanilla Drupal" do
				command "drush make --force-complete --prepare-install /root/drupal-org-core.make #{node.apache.docroot_dir}/drupal"
				cwd "#{node.apache.docroot_dir}"
			end
		end
	end
	template "#{node.apache.docroot_dir}/drupal/sites/default/settings.php" do
		source "settings.php.erb"
	end

	["httpd_can_network_connect", "httpd_can_network_connect_db", "httpd_can_sendmail"].each { |priv|
		execute "setsebool -P #{priv} 1" do
			not_if "getsebool #{priv} | grep ' on$'"
			notifies :reload, "service[apache2]", :delayed
		end
	}

	execute "htaccess set rewritebase" do
		command "echo 'RewriteBase /drupal' >> #{node.apache.docroot_dir}/drupal/.htaccess"
		not_if "grep '^RewriteBase /drupal$' #{node.apache.docroot_dir}/drupal/.htaccess"
	end

	execute "find #{node.apache.docroot_dir}/drupal -type f -exec chmod 644 {} \\;"
	execute "find #{node.apache.docroot_dir}/drupal -type d -exec chmod 755 {} \\;"

	directory "#{node.apache.docroot_dir}/drupal/sites/default/files" do
		owner "apache"
		group "apache"
		mode "0755"
	end

	chef_gem 'simple-password-gen'

	execute "drush cc all" do
		cwd "#{node.apache.docroot_dir}/drupal"
		action :nothing
	end

	execute "sed -i 's/^memory_limit.*/memory_limit = -1/' /etc/php.ini" do
		not_if "grep '^memory_limit = -1$' /etc/php.ini"
		notifies :reload, "service[apache2]", :immediately
	end

	# First-time database setup actions should only be run on one node.
	first_node_struct = node.deployment.servers.linuxapps.first[1]
	if first_node_struct['nodename'] == Chef::Config[:node_name]
		profile = "standard"
		profile = "openpublic" if node.application_attributes.drupal_distro == "openpublic"
		execute "drush -y si #{profile} --site-name='#{node.application_attributes.my_domain}'" do
			cwd "#{node.apache.docroot_dir}/drupal"
			not_if "cd #{node.apache.docroot_dir}/drupal && ( `drush sql-connect` -e \"SHOW TABLES\" | grep drupal_cache )"
		end
		if profile == "standard"
			execute "drush vset theme_default nexus" do
				cwd "#{node.apache.docroot_dir}/drupal"
				notifies :run, "execute[drush cc all]", :delayed
			end
			execute "drush pm-enable -y nexus" do
				cwd "#{node.apache.docroot_dir}/drupal"
				notifies :run, "execute[drush cc all]", :delayed
			end
		end
		first_admin = nil
		node.deployment.admins.each_value { |admin|
			if !node.application_attributes.has_key?('drupal_pws')
				node.normal.application_attributes.drupal_pws = Hash.new
				node.save
			end
			if !node.application_attributes.drupal_pws.has_key?(admin['email'])
				require 'simple-password-gen'
				node.normal.application_attributes.drupal_pws[admin['email']] = Password.pronounceable(9..12)
				node.save
			end
			first_admin = admin['email'] if !first_admin
			execute "create Drupal admin user #{admin['name']}" do
				command "drush user-create '#{admin['email']}' --mail='#{admin['email']}'"
				not_if "cd #{node.apache.docroot_dir}/drupal && drush user-information '#{admin['email']}'"
				cwd "#{node.apache.docroot_dir}/drupal"
			end
			execute "grant admin privileges to #{admin['name']}" do
				command "drush user-add-role administrator '#{admin['name']}'"
				cwd "#{node.apache.docroot_dir}/drupal"
				not_if "drush uinf '#{admin['name']}' --fields=roles | grep ' administrator( |$)'"
			end
		}
		execute "set site mail" do
			command "drush vset site_mail '#{first_admin}'"
			cwd "#{node.apache.docroot_dir}/drupal"
			not_if "drush vget site_mail | grep '^#{first_admin}$'"
			notifies :run, "execute[drush cc all]", :delayed
		end
	end

	web_app "vhosts" do
		server_name node.application_attributes.my_domain
		server_aliases [ node.fqdn, node.hostname ]
		docroot node.apache.docroot_dir
		cookbook "mu-demo"
		allow_override "All"
		template "vhosts.conf.erb"
	end

else
	Chef::Log.info("Unsupported platform #{node[:platform]}")
end

