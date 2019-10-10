#
# Cookbook Name:: php5-apache
# Recipe:: default
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

include_recipe "apache2"

build_essential 'name' do
  compile_time  True
end

case node['platform']

  when "centos"
    include_recipe "yum-epel"
    include_recipe "mu-utility::remi"

    # PHP, from Remi (for 5.4)
    ["mysql-client", "mysql-libs", "mysql-devel", "compat-mysql51", "compat-mysql51-devel", "php", "php-cli"].each { |pkg|
      package pkg do
        options "--enablerepo=remi"
        action :install
      end
    }

    # What we really mean is "chef_gem" but that insists on running
    # at compile time, before any of its dependencies are ready.
    gem_package "mysql"

    # Sundry libraries for PHP
    ["libmcrypt", "libmcrypt-devel", "php-devel", "php-pdo", "php-mysql", "php-pgsql", "php-gd", "php-pspell", "php-snmp", "php-xmlrpc", "php-xml", "php-mbstring", "php-mcrypt", "php-pear"].each { |pkg|
      package pkg do
        options "--enablerepo=remi"
        action :install
      end
    }
    # PECL modules
    ["php-pecl-memcache", "php-pecl-mongo", "php-pecl-sqlite"].each { |pkg|
      package pkg do
        options "--enablerepo=remi"
        action :install
      end
    }

    bash "Allow http and https through iptables" do
      user "root"
      not_if "/sbin/iptables -nL | egrep '^ACCEPT.*dpt:(80|443)($| )'"
      code <<-EOH
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT
    service iptables save
      EOH
    end

  when "ubuntu"
# XXX rewrite this: https://launchpad.net/~ondrej/+archive/php5-oldstable
    bash "set default mysql passwords [bad]" do
      user "root"
      code <<-EOH
				debconf-set-selections <<< 'mysql-server-5.5 mysql-server/root_password password root'
				debconf-set-selections <<< 'mysql-server-5.5 mysql-server/root_password_again password root'
      EOH
    end
    ["mysql-server", "php5", "php5-mysql", "libapache2-mod-php5", "php5-curl", "php5-gd", "php5-intl", "php-pear", "php5-imagick", "php5-imap", "php5-mcrypt", "php5-memcache", "php5-ming", "php5-ps", "php5-pspell", "php5-recode", "php5-snmp", "php5-sqlite", "php5-tidy", "php5-xmlrpc", "php5-xsl"].each { |pkg|
      package pkg
    }
    bash "Allow http and https through iptables" do
      user "root"
      not_if "/sbin/iptables -nL | egrep '^ACCEPT.*dpt:(80|443)($| )'"
      code <<-EOH
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT
      EOH
    end

  else
    Chef::Log.info("Unsupported platform #{node['platform']}")

end

cookbook_file "/etc/php.ini" do
  source "php.ini"
  notifies :restart, "service[apache2]", :delayed
end
