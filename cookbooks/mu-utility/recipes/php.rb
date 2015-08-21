#
# Cookbook Name:: mu-utility
# Recipe:: PHP
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

case node[:platform]

  when "centos"


  when "ubuntu"

    ["php5", "php5-mysql", "libapache2-mod-php5", "php5-mysql", "php5-curl", "php5-gd", "php5-intl", "php-pear", "php5-imagick", "php5-imap", "php5-mcrypt", "php5-memcache", "php5-ming", "php5-ps", "php5-pspell", "php5-recode", "php5-snmp", "php5-sqlite", "php5-tidy", "php5-xmlrpc", "php5-xsl", "php5-fpm"].each { |pkg|
      package pkg
    }
  else
    Chef::Log.info("Unsupported platform #{node[:platform]}")
end


