#
# Cookbook Name:: demo
# Recipe:: php
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
include_recipe "php"
include_recipe "apache2::mod_php5"

document_root = '/var/www'
server_name = node.ec2.public_ip_address

web_app "default" do
  enable true
  docroot document_root
  server_name server_name
end

file "#{document_root}/index.html" do
  action :delete
end

file "#{document_root}/index.php" do
  content <<-EOH
<?php phpinfo(); ?>
  EOH
end

ruby_block "Notify_Users" do
    block do
        puts "\n######################################## End of Run Information ########################################"
        puts "# Your PHP Server is running at http://#{node['ec2']['public_dns_name']}"
        puts "########################################################################################################\n\n"
    end
    action :create
end
