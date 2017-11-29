#
# Cookbook Name:: demo
# Recipe:: filebeat
#
# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
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



# I know this is stupid. I need to do it better
elkServer = ''

elkServers = search(:node, "elk_is_server:true") do |node|
    elkServer = node["hostname"]
end

if elkServer || elkServer.length == 0
    elkServer = node['ec2']['public_dns_name']
end


case node[:platform]

when "windows" 
    Chef::Log.info("NEED TO SETUP INSTALLATION FOR #{node[:platform]}")

    # remote_file "Download Filebeat" do
    #     path "#{Chef::Config[:file_cache_path]}/filebeat.zip"
    #     source "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-5.6.3-windows-x86_64.zip"
    #     #checksum 'd8a27129ada2ff94df107b52e868d1bd4491411da07d7af1f8307c812cf4f67e18b44216ae0aa17c0204a9bc1bf5bc5dcc12a05c5ca6cd0d7ca4374272abf7ae'
    #     not_if { ::File.exist?("#{Chef::Config[:file_cache_path]}/filebeat.zip") }
    # end

else

    case node['platform_family']
    when 'debian'

        apt_repository 'elastic-5.x' do
            uri 'https://artifacts.elastic.co/packages/5.x/apt'
            components ['stable', 'main']
            distribution ''
            key 'D88E42B4'
            keyserver 'pgp.mit.edu'
            action :add
        end
        
    when 'rhel'

        yum_repository 'elastic-5.x' do
            description "ELK Repo"
            baseurl "https://artifacts.elastic.co/packages/5.x/yum"
            gpgkey 'https://artifacts.elastic.co/GPG-KEY-elasticsearch'
            action :create
        end

    end

    package 'filebeat' do
        action [:install, :upgrade]
    end

    service "filebeat" do
        action [ :enable, :start ]
    end

    template '/etc/filebeat/filebeat.yml' do
        source 'filebeat.yml.erb'
        variables(
          :logstashServer => elkServer
        )
      notifies :restart, "service[filebeat]", :delayed
    end

end