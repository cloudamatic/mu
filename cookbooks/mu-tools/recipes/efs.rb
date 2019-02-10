# Cookbook Name:: mu-tools
# Recipe:: efs
#
# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#		 http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Client-side behavior for interfacing with Amazon Elastic File System

if node['deployment'].has_key?('storage_pools')
  require 'net/http'
  require 'json'

  case node['platform']
  when 'ubuntu'
    package "nfs-common"
  when "rhel", "amazon", "centos" # ~FC024
    package %w{nfs-utils nfs4-acl-tools}
  end

  instance_identity = JSON.parse(Net::HTTP.get(URI("http://169.254.169.254/latest/dynamic/instance-identity/document")))

  node['deployment']['storage_pools'].each { |_name, pool|
    pool['mount_targets'].each { |_name, target|
      if target['availability_zone'] == instance_identity["availabilityZone"]
      # Should also make it possible to choose a random endpoint if there isn't one for a specific AZ

        directory target['mount_directory'] do
          recursive true
          mode 0755
        end

        endpoint = target['endpoint']
        resolver = Resolv::DNS.new
        begin
          resolver.getaddress(endpoint)
        rescue  Resolv::ResolvError
          endpoint = target['ip_address']
        end

        if node['platform_family'] == "rhel" and node['platform_version'].to_i < 6 and node['platform'] != "amazon"
          service "portmap" do
            action [:enable, :start]
          end
        end

        mount target['mount_directory'] do
          device "#{endpoint}:/"
          fstype "nfs4"
          action [:mount, :enable]
          unless node['platform_family'] == "rhel" and node['platform_version'].to_i < 6
            options "nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2"
          end
        end

        break
      end
    }
  }
end
