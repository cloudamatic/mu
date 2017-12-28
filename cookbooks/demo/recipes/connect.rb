#
# Cookbook Name:: demo
# Recipe:: connect
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

chef_gem "json" do
  action :install
end

require 'json'

$timestamp=node.deployment.timestamp

bash "create env directory" do
  user "root"
  code <<-EOH

		mkdir /tmp/env

  EOH
end

template "/tmp/env/deployment.json" do
  source "#{node.chef_environment}/deployment.json.erb"
  mode 0755
  owner "root"
  group "root"
end

$service_name = node.normal.service_name;

bash "copy env directory to #{node[node.chef_environment][$service_name].apps_dir}" do
  user "root"
  code <<-EOH

		apps_dir=#{node[node.chef_environment][$service_name].apps_dir}

		cp -rf /tmp/env $apps_dir

  EOH
end

