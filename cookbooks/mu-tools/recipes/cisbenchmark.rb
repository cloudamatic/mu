#
# Cookbook Name:: mu-tools
# Recipe:: cisbenchmark
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

include_recipe "mu-utility::zip"
include_recipe "java"

remote_file "#{Chef::Config[:file_cache_path]}/cis-cat-full.zip" do
  source "https://s3.amazonaws.com/femadata-sandbox-public/ciscat-full-bundle.zip"
end

execute "unzip -u #{Chef::Config[:file_cache_path]}/cis-cat-full.zip" do
  cwd Chef::Config[:file_cache_path]
end

file "#{Chef::Config[:file_cache_path]}/cis-cat-full/CIS-CAT.sh" do
  mode "744"
end

execute "Run CIS Benchmark" do
  command "./CIS-CAT.sh -t -a -b benchmarks/CIS_CentOS_Linux_6_Benchmark_v1.0.0.xml"
  cwd "#{Chef::Config[:file_cache_path]}/cis-cat-full"
end

execute "zip -r /tmp/cis-results.zip /root/CIS-CAT_Results"

package "mailx"

bash "mail results" do
  user "root"
  code <<-EOH
		echo "The node has been configured and the security file can be found in /tmp/cis-cat-full.zip directory" | mailx -a /tmp/cis-results.zip -s "#{node.name} security report" -- #{node.admins.first}
  EOH
end

#Don't Keep old scans so we won't get confused
directory "/root/CIS-CAT_Results" do
  recursive true
  action :delete
end

file "/tmp/cis-results.zip" do
  action :delete
end

