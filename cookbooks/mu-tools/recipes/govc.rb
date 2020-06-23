# Cookbook Name::mu-tools
# Recipe::gpvc
#
# Copyright:: Copyright (c) 2020 eGlobalTech, Inc., all rights reserved
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


execute "gunzip govc archive" do
  command "gunzip -f #{Chef::Config[:file_cache_path]}/govc_linux_amd64.gz"
  action :nothing
end

remote_file "#{Chef::Config[:file_cache_path]}/govc_linux_amd64.gz" do
  source "https://github.com/vmware/govmomi/releases/download/v0.23.0/govc_linux_amd64.gz"
  notifies :run, 'execute[gunzip govc archive]', :immediately
end

remote_file "/opt/mu/bin/govc" do
  source "file:///#{Chef::Config[:file_cache_path]}/govc_linux_amd64"
  mode 0755
  action :create_if_missing
  notifies :create, "remote_file[#{Chef::Config[:file_cache_path]}/govc_linux_amd64.gz]", :before
end
