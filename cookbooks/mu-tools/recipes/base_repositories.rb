# Cookbook Name:: mu-tools
# Recipe:: base_repositories
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
# Install the EPEL yum repository for CentOS.

if !node['application_attributes']['skip_recipes'].include?('base_repositories')
  case node['platform_family']
    when "rhel", "redhat", "amazon" # ~FC024
      # Workaround for EOL CentOS 5 repos
      if node['platform_family'] != "amazon" and node['platform_version'].to_i <= 6
        cookbook_file "/etc/yum.repos.d/CentOS-Base.repo" do
          source "CentOS-Base.repo"
        end
      end
      include_recipe "yum-epel"
  end
  if platform_family?("amazon")
    package "cronie"
  end
end
