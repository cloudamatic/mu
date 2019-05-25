#
# Cookbook Name:: mu-tools
# Recipe:: clamav
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


if !node['application_attributes']['skip_recipes'].include?('clamav')
  if platform_family?("rhel") or platform_family?("amazon")
    include_recipe "yum-epel"
    if node['platform_version'].to_i >= 7
      package "clamav-update"
    end
    cookbook_file "/etc/freshclam.conf" do
      source "etc/freshclam.conf"
      mode 0644
      owner "root"
      group "root"
    end
    freshclam = "/usr/bin/freshclam"
    freshclam = "/bin/freshclam" if File.exist?("/bin/freshclam")
    execute freshclam do
      action :nothing
    end
    package "clamav" do
  #		notifies :run, "execute[#{freshclam}]", :delayed
    end
    package "clamav-devel"
    if node['platform_version'].to_i < 7
  	  package "clamav-milter"
  	end
  elsif platform_family?("debian")
    include_recipe "mu-utility::apt"
    package "clamav"
    package "clamav-daemon"
    package "clamav-freshclam" # this is a daemon, no need to run explicitly
    package "clamav-milter"
    package "libclamav-dev"
  else
  end
end
