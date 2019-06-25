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

if !node['application_attributes']['skip_recipes'].include?('newclient')
  unless node['recipes'].include?("chef-server")
    file Chef::Config[:validation_key] do
      action :delete
      backup false
      only_if { ::File.exist?(Chef::Config[:client_key]) }
    end
  end

  selinux_state "SELinux Enforcing" do
    action :enforcing
    notifies :reboot_now, 'reboot[now]', :immediately
  end
  
  reboot 'now' do
    action :nothing
    reason 'Must reboot to enable SELinux.'
  end
end
