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

unless node[:recipes].include?("chef-server")
  file Chef::Config[:validation_key] do
    action :delete
    backup false
    only_if { ::File.exists?(Chef::Config[:client_key]) }
  end
end

include_recipe "mu-tools::updates"
# if !node.ad.nil? and node.ad.size > 1
	# include_recipe "active-directory::domain-node"
# end rescue NoMethodError

if node[:platform] == "windows"
	include_recipe 'windows::reboot_handler'
	::Chef::Recipe.send(:include, Chef::Mixin::PowershellOut)

	windows_reboot 1 do
		reason 'Applying updates'
		action :nothing
	end

	if registry_key_exists?("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired")
		ruby_block "restart windows" do
			block do
				puts "Restarting Windows"
			end
			notifies :request, 'windows_reboot[1]'
		end
		execute "shutdown -r -f -t 0"
	end

end
