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
include_recipe "mu-tools::windows-client"

if !node.ad.nil? and node.ad.size > 1
	if node.ad.domain_operation == "join"
		include_recipe "mu-activedirectory::domain-node"
	elsif node.ad.domain_operation == "create"
		include_recipe "mu-activedirectory::domain"
	elsif node.ad.domain_operation == "add_controller"
		include_recipe "mu-activedirectory::domain-controller"
	end
end rescue NoMethodError
