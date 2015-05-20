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

case node.platform_family
when "windows"
	%w{client.rb first-boot.json client.pem validation.pem}.each { |file|
		file "C:\\Users\\Administrator\\AppData\\Local\\Temp\\#{file}" do
			content IO.read("C:\\chef\\#{file}")
		end

		file "C:\\chef\\#{file}" do
			action :delete
		end
	}
when "rhel"
	if node.platform_version.to_i == 7
		execute "sed -i '/^preserve_hostname/d' /etc/cloud/cloud.cfg" do
			only_if "grep 'preserve_hostname: true' /etc/cloud/cloud.cfg"
		end
	end

	directory "/etc/chef" do
		action :delete
		recursive true
	end
else
	directory "/etc/chef" do
		action :delete
		recursive true
	end
end
