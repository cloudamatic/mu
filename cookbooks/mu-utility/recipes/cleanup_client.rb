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

case node[:platform]

	when "centos"

		bash "Install system updates" do
        user "root"
		code <<-EOH

		yum -y update

		EOH
		end


	when "ubuntu"
		include_recipe "mu-utility::apt"
		bash "Install system updates" do
        user "root"
		code <<-EOH
		apt-get -y upgrade

cat >> /etc/ssh/sshd_config << EOF
PermitRootLogin without-password
EOF

cat /root/.ssh/authorized_keys | sed 's/^.*ssh-rsa//g' > /tmp/temp && mv /tmp/temp /root/.ssh/authorized_keys
cat /root/.ssh/authorized_keys | sed '1s/^/ssh-rsa/' > /tmp/temp && mv /tmp/temp /root/.ssh/authorized_keys

/etc/init.d/ssh restart

		EOH
		end
	
	else
		Chef::Log.info("Unsupported platform #{node[:platform]}")
end
