#
# Cookbook Name:: mu-utility
# Recipe:: mysql
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

case node[:platform]

	when "centos"


	when "ubuntu"

		bash "install mysql on ubuntu" do
	        user "root"
	        code <<-EOH

dpkg -s mysql-client >/dev/null 2>&1 && sudo apt-get -y remove mysql-client
dpkg -s mysql-server >/dev/null 2>&1 && sudo apt-get -y remove mysql-server

command -v debconf-set-selections || sudo apt-get -y install debconf-utils --force-yes

echo mysql-server-5.5 mysql-server/root_password password root | sudo debconf-set-selections
echo mysql-server-5.5 mysql-server/root_password_again password root | sudo debconf-set-selections

command -v add-apt-repository || sudo apt-get -y install software-properties-common --force-yes
sudo add-apt-repository -y ppa:ondrej/mysql --force-yes
sudo apt-get update --force-yes
export DEBIAN_FRONTEND=noninteractive 
sudo apt-get -y install mysql-client-5.5 mysql-server-5.5 --force-yes

			EOH
		end

	else
		Chef::Log.info("Unsupported platform #{node[:platform]}")
end
