#
# Cookbook Name:: mu-tools
# Recipe:: maldet
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
# Installs maldetect and enables a cron job to scan all local filesystems at
# a random time once per day.
if node.maldet.install == true
	include_recipe "mu-tools::clamav"

	if !platform_family?("windows")
		execute "unpack maldetect" do
		  cwd Chef::Config[:file_cache_path]
		  command "tar xfz maldetect-current.tar.gz"
			action :nothing
		end

		# XXX Probably ought to pick a version and checksum it.
		remote_file "#{Chef::Config[:file_cache_path]}/maldetect-current.tar.gz" do
		  action :create
		  source "http://www.rfxn.com/downloads/maldetect-current.tar.gz"
		  owner "root"
		  group "root"
			notifies :run, "execute[unpack maldetect]", :immediately
		end


		execute "install maldetect" do
		  command "dir=\"`tar -tzf #{Chef::Config[:file_cache_path]}/maldetect-current.tar.gz | head -1`\" ; cd #{Chef::Config[:file_cache_path]}/$dir && ./install.sh && /usr/local/maldetect/maldet --update ; rm -f /etc/cron.daily/maldet"
			returns [0,1]
		  not_if "test -f /usr/local/maldetect/maldet"
		end

		template "/usr/local/sbin/maldet_scanall.sh" do
			source "maldet_scanall.sh.erb"
			mode "0755"
		end

		template "/usr/local/sbin/conf.maldet" do
			source "conf.maldet.erb"
		end

		cron "update maldet" do
			minute "#{Random.rand(0...59)}"
			hour "#{Random.rand(0...23)}"
			command "/usr/local/maldetect/maldet --update; /usr/local/sbin/maldet_scanall.sh"
		end
	end
end