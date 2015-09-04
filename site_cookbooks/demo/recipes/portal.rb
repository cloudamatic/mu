#
# Cookbook Name:: demo
# Recipe:: dbservice
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

$service_name = node.normal.service_name

# Bake SSH Keys into instance

#cookbook_file "/root/.ssh/authorized_keys" do
#  source "#{node.chef_environment}/#{$service_name}/authorized_keys"
#  mode 0755
#  owner "root"
#  group "root"
#end

#cookbook_file "/root/.ssh/app-#{$service_name}" do
#  source "#{node.chef_environment}/#{$service_name}/app-#{$service_name}"
#  mode 0755
#  owner "root"
#  group "root"
#end
#
#bash "ssh keys handling" do
#        user "root"
#                code <<-EOH
#                chmod 400 /root/.ssh/app-#{$service_name}
#                eval `ssh-agent -s`
#                ssh-add /root/.ssh/app-#{$service_name}
#
#		 sudo touch /root/.ssh/config
#                chmod 600 /root/.ssh/config
#                echo "StrictHostKeyChecking no" >> /root/.ssh/config
#                echo "IdentityFile /root/.ssh/app-#{$service_name}" >> /root/.ssh/config
#
#                EOH
#end


# Set machine hostname


bash "Pull application repo from github" do
  user "root"
  code <<-EOH
    application_repo=#{node[node.chef_environment][$service_name].application.github_repo}
    application_repo_name=#{node[node.chef_environment][$service_name].application.github_repo_name}

    apps_dir=#{node[node.chef_environment][$service_name].apps_dir}
                
    git clone --recursive git@github.com:$application_repo $apps_dir
  EOH
end

bash "Remove existing httpd conf file" do
  user "root"
  code <<-EOH
    rm -rf /etc/apache2/sites-available/default
  EOH
end

template "/etc/apache2/sites-available/default" do
  source "#{node.chef_environment}/#{$service_name}/httpd.conf.erb"
  mode 0755
  owner "root"
  group "root"
end

bash "Set permissions and start services" do
  user "root"
  code <<-EOH

	apps_dir=#{node[node.chef_environment][$service_name].apps_dir}

	chmod -R 777 $apps_dir

	# Start apache
  sudo service apache2 restart

	# Start at runtime
	#chkconfig --levels 235 httpd on
  EOH
end
