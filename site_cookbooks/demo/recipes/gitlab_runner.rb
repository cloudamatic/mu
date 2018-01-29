#
# Cookbook Name:: demo
# Recipe:: gitlab
#
# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
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


case node['platform_family']
when 'rhel', 'amazon'
  #scriptURL = "#{node['gitlab-ci-runner']['repository_base_url']}" + "#{node['gitlab-ci-runner']['rpmScript']}"
  scriptURL = 'https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.rpm.sh'
when 'debian'
  #scriptURL = "#{node['gitlab-ci-runner']['repository_base_url']}" + "#{node['gitlab-ci-runner']['debScript']}"
  scriptURL = 'https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh'
end



execute 'Configure Repositories' do
  command "curl -L #{scriptURL} | sudo bash"
end

package 'gitlab-runner' do
  action :install
end

service 'gitlab-runner' do
  action [:enable, :start]
end

execute 'Register Runner' do
  command "gitlab-runner register -n -u 'http://ec2-34-225-243-242.compute-1.amazonaws.com/' -r 'DNchSDLqCp_rzkkUWPvh' --executor docker --docker-image ubuntu --locked false --tag-list 'hello, goodbye, demo, #{node['platform_family']}, docker'"
  notifies :restart, "service[gitlab-runner]", :delayed
end

docker_service 'default' do
  action [:create, :start]
end