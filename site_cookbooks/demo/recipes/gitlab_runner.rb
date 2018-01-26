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


url = node['gitlab-ci-runner']['repository_url']
base = node['gitlab-ci-runner']['repository_base_url']
package_retries = node['gitlab-ci-runner']['package_retries']

case node['platform_family']
when 'rhel', 'amazon'
  url ||= "#{base}/el/#{node['platform_version'].split('.').first}/$basearch"
  yum_repository 'gitlab-ci-runner' do
    description 'GitLab CI Runner'
    baseurl url
    gpgkey node['gitlab-ci-runner']['gpg_key']
    gpgcheck false
  end
when 'debian'
  %w[apt-transport-https libcurl3-gnutls].each do |pkg|
    package "#{cookbook_name}: install #{pkg}" do
      package_name pkg
      retries package_retries unless package_retries.nil?
    end
  end

  # On the docker image for instance, lsb-release is not installed and thus
  # the ohai attribute is not defined
  package "#{cookbook_name}: install lsb-release" do
    package_name 'lsb-release'
    retries package_retries unless package_retries.nil?
    action :nothing
  end.run_action(:install)

  cmd = Mixlib::ShellOut.new('lsb_release -c -s')
  cmd.run_command
  codename = node['lsb']['codename'] || cmd.stdout.chomp

  url ||= "#{base}/#{node['platform']}"
  apt_repository 'gitlab-ci-runner' do
    uri url
    distribution codename
    components ['main']
    key node['gitlab-ci-runner']['gpg_key']
  end
end

package_retries = node['gitlab-ci-runner']['package_retries']
version = node['gitlab-ci-runner']['version']
package 'gitlab-runner' do
  version version unless version == 'latest'
  retries package_retries unless package_retries.nil?
  action :upgrade if version == 'latest'
end

service 'gitlab-runner' do
	supports status: true, restart: true
	action %i[enable start]
end