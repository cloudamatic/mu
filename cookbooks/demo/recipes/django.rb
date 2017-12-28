#
# Cookbook Name:: demo
# Recipe:: django
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

include_recipe 'git'
include_recipe 'nginx'

service_name = node.normal.service_name
Chef::Log.info "apps_dis should be at: node[#{node.chef_environment}][#{service_name}].apps_dir"
application_dir = node[node.chef_environment][service_name].apps_dir
application_repo = "https://github.com/#{node[node.chef_environment][service_name].application.django_repo}"
gunicorn_config = '/etc/gunicorn/demo.py'
gunicorn_log_dir = '/var/log/gunicorn'
gunicorn_access_log = "#{gunicorn_log_dir}/access.log"

node.set['nginx']['default_root'] = "#{application_dir}/current"

application 'demo' do
  action :deploy
  path application_dir
  owner 'www-data'
  group 'www-data'
  repository application_repo
  revision 'master'
  migrate false

  django do
    requirements 'requirements.txt'
  end
end

directory gunicorn_log_dir do
  owner "root"
  group "root"
  mode 00755
  action :create
end

file gunicorn_access_log do
  action :create_if_missing
end

gunicorn_config gunicorn_config do
  pid '/run/gunicorn.sock'
  owner 'www-data'
  group 'www-data'
  listen '127.0.0.1:9000'
  action :create
  accesslog gunicorn_access_log
end

file '/etc/nginx/sites-available/default' do
  content <<-EOH
    server {
      listen 80;
      server_name demo;

      location / {
        proxy_pass http://127.0.0.1:9000;
      }
    }
  EOH
end

bash "boot_gunicorn" do
  cwd "#{application_dir}/current"
  code <<-EOH
#{application_dir}/shared/env/bin/gunicorn -D -c /etc/gunicorn/demo.py demo.wsgi:application
  EOH
end
