#
# Cookbook Name:: demo
# Recipe:: rails
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

include_recipe 'apt'
include_recipe 'ruby_build'
include_recipe 'runit'
include_recipe 'nodejs'
include_recipe 'nginx'

service_name     = node.normal.service_name
chef_environment = node.chef_environment
application_dir  = node[chef_environment][service_name].apps_dir
application_repo = "https://github.com/#{node[chef_environment][service_name].application.rails_repo}"

# Unicorn config
unicorn_log_dir   = '/var/log/unicorn'
unicorn_log       = "#{unicorn_log_dir}/unicorn.log"
unicorn_error_log = "#{unicorn_log_dir}/error.log"

# RDS cofig
db_name     = node.deployment.databases.fss.db_name
db_username = node.deployment.databases.fss.username
db_password = node.deployment.databases.fss.password
db_host     = node.deployment.databases.fss.endpoint
db_port     = node.deployment.databases.fss.port

node.set['nginx']['default_root'] = "#{application_dir}/"

ruby_build_ruby '1.9.3-p547' do
  prefix_path   '/usr/local/'
  environment   'CFLAGS' => '-g -O2'
  action        :install
end

gem_package 'bundler' do
  version    '1.6.2'
  gem_binary '/usr/local/bin/gem'
  options    '--no-ri --no-rdoc'
end

directory unicorn_log_dir do
  owner  'www-data'
  group  'www-data'
  mode   00555
  action :create
end

file unicorn_log do
  owner  'www-data'
  group  'www-data'
  action :create_if_missing
end

file unicorn_error_log do
  owner  'www-data'
  group  'www-data'
  action :create_if_missing
end

package 'libmysqlclient-dev' do
  action :install
end

file '/etc/nginx/sites-available/default' do
  content <<-EOH
    server {
      listen 80;
      server_name flagship_safety;

      location / {
        proxy_pass http://127.0.0.1:9000;
      }
    }
  EOH
end

application 'flagship_safety' do
  action     :deploy
  path       application_dir
  owner      'www-data'
  group      'www-data'
  repository application_repo
  revision   'master'
  migrate    true

  rails do
    gems %w(bundler unicorn)

    database do
      adapter  'mysql2'
      encoding 'utf8'
      database db_name
      username db_username
      password db_password
      host     db_host
      port     db_port
    end
  end

  unicorn do
    port             '127.0.0.1:9000'
    worker_processes 2
    stderr_path      unicorn_error_log
    stdout_path      unicorn_log
    forked_user      'www-data'
    forked_group     'www-data'
  end
end
