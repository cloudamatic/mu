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

include_recipe 'chef-vault'
packages = %w(libpq-dev sqlite3 libsqlite3-dev libmysqlclient-dev software-properties-common libxml2-dev libxslt-dev libmagickwand-dev make build-essential g++ git)

package packages

apt_repository "brightbox-ruby-ng-#{node['lsb']['codename']}" do
  uri "http://ppa.launchpad.net/brightbox/ruby-ng/ubuntu"
  distribution node['lsb']['codename']
  components ["main"]
  keyserver "keyserver.ubuntu.com"
  key "C3173AA6"
  action :add
  notifies :run, "execute[apt-get update]", :immediately
end

include_recipe 'apt'
include_recipe 'runit'
include_recipe 'nodejs'
include_recipe 'nginx'

service_name = node.normal.service_name
chef_environment = node.chef_environment
application_dir = node[chef_environment][service_name].apps_dir
repo_path = node[chef_environment][service_name].application.rails_repo
version = node[chef_environment][service_name].application.version
application_repo = "https://github.com/#{repo_path}"

# Unicorn config
unicorn_log_dir = '/var/log/unicorn'
unicorn_log = "#{unicorn_log_dir}/unicorn.log"
unicorn_error_log = "#{unicorn_log_dir}/error.log"

# RDS config
db = node.deployment.databases.concerto.first.last
db_name = db.db_name
db_username = db.username
db_host = db.endpoint
db_port = db.port
db_password = chef_vault_item(db.vault_name, db.vault_item)[db.password_field]
node.set['nginx']['default_root'] = "#{application_dir}/"

package %w(ruby2.2 ruby2.2-dev)

gem_package 'bundler' do
  options '--no-ri --no-rdoc'
  gem_binary "/usr/bin/gem"
end

# Need to reload OHAI to ensure the newest ruby is loaded up
ohai "reload" do
  action :reload
end

directory unicorn_log_dir do
  owner 'www-data'
  group 'www-data'
  mode 00555
  action :create
end

file unicorn_log do
  owner 'www-data'
  group 'www-data'
  action :create_if_missing
end

file unicorn_error_log do
  owner 'www-data'
  group 'www-data'
  action :create_if_missing
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

directory application_dir do
  recursive true
  owner 'www-data'
end

git 'checkout application' do
  destination "#{application_dir}/rails"
  user 'www-data'
  group 'www-data'
  repository application_repo
  revision version
end

rails_env = 'development'
database = {
    'adapter' => 'mysql2',
    'encoding' => 'utf8',
    'database' => db_name,
    'username' => db_username,
    'password' => db_password,
    'port' => db_port
}

template 'config/database.yml' do
  source 'database.yml.erb'
  variables ({:database => database, :rails_env => rails_env, :host => db_host})
  path "#{application_dir}/rails/config/database.yml"
end

cookbook_file 'concerto.yml' do
  path "#{application_dir}/rails/config/concerto.yml"
end


#disable concerto_remote_video and concerto_simple_rss
["gem \"concerto_simple_rss\"\n", "gem \"concerto_remote_video\"\n"].each do |f|
  ruby_block 'delete gem plugin concerto_remote_video and concerto_simple_rss' do 
    block do
      file = Chef::Util::FileEdit.new("#{application_dir}/rails/Gemfile-plugins")
      file.search_file_replace(/#{f}/, "")
      file.write_file
    end
    not_if {File.readlines("#{application_dir}/rails/Gemfile-plugins").grep(f).size == 0}
  end
end



template 'Prevent nginx default page conf' do
  source 'nginx.conf.erb'
  path '/etc/nginx/nginx.conf'
end

execute 'bundle install' do
  cwd "#{application_dir}/rails"
  command "#{application_dir}/rails/bin/bundle install --path vendor/bundle"
end

execute 'migrate database' do
  cwd "#{application_dir}/rails"
  command "/usr/local/bin/bundle exec rake db:migrate"
end

execute 'boot Webrick' do
  command "bundle exec rails s -e development -p 9000 -d"
  cwd "#{application_dir}/rails"
end

# Use this technique for end of run notifications
ruby_block "Notify_Users" do
    block do
        puts "\n######################################## End of Run Information ########################################"
        puts "# Your Concerto Server is running at http://#{node['ec2']['public_dns_name']}"
        puts "########################################################################################################\n\n"
    end
    action :create
end

