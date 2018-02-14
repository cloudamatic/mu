#
# Cookbook Name:: demo
# Recipe:: flask
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

include_recipe 'poise-python'
include_recipe 'nginx'

service_name = node.normal.service_name;
application_dir = node[node.chef_environment]['flask']['apps_dir']
virtual_environment = "#{application_dir}/envs/demo"

directories = virtual_environment.split('/')
(0..directories.size).each do |i|
  directory = directories.slice(0..i).join '/'

  next if directory.empty?

  directory directory do
    owner 'root'
    group 'root'
    mode 00644
    action :create
  end
end

python_virtualenv virtual_environment do
  user 'root'
  group 'root'
  action :create
end

python_package 'flask' do
  virtualenv virtual_environment
  action :install
end

python_package 'gunicorn' do
  virtualenv virtual_environment
  action :install
end

file "#{virtual_environment}/demo.py" do
  content <<-EOH
from flask import Flask
app = Flask(__name__)
@app.route("/")
def hello():
    return "Hello World!"
if __name__ == "__main__":
    app.run()
  EOH
end

user 'www-data'


gunicorn_config '/etc/gunicorn/demo.py' do
  owner 'www-data'
  group 'www-data'
  listen '127.0.0.1:9000'
  action :create
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

ruby_block 'Add LD_LIBRARY_PATH' do
  block do
    find='/opt/rh/python27/root/usr/lib64/'
    file=Chef::Util::FileEdit.new("/etc/ld.so.conf")
    file.insert_line_if_no_match(find,find)
    file.write_file
  end
  not_if  {File.readlines("/etc/ld.so.conf").grep(/find/).size > 0}
  notifies :run, "execute[run ldconfig]", :immediately
end

execute "run ldconfig" do
  user 'root'
  command "ldconfig"
  action :nothing
end


bash "boot_gunicorn" do
  user 'root'
  cwd virtual_environment
  code <<-EOH
    ./bin/gunicorn -D -c /etc/gunicorn/demo.py demo:app
  EOH
end
