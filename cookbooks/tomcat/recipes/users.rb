#
# Cookbook Name:: tomcat
# Recipe:: users
#
# Author:: Jamie Winsor (<jamie@vialstudios.com>)
#
# Copyright 2010-2012, Chef Software, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

template "#{node['tomcat']['config_dir']}/tomcat-users.xml" do
  source 'tomcat-users.xml.erb'
  owner 'root'
  group 'root'
  mode '0644'
  variables(
    users: TomcatCookbook.users,
    roles: TomcatCookbook.roles
  )
  notifies :restart, "service[#{node['tomcat']['base_instance']}]"
end

if node["tomcat"]["base_version"] == 8
  template "#{node["tomcat"]["config_dir"]}/tomcat-users.xsd" do
    source 'tomcat-users.xsd.erb'
    owner 'root'
    group 'root'
    mode '0644'
    notifies :restart, "service[#{node['tomcat']['base_instance']}]"
  end
end
