#
# Cookbook Name::mu-tools
# Recipe::configure_oracle_tools
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
# Installs the oracle instantclient, sqlplus and the dev tools, then sets up environment for access
#
# USAGE: Must define location of packages in the node, typically via environment, EXAMPLE ONLY:
#                 "oracle-instantclient":{
#                        "public-url":"https://s3.amazonaws.com/flra-cms-dev/packages/",
#                        "sqlplus-rpm":"oracle-instantclient12.1-sqlplus-12.1.0.1.0-1.x86_64.rpm",
#                        "devel-rpm":"oracle-instantclient12.1-devel-12.1.0.1.0-1.x86_64.rpm",
#                       "basic-rpm":"oracle-instantclient12.1-basic-12.1.0.1.0-1.x86_64.rpm"
#                },
#                "oracle-jdbc":{
#                       "public-url":"https://s3.amazonaws.com/flra-cms-dev/packages/",
#                       "oracle-jdbc-jar" : "ojdbc7.jar",
#                       "jar-home" : "/usr/local/lib/jvm/"
#                }
#
# TODO: Make the versions attribute-driven
#               The package relies upon the packages being accessible via https, which requires public access.
#               Eliminate this by either an s3 copy possibility or creating an rpm repository
#
# Maintained by: robert.patt-corner@eglobaltech.com
#
case node['platform']

  when "centos"
    # Install sqlplus and the oracle development sdk, then set the oracle environment up
    include_recipe "oracle-instantclient::sqlplus"
    include_recipe "oracle-instantclient::devel"

    # Add a pull and setup for JDBC if driven by node
    uses_jdbc = node['oracle-jdbc']
    unless uses_jdbc.nil?
      directory node['oracle-jdbc']['jar-home'] do
        owner "root"
        group "root"
        mode 0755
        action :create
      end

      remote_file File.join(node['oracle-jdbc']['jar-home'], node['oracle-jdbc']['oracle-jdbc-jar']) do
        source node['oracle-jdbc']['public-url'] + node['oracle-jdbc']['oracle-jdbc-jar']
        action :create
      end


    end

    # Set up the configuration so oracle is in the path
    file "/etc/ld.so.conf.d/oracle.conf" do
      content "/usr/lib/oracle/12.1/client64/lib\n"
      mode 0644
      owner "root"
      group "root"
      notifies :run, "execute[/sbin/ldconfig]", :immediately
    end

    execute "/sbin/ldconfig" do
      action :nothing
    end

  else
    Chef::Log.info("Unsupported platform #{node['platform']}")

end
