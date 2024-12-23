# Cookbook Name:: mu-master
# Recipe:: basepackages
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

# This recipe is meant to be invoked standalone, by chef-apply. It can safely
# be invoked during a regular chef-client run.
#
# When modifying this recipe, DO NOT ADD EXTERNAL DEPENDENCIES. That means no
# references to other cookbooks, no include_recipes, no cookbook_files, no
# templates.

basepackages = []
removepackages = []
rpms = {}
dpkgs = {}

rhelbase = ["vim-enhanced", "zip", "unzip", "java-1.8.0-openjdk", "libxml2-devel", "libxslt-devel", "cryptsetup-luks", "python-pip", "lsof", "mlocate", "strace", "nmap", "openssl-devel", "readline-devel", "python-devel", "diffutils", "patch", "bind-utils", "httpd-tools", "mailx", "openssl", "libyaml", "graphviz", "ImageMagick-devel", "graphviz-devel", "jq", "vim", "libffi-devel"]
debianbase = [] # Bill is hopeful about the future...

case node['platform_family']
when 'rhel'
  basepackages = rhelbase

  case node['platform_version'].split('.')[0].to_i
  when 6
    basepackages.concat(["java-1.5.0-gcj", "mysql-server", "autoconf"])

  when 7
    basepackages.concat(["gecode-devel", "mariadb", "qt", "qt-x11", "iptables-services"])

  when 8
    raise "Mu currently does not support RHEL 8... but I assume it will in the future... But I am Bill and I am hopeful about the future."
  else
    raise "Mu does not support RHEL #{node['platform_version']}"
  end

when 'amazon'
  basepackages = rhelbase

  case node['platform_version'].split('.')[0].to_i
  when 1, 6
    basepackages.concat(['java-1.5.0-gcj', 'mysql-server', 'autoconf', 'gecode-devel'])

  when 2
    basepackages.concat(["gecode-devel", "mariadb", "qt", "qt-x11", "iptables-services"])

  when 2023
    basepackages.concat(["iptables-services"])
    basepackages.delete("java-1.8.0-openjdk")
    basepackages.delete("cryptsetup-luks")

  else
    raise "Mu does not support Amazon #{node['platform_version']}"
  end

else
  raise "Mu Masters are currently only supported on RHEL and Amazon family hosts."
end

package basepackages
rpms.each_pair { |pkg, src|
  rpm_package pkg do
    source src
  end
}
package removepackages do
  action :remove
end

basepackages = ["git", "curl", "diffutils", "patch", "gcc", "gcc-c++", "make", "postgresql-devel", "libyaml", "libffi-devel", "tcl", "tk"]
