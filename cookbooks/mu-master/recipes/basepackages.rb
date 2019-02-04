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

if platform_family?("rhel") 
  basepackages = ["vim-enhanced", "zip", "unzip", "java-1.8.0-openjdk", "libxml2-devel", "libxslt-devel", "cryptsetup-luks", "python-pip", "lsof", "mlocate", "strace", "nmap", "openssl-devel", "readline-devel", "python-devel", "diffutils", "patch", "bind-utils", "httpd-tools", "mailx", "openssl", "libyaml", "graphviz", "ImageMagick-devel", "graphviz-devel", "jq", "vim", "libffi-devel"]

  if node['platform_version'].to_i < 6 or node['platform_version'].to_i >= 8
    raise "Mu Masters on RHEL-family hosts must be equivalent to RHEL6 or RHEL7"

  # RHEL6, CentOS6, Amazon Linux
  elsif node['platform_version'].to_i < 7
    basepackages.concat(["java-1.5.0-gcj", "mysql-server", "autoconf"])
    basepackages << "gecode-devel" if node['platform'] == "amazon"

  # RHEL7, CentOS7
  elsif node['platform_version'].to_i < 8
    basepackages.concat(["gecode-devel", "mariadb", "qt", "qt-x11", "iptables-services"])
  end

else
  raise "Mu Masters are currently only supported on RHEL-family hosts."
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
