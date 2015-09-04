#
# Cookbook Name::ecap-tools
# Recipe:: python_pip
#
# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#         http://egt-labs.com/ecap/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Updates setup_tools and pip by way of pip, which seems to be required before putting pip to any real use
# Requires an initial python and pip installation
# For now, linux only.  Remove case statement if windows turns out to need it

case node[:platform]
  when "windows"
  else
    bash "update-pip" do
      code <<-EOF
#                   easy_install --upgrade setuptools
                    curl https://bootstrap.pypa.io/ez_setup.py | python
                    pip install pip --upgrade
      EOF
    end
end

