#
# Cookbook Name::mu-tools
# Recipe::aws_api
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

chef_gem "aws-sdk" do
  compile_time true
  version "3.0.1"
  action :install
end

if platform_family?("rhel") or platform_family?("amazon")
  if node['platform_version'].to_i == 6
    package "python34-pip"
    execute "/usr/bin/pip3 install awscli" do
      not_if "test -x /usr/bin/aws"
    end
  end
end

if node['platform_version'].to_i > 6
  package "nvme-cli" do
    ignore_failure true
  end
end
