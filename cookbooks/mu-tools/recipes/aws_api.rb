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

# well apparently these versions need to be pegged to whatever Chef is using
# internally (as of Chef 17.4.38, aws-sdk-core 3.119)
awsgems = {
#  "aws-sdk-core" => "~> 3.119",
  "aws-sdk-s3" => "1.100.0",
#  "aws-sdk-ec2" => nil
}

awsgems.each_pair { |g, v|
# XXX chef_gem is, inexplicably, failing for these AWS SDK gems; logs indicate
# installation, but they're not actually there. Doing it with an execute seems
# to circumvent the problem. We then use chef_gem to load the stupid thing for
# the current Chef run.
  execute "env -i /opt/chef/embedded/bin/gem install #{g} #{v.nil? ? "" : "--version '#{v}'"}" do
    compile_time true
  end
  chef_gem g do
    gem_binary "/opt/chef/embedded/bin/gem"
    version v if !v.nil?
    compile_time true
   action :install
  end
}

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
