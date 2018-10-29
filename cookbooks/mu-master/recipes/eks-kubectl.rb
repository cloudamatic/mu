# Cookbook Name:: mu-master
# Recipe:: eks-kubectl
#
# Copyright:: Copyright (c) 2018 eGlobalTech, Inc., all rights reserved
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
#
remote_file "/opt/mu/bin/kubectl" do
  source "https://amazon-eks.s3-us-west-2.amazonaws.com/1.10.3/2018-07-26/bin/linux/amd64/kubectl"
  mode 0755
  not_if "test -f /opt/mu/bin/kubectl"
end

remote_file "/opt/mu/bin/aws-iam-authenticator" do
  source "https://amazon-eks.s3-us-west-2.amazonaws.com/1.10.3/2018-07-26/bin/linux/amd64/aws-iam-authenticator"
  mode 0755
  not_if "test -f /opt/mu/bin/aws-iam-authenticator"
end

# in brand new accounts where no load balancer has been created, something
# has to do this before EKS has to, because by default it can't
execute "aws iam create-service-linked-role --aws-service-name 'elasticloadbalancing.amazonaws.com'" do
  not_if "aws iam list-roles | grep /aws-service-role/elasticloadbalancing.amazonaws.com/"
end
