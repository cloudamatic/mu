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
# Use awscli to get the secret_key and place it in the default location
# Needs to be run unconditionally in the compile phase to enable later data bag fetches
#
remote_secret = "s3://icras-dev/credentials/icras_encrypted_databag_secret"
local_secret = "/etc/chef/encrypted_data_bag_secret"
get = bash "Get Secret Key" do
  user "root"
  action :nothing
  code <<-EOH
        aws s3 cp #{remote_secret} #{local_secret}
  EOH
  not_if { ::File.exists?("#{local_secret}") }
end

get.run_action (:run)
