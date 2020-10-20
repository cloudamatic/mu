#
# Cookbook Name::mu-tools
# Recipe::google_api
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

["google-api-client", "googleauth"].each { |gem|
  chef_gem gem do
    compile_time true
    action :install
		only_if { !get_google_metadata("instance/name").nil? }
  end
}

package "nvme-cli" do
  ignore_failure true
end
