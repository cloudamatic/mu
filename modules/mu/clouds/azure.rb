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

require 'googleauth'
require "net/http"
require 'net/https'
require 'multi_json'
require 'stringio'

module MU
  class Cloud
    # Support for Google Cloud Platform as a provisioning layer.
    class Azure
      @@authtoken = nil
      @@default_project = nil
      @@myRegion_var = nil
      @@authorizers = {}

      # Any cloud-specific instance methods we require our resource
      # implementations to have, above and beyond the ones specified by
      # {MU::Cloud}
      # @return [Array<Symbol>]
      def self.required_instance_methods
        []
      end

      # If we're running this cloud, return the $MU_CFG blob we'd use to
      # describe this environment as our target one.
      def self.hosted_config
        return nil if !hosted?
        getGoogleMetaData("instance/zone").match(/^projects\/[^\/]+\/zones\/([^\/]+)$/)
        zone = Regexp.last_match[1]
        {
          "project" => MU::Cloud::Google.getGoogleMetaData("project/project-id"),
          "region" => zone.sub(/-[a-z]$/, "")
        }
      end
    end
  end
end
