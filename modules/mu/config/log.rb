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

module MU
  class Config
    class Log

      def self.schema
        {
          "type" => "object",
          "title" => "Logs",
          "additionalProperties" => false,
          "description" => "Log events using a cloud provider's log service.",
          "properties" => {
            "name" => {
              "type" => "string"
            },
            "cloud" => MU::Config.cloud_primitive,
            "region" => MU::Config.region_primitive,
            "dependencies" => MU::Config.dependencies_primitive,
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::logs}, bare and unvalidated.
      # @param log [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(log, configurator)
        ok = true
        ok
      end

    end
  end
end
