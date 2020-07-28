# Copyright:: Copyright (c) 2020 eGlobalTech, Inc., all rights reserved
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
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/job.rb
    class CDN

      # Base configuration schema for a scheduled job
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "A cloud provider-specific facility for triggered or scheduled tasks, such as AWS CloudWatch Events or Google Cloud Scheduler.",
          "properties" => {
            "name" => {
              "type" => "string"
            },
            "credentials" => MU::Config.credentials_primitive
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::jobs}, bare and unvalidated.
      # @param _job [Hash]: The resource to process and validate
      # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(_job, _configurator)
        ok = true

        ok
      end

    end
  end
end
