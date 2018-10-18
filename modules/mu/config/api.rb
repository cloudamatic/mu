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
    # Basket of Kittens config schema and parser logic. See modules/mu/clouds/*/api.rb
    class Api

      # Base configuration schema for a API
      # @return [Hash]
      def self.schema
      {
        "type" => "object",
        "title" => "API Endpoint",
        "description" => "Create a cloud API endpoint.",
        "required" => ["name", "cloud", "region"],
        "additionalProperties" => false,
        "properties" => {
          "cloud" => MU::Config.cloud_primitive,
          "name" => {"type" => "string"},
          "iam_role" => {"type" => "string"},
          "region" => MU::Config.region_primitive,
        }
      } 
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::functions}, bare and unvalidated.
      # @param function [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(function, configurator)
        ok = true

        ok
      end

    end
  end
end
