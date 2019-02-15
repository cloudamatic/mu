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
    class Endpoint

      # Base configuration schema for an Endpoint (e.g. AWS API Gateway)
      # @return [Hash]
      def self.schema
      {
        "type" => "object",
        "title" => "API Endpoint",
        "description" => "Create a cloud API endpoint, e.g. Amazon API Gateway",
        "required" => ["name", "cloud", "region"],
        "additionalProperties" => false,
        "properties" => {
          "cloud" => MU::Config.cloud_primitive,
          "name" => {"type" => "string"},
          "iam_role" => {"type" => "string"},
          "region" => MU::Config.region_primitive,
          "vpc" => MU::Config::VPC.reference(MU::Config::VPC::NO_SUBNETS, MU::Config::VPC::NO_NAT_OPTS),
          "methods" => {
            "type" => "array",
            "items" => {
              "type" => "object",
              "description" => "Method, as in HTTP method",
              "required" => ["path", "type"],
              "properties" => {
                "path" => {
                  "type" => "string",
                  "description" => "The path underneath our endpoint at this invocation will be triggered",
                  "default" => "/"
                },
                "type" => {
                  "type" => "string",
                  "enum" => ["GET", "POST", "PUT", "HEAD", "DELETE", "CONNECT", "OPTIONS", "TRACE"],
                  "default" => "GET"
                }
              }
            }
          }
        }
      } 
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::endpoints}, bare and unvalidated.
      # @param endpoint [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(endpoint, configurator)
        ok = true

        ok
      end

    end
  end
end
