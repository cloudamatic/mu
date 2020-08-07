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
          "required" => ["origins"],
          "properties" => {
            "name" => {
              "type" => "string"
            },
            "dns_records" => MU::Config::DNSZone.records_primitive(need_target: false, default_type: "CNAME", need_zone: true, embedded_type: "cdn"),
            "default_object" => {
              "type" => "string",
              "default" => "index.html"
            },
            "credentials" => MU::Config.credentials_primitive,
            "aliases" => {
              "type" => "array",
              "items" => {
                "type" => "string"
              }
            },
            "origins" => {
              "type" => "array",
              "minItems" => 1,
              "items" => {
                "type" => "object",
                "description" => "One or more back-end sources which this CDN will cache",
                "required" => ["name"],
                "properties" => {
                  "name" => {
                    "type" => "string",
                    "description" => "A unique identifying string which other components of this distribution may use to reference this origin"
                  },
                  "domain_name" => {
                    "type" => "string",
                    "description" => "Domain name of the back-end web server or other resource behind this CDN"
                  },
                  "path" => {
                    "type" => "string",
                    "default" => "",
                    "description" => "Optional path on back-end service to which to map front-end requests"
                  }
                }
              }
            },
            "behaviors" => {
              "type" => "array",
              "items" => {
                "description" => "Customize the behavior of requests sent to one of this CDN's configured +origins+",
                "type" => "object",
                "properties" => {
                  "origin" => {
                    "type" => "string",
                    "description" => "Which of our +origins+ this set of behaviors should map to, by its +name+ field."
                  },
                  "path_pattern" => {
                    "type" => "string",
                    "description" => "The request path or paths for which this behavior should be invoked"
                  }
                }
              }
            }
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
