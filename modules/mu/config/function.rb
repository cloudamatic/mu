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
    # Basket of Kittens config schema and parser logic. See modules/mu/clouds/*/function.rb
    class Function

      # Base configuration schema for a Function
      # @return [Hash]
      def self.schema
      {
        "type" => "object",
        "title" => "Function",
        "description" => "Create a cloud function.",
        "required" => ["name", "cloud","runtime","iam_role","handler","code","region"],
        "additionalProperties" => false,
        "properties" => {
          "cloud" => MU::Config.cloud_primitive,
          "name" => {"type" => "string"},
          "runtime" => {"type" => "string"},
          "iam_role" => {"type" => "string"},
          "region" => MU::Config.region_primitive,
          "vpc" => MU::Config::VPC.reference(MU::Config::VPC::ONE_SUBNET+MU::Config::VPC::MANY_SUBNETS, MU::Config::VPC::NO_NAT_OPTS, "all_private"),
          "handler" => {"type" => "string"}, 
          "timeout" => {"type" => "string"},
          "tags" => MU::Config.tags_primitive,
          "memory" => {"type" => "string"},
          "dependencies" => MU::Config.dependencies_primitive,
          "optional_tags" => {
            "type" => "boolean",
            "description" => "Tag the resource with our optional tags (MU-HANDLE, MU-MASTER-NAME, MU-OWNER). Defaults to true"
          },
          "trigger" => {
            "type" => "array",
            "items" => {
              "type" => "object",
              "description" => "Trigger for lambda function",
              "additionalProperties" => false,
              "properties" => {
                "type" => {"type" => "string"},
                "name" => {"type" => "string"}
              }
            }
          },
          "code" => {
            "type" => "array", 
            "items" => { 
              "type" => "object",  
              "description" => "", 
              "additionalProperties" => false, 
              "properties" => {  
                "s3_bucket" => {"type" => "string"}, 
                "s3_key" => {"type" => "string"} 
              }  
            }  
          },
          "environment_variable" => {
            "type" => "array", 
            "minItems" => 1, 
            "items" => { 
              "description" => "environment variables",  
              "type" => "object",  
              "title" => "tags", 
              "required" => ["key", "value"],  
              "additionalProperties" => false, 
              "properties" => {  
                "key" => { 
                  "type" => "string",  
                }, 
                "value" => { 
                  "type" => "string",  
                }  
              }  
            }  
          }
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
