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
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/function.rb
    class Function

      # Base configuration schema for a Function
      # @return [Hash]
      def self.schema
      {
        "type" => "object",
        "title" => "Function",
        "description" => "Create a cloud function.",
        "required" => ["name", "cloud","runtime","handler","code","region"],
        "additionalProperties" => false,
        "properties" => {
          "cloud" => MU::Config.cloud_primitive,
          "name" => {"type" => "string"},
          "region" => MU::Config.region_primitive,
          "vpc" => MU::Config::VPC.reference(MU::Config::VPC::ONE_SUBNET+MU::Config::VPC::MANY_SUBNETS, MU::Config::VPC::NO_NAT_OPTS, "all_private"),
          "triggers" => {
            "type" => "array",
            "items" => {
              "type" => "object",
              "description" => "Triggers which will cause this function to be invoked."
            }
          },
          "loadbalancers" => {
            "type" => "array",
            "minItems" => 1,
            "items" => MU::Config::LoadBalancer.reference
          },
          "handler" => {
            "type" => "string",
            "description" => "The function within your code that is should be called to begin execution. For Node.js, it is the module-name.export value in your function. For Java, it can be package.class-name::handler or package.class-name. For more information, see https://docs.aws.amazon.com/lambda/latest/dg/java-programming-model-handler-types.html"
          }, 
          "timeout" => {
            "type" => "integer",
            "description" => "Maximum run time for an invocation of this function, in seconds",
            "default" => 3
          },
          "tags" => MU::Config.tags_primitive,
          "optional_tags" => MU::Config.optional_tags_primitive,
          "add_firewall_rules" => {
            "type" => "array",
            "items" => MU::Config::FirewallRule.reference,
          },
          "ingress_rules" => {
            "type" => "array",
            "description" => "Firewall rules to apply to our function. Ignored if not applicable to target environment.",
            "items" => MU::Config::FirewallRule.ruleschema
          },
          "memory" => {
            "type" => "integer",
            "default" => 128,
            "description" => "Memory to allocation for function, in MB. The value must be a multiple of 64 MB."
          },
          "dependencies" => MU::Config.dependencies_primitive,
          "code" => {
            "type" => "object",  
            "description" => "Zipped deployment package to upload to our function.", 
            "properties" => {  
              "zip_file" => {
                "type" => "string",
                "description" => "Path to a zipped deployment package to upload."
              }, 
              "path" => {
                "type" => "string",
                "description" => "Path to a directory that can be zipped into deployment package to upload."
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
      # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(function, _configurator)
        ok = true
        if !function['code']
          ok = false
        end

        if function['code']
          ['zip_file', 'path'].each { |src|
            if function['code'][src]
              if !File.readable?(function['code'][src]) and !Dir.exist?(function['code'][src])
                MU.log "Function '#{function['name']}' specifies a deployment package that I can't read at #{function['code'][src]}", MU::ERR
                ok = false
              else
                function['code'][src] = File.realpath(File.expand_path(function['code'][src]))
              end
            end
          }
        end

        ok
      end

    end
  end
end
