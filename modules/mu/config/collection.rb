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
    class Collection

      def self.schema
        {
          "type" => "object",
          "title" => "cloudformation",
          "required" => ["name"],
          "additionalProperties" => false,
          "description" => "Create an Amazon CloudFormation stack.",
          "properties" => {
            "name" => {"type" => "string"},
            "cloud" => MU::Config.cloud_primitive,
            "tags" => MU::Config.tags_primitive,
            "dependencies" => MU::Config.dependencies_primitive,
            "parameters" => {
                "type" => "array",
                "items" => {
                    "type" => "object",
                    "description" => "set cloudformation template parameter",
                    "required" => ["parameter_key", "parameter_value"],
                    "additionalProperties" => false,
                    "properties" => {
                        "parameter_key" => {"type" => "string"},
                        "parameter_value" => {"type" => "string"}
                    }
                }
            },
            "pass_deploy_key_as" => {
                "type" => "string",
                "description" => "Pass in the deploy key for this stack as a CloudFormation parameter. Set this to the CloudFormation parameter name.",
            },
            "pass_parent_parameters" => {
              "type" => "boolean",
              "default" => true,
              "description" => "If targeting CloudFormation, this will pass all of the parent template's parameters to the nested template"
            },
            "on_failure" => {
                "type" => "string",
                "enum" => ["DO_NOTHING", "ROLLBACK", "DELETE"],
                "default" => "ROLLBACK"
            },
            "template_file" => {"type" => "string"},
            "timeout" => {
              "type" => "string",
              "description" => "Timeout (in minutes) for building this Collection.",
              "default" => "45"
            },
            "template_url" => {
                "type" => "string",
                "pattern" => "^#{URI::regexp(%w(http https))}$"
            },
            "creation_style" => {
                "type" => "string",
                "enum" => ["existing", "new"]
            }
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::collections}, bare and unvalidated.
      # @param stack [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(stack, configurator)
        ok = true
        ok
      end

    end
  end
end
