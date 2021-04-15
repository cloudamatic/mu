# Copyright:: Copyright (c) 2018 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the folder or at
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
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/role.rb
    class Role

      # Base configuration schema for a Group
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "Set up a cloud provider role for mapping permissions to other entities",
          "properties" => {
            "name" => {
              "type" => "string",
              "description" => "The name of a cloud provider role to create",
              "pattern" => '^[a-zA-Z0-9_\-\.]+$'
            },
            "import" => {
              "type" => "array",
              "items" => {
                "type" => "string",
                "description" => "Import pre-fabricated roles/policies from the cloud provider into this role."
              }
            },
            "policies" => {
              "type" => "array",
              "items" => self.policy_primitive
            }
          }
        }
      end

      # Chunk of schema to reference an account/project, here to be embedded
      # into the schemas of other resources.
      def self.reference
        MU::Config::Ref.schema(type: "roles")
      end

      # A generic, cloud-neutral descriptor for a policy that grants or denies
      # permissions to some entity over some other entity.
      # @param subobjects [Boolean]: Whether the returned schema should include a +path+ parameter
      # @param grant_to [Boolean]: Whether the returned schema should include an explicit +grant_to+ parameter
      # @return [Hash]
      def self.policy_primitive(subobjects: false, grant_to: false, permissions_optional: false, targets_optional: false)
        cfg = {
          "type" => "object",
          "description" => "Policies which grant or deny permissions.",
          "required" => ["name"],
#          "additionalProperties" => false,
          "properties" => {
            "name" => {
              "type" => "string",
              "description" => "A unique name for this policy"
            },
            "flag" => {
              "type" => "string",
              "enum" => ["allow", "deny"],
              "default" => "allow"
            },
            "permissions" => {
              "type" => "array",
              "items" => {
                "type" => "string",
                "description" => "Permissions to grant or deny. Valid permission strings are cloud-specific."
              }
            },
            "targets" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "description" => "Entities to which this policy will grant or deny access.",
                "required" => ["identifier"],
                "additionalProperties" => false,
                "properties" => {
                  "type" => {
                    "type" => "string",
                    "description" => "A Mu resource type, used when referencing a sibling Mu resource in this stack with +identifier+.",
                    "enum" => MU::Cloud.resource_types.values.map { |t| t[:cfg_name] }.sort
                  },
                  "identifier" => {
                    "type" => "string",
                    "description" => "Either the name of a sibling Mu resource in this stack (used in conjunction with +entity_type+), or the full cloud identifier for a resource, such as an ARN in Amazon Web Services."
                  },
                  "path" => {
                    "type" => "string",
                  }
                }
              }
            }
          }
        }

        cfg["required"] << "permissions" if !permissions_optional
        cfg["required"] << "targets" if !targets_optional

        schema_aliases = [
          { "identifier" => "id" },
        ]

        if grant_to
          cfg["properties"]["grant_to"] = {
            "type" => "array",
            "default" => [ { "identifier" => "*" } ],
            "items" => MU::Config::Ref.schema(schema_aliases, desc: "Entities to which this policy will grant or deny access.")
          }
        end

        if subobjects
          cfg["properties"]["targets"]["items"]["properties"]["path"] = {
            "type" => "string",
            "description" => "Target this policy to a path or child resource of the object to which we are granting or denying permissions, such as a key or wildcard in an S3 or Cloud Storage bucket."
          }
        end

        cfg
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::role}, bare and unvalidated.
      # @param _role [Hash]: The resource to process and validate
      # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(_role, _configurator)
        ok = true
        ok
      end

    end
  end
end
