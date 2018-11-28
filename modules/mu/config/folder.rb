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
    # Basket of Kittens config schema and parser logic. See modules/mu/clouds/*/folder.rb
    class Folder

      # Base configuration schema for a Folder
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "Set up a cloud provider folder/OU for containing other account-level resources",
          "properties" => {
            "name" => { "type" => "string" },
          }
        }
      end

      # Chunk of schema to reference a folder/OU, here to be embedded
      # into the schemas of other resources.
      def self.reference
        {
          "type" => "object",
          "description" => "Deploy into or connect with resources in a specific account/project",
          "minProperties" => 1,
          "additionalProperties" => false,
          "properties" => {
            "id" => {
              "type" => "string",
              "description" => "Discover this folder/OU by looking by its cloud provider identifier "
            },
            "name" => {
              "type" => "string",
              "description" => "Discover this folder/OU by Mu-internal name; typically the shorthand 'name' field of an Folder object declared elsewhere in the deploy, or in another deploy that's being referenced with 'deploy_id'."
            },
            "cloud" => MU::Config.cloud_primitive,
            "deploy_id" => {
              "type" => "string",
              "description" => "Search for this folder in an existing Mu deploy; specify a Mu deploy id (e.g. DEMO-DEV-2014111400-NG)."
            }
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::folder}, bare and unvalidated.
      # @param folder [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(folder, configurator)
        ok = true
        ok
      end

    end
  end
end
