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
    # Basket of Kittens config schema and parser logic. See modules/mu/clouds/*/project.rb
    class Habitat

      # Base configuration schema for a Habitat
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "Generate a cloud habitat (AWS account, Google Cloud project, Azure Directory, etc)",
          "properties" => {
            "name" => { "type" => "string" },
            "parent" => MU::Config::Folder.reference
          }
        }
      end

      # Chunk of schema to reference an account/project, here to be embedded
      # into the schemas of other resources.
      def self.reference
#        {
#          "type" => "object",
#          "description" => "Deploy into or connect with resources in a specific habitat (AWS account, GCP project, etc)",
#          "minProperties" => 1,
#          "additionalProperties" => false,
#          "properties" => {
#            "id" => {
#              "type" => "string",
#              "description" => "Discover this habitat by looking for this cloud provider identifier, such as 836541910896 (an AWS account number) or my-project-196124 (a Google Cloud project id)"
#            },
#            "name" => {
#              "type" => "string",
#              "description" => "Discover this habitat by Mu-internal name; typically the shorthand 'name' field of a Habitat object declared elsewhere in the deploy, or in another deploy that's being referenced with 'deploy_id'."
#            },
#            "cloud" => MU::Config.cloud_primitive,
#            "deploy_id" => {
#              "type" => "string",
#              "description" => "Search for this Habitat in an existing Mu deploy by Mu deploy id (e.g. DEMO-DEV-2014111400-NG)."
#            }
#          }
#        }
        MU::Config::Ref.schema(type: "habitats")
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::habitat}, bare and unvalidated.
      # @param habitat [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(habitat, configurator)
        ok = true
        ok
      end

    end
  end
end
