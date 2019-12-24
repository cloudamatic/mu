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
        MU::Config::Ref.schema(type: "habitats", omit_fields: ["region", "tag"])
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
