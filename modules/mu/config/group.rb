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
    # Basket of Kittens config schema and parser logic. See modules/mu/clouds/*/group.rb
    class Group

      # Base configuration schema for a Group
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "Set up a cloud provider group for containing accounts/groups",
          "required" => ["name"],
          "properties" => {
            "name" => {
              "type" => "string"
            },
            "members" => {
              "type" => "array",
              "items" => {
                "type" => "string",
                "description" => "One or more user accounts to add to this group."
              }
            },
            "use_if_exists" => {
              "type" => "boolean",
              "description" => "If we attempt to create or associate a group that already exists, simply group that user in-place and use it, rather than throwing an error. If this flag is set, the group will *not* be deleted on cleanup.",
              "default" => true
            }
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::group}, bare and unvalidated.
      # @param group [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(group, configurator)
        ok = true
        ok
      end

    end
  end
end
