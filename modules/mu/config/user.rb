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
    # Basket of Kittens config schema and parser logic. See modules/mu/clouds/*/user.rb
    class User

      # Base configuration schema for a User
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "Set up a cloud provider user or machine account",
          "properties" => {
            "name" => {
              "type" => "string",
              "description" => "The name of the account to create or associate."
            },
            "use_if_exists" => {
              "type" => "boolean",
              "description" => "If we attempt to create or associate a user that already exists, simply modify that user in-place and use it, rather than throwing an error. If this flag is set, the user will *not* be deleted on cleanup, nor will we overwrite any existing tags on cloud platforms that support user tagging.",
              "default" => true
            },
            "groups" => {
              "type" => "array",
              "description" => "One or more groups to associate with this user.",
              "items" => {
                "type" => "string",
                "description" => "Name of a group of which this user should be a member. If there is a 'group' resource defined with this name in this Basket of Kittens, we will use that; if not, and if there is an existing cloud provider group in the appropriate account/project that matches, we will use that; if neither of those exists, we will implicitly create a matching group if it had been declared in this Basket of Kittens."
              }
            }
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::user}, bare and unvalidated.
      # @param user [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(user, configurator)
        ok = true
        ok
      end

    end
  end
end
