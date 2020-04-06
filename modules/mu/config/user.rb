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
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/user.rb
    class User

      # Base configuration schema for a User
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "Set up a cloud provider user or machine account",
          "required" => ["name", "type"],
          "properties" => {
            "name" => {
              "type" => "string",
              "description" => "The name of the account to create or associate."
            },
            "type" => {
              "type" => "string",
              "description" => "Indicates whether to create or associate an account meant for interactive human use, or for a machine or service.",
              "enum" => ["interactive", "service"],
              "default" => "interactive"
            },
            "use_if_exists" => {
              "type" => "boolean",
              "description" => "If we attempt to create or associate a user that already exists, simply modify that user in-place and use it, rather than throwing an error. If this flag is set, the user will *not* be deleted on cleanup, nor will we overwrite any existing tags on cloud platforms that support user tagging.",
              "default" => true
            },
            "force_password_change" => {
              "type" => "boolean",
              "description" => "For supported platforms and user types, require the user to reset their password on their next login. Our default behavior is to set this flag when initially creating an account. Setting it explicitly +true+ will set this flag on every subsequent +groom+ of the user, which may not be desired behavior."
            },
            "create_api_key" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Create a set of cloud API keys for this user. Keys will be shared via Scratchpad for one-time retrieval."
            },
            "preserve_on_cleanup" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Leave the user intact during the cleanup process. If we are re-using an existing user, rather than creating one ourselves, this option has no effect- that user will always be left intact."
            },
            "groups" => {
              "type" => "array",
              "description" => "One or more groups to associate with this user.",
              "items" => {
                "type" => "string",
                "description" => "One or more groups to associate with this user. If there is a 'group' resource defined with this name in this Basket of Kittens, we will use that; if not, and if there is an existing cloud provider group in the appropriate account/project that matches, we will use that; if neither of those exists, we will implicitly create a matching group if it had been declared in this Basket of Kittens."
              }
            }
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::user}, bare and unvalidated.
      # @param _user [Hash]: The resource to process and validate
      # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(_user, _configurator)
        ok = true

        ok
      end

    end
  end
end
