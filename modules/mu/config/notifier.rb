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
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/notifier.rb
    class Notifier

      # Base configuration schema for a Notifier
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "A stub for inline resource that generate SNS notifications in AWS. This should really be expanded.",
          "properties" => {
            "name" => {
              "type" => "string"
            },
            "region" => MU::Config.region_primitive,
            "credentials" => MU::Config.credentials_primitive,
            "subscriptions" => {
              "type" => "array",
              "description" => "A list of people or resources which should receive notifications",
              "items" => {
                "type" => "object",
                "description" => "A list of people or resources which should receive notifications",
                "properties" => {
                  "endpoint" => {
                    "type" => "string",
                    "description" => "Shorthand for an endpoint which should be subscribed to this notifier, typically an email address or SMS-enabled phone number. For complex cases, such as referencing an AWS Lambda function defined elsewhere in your Mu stack, use +resource+ instead."
                  },
                  "resource" => MU::Config::Ref.schema(desc: "A cloud resource that is a valid notification target for this notifier. For simple use cases, such as external email addresses or SMS, use +endpoint+ instead.")
                }
              }
            }
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::notifiers}, bare and unvalidated.
      # @param notifier [Hash]: The resource to process and validate
      # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(notifier, _configurator)
        ok = true


        if notifier['subscriptions']
          notifier['subscriptions'].each { |sub|
            if !sub['endpoint'] and !sub['resource']
              MU.log "Notifier '#{notifier['name']}' must specify either resource or endpoint in subscription", MU::ERR, details: sub
              ok = false
            end
          }
        end

        ok
      end

    end
  end
end
