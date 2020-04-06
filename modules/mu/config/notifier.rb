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
                "required" => ["endpoint"],
                "properties" => {
                  "endpoint" => {
                    "type" => "string",
                    "description" => "The endpoint which should be subscribed to this notifier, typically an email address or SMS-enabled phone number."
                  }
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
            if !sub["type"]
              if sub["endpoint"].match(/^http:/i)
                sub["type"] = "http"
              elsif sub["endpoint"].match(/^https:/i)
                sub["type"] = "https"
              elsif sub["endpoint"].match(/^sqs:/i)
                sub["type"] = "sqs"
              elsif sub["endpoint"].match(/^\+?[\d\-]+$/)
                sub["type"] = "sms"
              elsif sub["endpoint"].match(/\A[\w+\-.]+@[a-z\d\-]+(\.[a-z]+)*\.[a-z]+\z/i)
                sub["type"] = "email"
              else
                MU.log "Notifier #{notifier['name']} subscription #{sub['endpoint']} did not specify a type, and I'm unable to guess one", MU::ERR
                ok = false
              end
            end
          }
        end

        ok
      end

    end
  end
end
