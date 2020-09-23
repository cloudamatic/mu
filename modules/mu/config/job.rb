# Copyright:: Copyright (c) 2020 eGlobalTech, Inc., all rights reserved
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
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/job.rb
    class Job

      # Base configuration schema for a scheduled job
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "A cloud provider-specific facility for triggered or scheduled tasks, such as AWS CloudWatch Events or Google Cloud Scheduler.",
          "properties" => {
            "name" => {
              "type" => "string"
            },
            "region" => MU::Config.region_primitive,
            "credentials" => MU::Config.credentials_primitive,
            "description" => {
              "type" => "string",
              "description" => "Human-readable description field for this job (this will field be overriden with the Mu deploy id on most providers unless +scrub_mu_isms+ is set)"
            },
            "schedule" => {
              "type" => "object",
              "description" => "A schedule on which to invoke this task, typically unix crontab style.",
              "properties" => {
                "minute" => {
                  "type" => "string",
                  "description" => "The minute of the hour at which to invoke this job, typically an integer between 0 and 59. This will be validated by the cloud provider, where other more human-readable values may be supported.",
                  "default" => "0"
                },
                "hour" => {
                  "type" => "string",
                  "description" => "The hour at which to invoke this job, typically an integer between 0 and 23. This will be validated by the cloud provider, where other more human-readable values may be supported.",
                  "default" => "*"
                },
                "day_of_month" => {
                  "type" => "string",
                  "description" => "The day of the month which to invoke this job, typically an integer between 1 and 31. This will be validated by the cloud provider, where other more human-readable values may be supported.",
                  "default" => "*"
                },
                "month" => {
                  "type" => "string",
                  "description" => "The month in which to invoke this job, typically an integer between 1 and 12. This will be validated by the cloud provider, where other more human-readable values may be supported.",
                  "default" => "*"
                },
                "day_of_week" => {
                  "type" => "string",
                  "description" => "The day of the week on which to invoke this job, typically an integer between 0 and 6. This will be validated by the cloud provider, where other more human-readable values may be supported.",
                  "default" => "*"
                },
                "year" => {
                  "type" => "string",
                  "description" => "The year in which to invoke this job. Not honored by all cloud providers.",
                  "default" => "*"
                }
              }
            }
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::jobs}, bare and unvalidated.
      # @param _job [Hash]: The resource to process and validate
      # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(_job, _configurator)
        ok = true

        ok
      end

    end
  end
end
