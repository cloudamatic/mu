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
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/alarm.rb
    class Alarm

      # Sections of Alarm schema shared between Alarms as a first-class
      # resource and as inline declarations in other resources.
      # @return [Hash]
      def self.common_properties
        {
          "name" => {
            "type" => "string"
          },
          "ok_actions" => {
            "type" => "array",
            "minItems" => 1,
            "description" => "What actions to take when alarm state transitions to 'OK'.",
            "items" => {
                "type" => "String"
            }
          },
          "alarm_actions" => {
            "type" => "array",
            "minItems" => 1,
            "description" => "What actions to take when alarm state transitions to 'ALARM'.",
            "items" => {
                "type" => "String"
            }
          },
          "no_data_actions" => {
            "type" => "array",
            "minItems" => 1,
            "description" => "What actions to take when alarm state transitions to 'INSUFFICIENT'.",
            "items" => {
                "type" => "String"
            }
          },
          "metric_name" => {
            "type" => "string",
            "description" => "The name of the attribute to monitor eg. CPUUtilization."
          },
          "namespace" => {
            "type" => "string",
            "description" => "The name of container 'metric_name' belongs to eg. 'AWS/EC2'"
          },
          "statistic" => {
            "type" => "string",
            "description" => "",
            "enum" => ["SampleCount", "Average", "Sum", "Minimum", "Maximum"]
          },
          "dimensions" => {
            "type" => "array",
            "description" => "What to monitor",
            "items" => {
                "type" => "object",
                "additionalProperties" => false,
                "required" => ["cloud_class"],
                "description" => "What to monitor",
                "properties" => {
                    "cloud_class" => {
                        "type" => "string",
                        "description" => "The type of resource we're checking",
                        "enum" => ["InstanceId", "server", "Server", "DBInstanceIdentifier", "database", "Database", "LoadBalancerName", "loadbalancer", "LoadBalancer", "CacheClusterId", "cache_cluster", "CacheCluster", "VolumeId", "volume", "Volume", "BucketName", "bucket", "Bucket", "TopicName", "notification", "Notification", "AutoScalingGroupName", "server_pool", "ServerPool"]
                    },
                    "cloud_id" => {
                        "type" => "string",
                        "description" => "The cloud identifier of the resource the alarm is being created for. eg - i-d96eca0d. Must use either 'cloud_id' OR 'mu_name' AND 'deploy_id'"
                    },
                    "mu_name" => {
                        "type" => "string",
                        "description" => "The full name of a resource in a foreign deployment which we should monitor. You should also include 'deploy_id' so we will be able to identifiy a single resource. Use either 'cloud_id' OR 'mu_name' and 'deploy_id'"
                    },
                    "deploy_id" => {
                        "type" => "string",
                        "description" => "Should be used with 'mu_name' to identifiy a single resource."
                    },
                    "name" => {
                        "type" => "string",
                        "description" => "The name of another resource in this stack with which to associate this alarm."
                    }
                }
            }  
          },
          "period" => {
            "type" => "integer",
            "description" => "The time, in seconds the 'statistic' is checked/tested. Must be multiples of 60"
          },
          "unit" => {
            "type" => "string",
            "description" => "Associated with the 'metric'",
            "enum" => ["Seconds", "Microseconds", "Milliseconds", "Bytes", "Kilobytes", "Megabytes", "Gigabytes", "Terabytes", "Bits", "Kilobits", "Megabits", "Gigabits", "Terabits", "Percent", "Count", "Bytes/Second", 
                                "Kilobytes/Second", "Megabytes/Second", "Gigabytes/Second", "Terabytes/Second", "Bits/Second", "Kilobits/Second", "Megabits/Second", "Gigabits/Second", "Terabits/Second", "Count/Second", "nil"]
          },
          "evaluation_periods" => {
            "type" => "integer",
            "description" => "The number of times to repeat the 'period' before changing the state of an alarm. eg form 'OK' to 'ALARM' state"
          },
          "threshold" => {
        # TO DO: This should be a float
            "type" => "integer",
            "description" => "The value the 'statistic' is compared to and action (eg 'alarm_actions') will be invoked "
          },
          "comparison_operator" => {
            "type" => "string",
            "description" => "The arithmetic operation to use when comparing 'statistic' and 'threshold'. The 'statistic' value is used as the first operand",
            "enum" => ["GreaterThanOrEqualToThreshold", "GreaterThanThreshold", "LessThanThreshold", "LessThanOrEqualToThreshold"]
          },
        # TO DO: Separate all of these to an SNS primitive
          "enable_notifications" => {
            "type" => "boolean",
            "description" => "Rather to send notifications when the alarm state changes"
          },
          "notification_group" => {
            "type" => "string",
            "description" => "The name of the notification group. Will be created if it doesn't exist. We use / create a default one if not specified. NOTE: because we can't confirm subscription to a group programmatically, you should use an existing group",
            "default" => "mu-default"
          },
          "notification_type" => {
            "type" => "string",
            "description" => "What type of notification endpoint will the notification be sent to. defaults to 'email'",
            "enum" => ["http", "https", "email", "email-json", "sms", "sqs", "application"],
            "default" => "email"
          },
          "notification_endpoint" => {
            "type" => "string",
            "description" => "The endpoint the notification will be sent to. eg. if notification_type is 'email'/'email-json' the endpoint will be the email address. A confirmation email will be sent to this email address if a new notification_group is created, if not specified and notification_type is set to 'email' we will use the mu-master email address",
            "default_if" => [
                {
                    "key_is" => "notification_type",
                    "value_is" => "email",
                    "set" => MU::Config.notification_email
                },
                {
                    "key_is" => "notification_type",
                    "value_is" => "email-json",
                    "set" => MU::Config.notification_email
                }
            ]
          }
        }
      end

      # Base configuration schema for a Alarm
      # @return [Hash]
      def self.schema
        base = {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "Cloud platform monitoring alarms",
          "properties" => {
          }
        }
        base["properties"].merge!(common_properties)
        base
      end

      # Most Alarm objects aren't actually declared as first-class resources,
      # but instead inline on other objects. Schema is slightly different.
      def self.inline
        {
          "type" => "array",
          "minItems" => 1,
          "items" => {
            "description" => "Create a CloudWatch Alarm.",
            "type" => "object",
            "title" => "CloudWatch Alarm Parameters",
            "required" => ["name", "metric_name", "statistic", "period", "evaluation_periods", "threshold", "comparison_operator"],
            "additionalProperties" => false,
            "properties" => common_properties
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::alarms}, bare and unvalidated.
      # @param alarm [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(alarm, configurator)
        ok = true

        if alarm["namespace"].nil?
          MU.log "You must specify 'namespace' when creating an alarm", MU::ERR
          ok = false
        end

        if alarm["metric_name"].nil?
          MU.log "You must specify 'metric_name' when creating an alarm", MU::ERR
          ok = false
        end

        if alarm["statistic"].nil?
          MU.log "You must specify 'statistic' when creating an alarm", MU::ERR
          ok = false
        end

        if alarm["period"].nil?
          MU.log "You must specify 'period' when creating an alarm", MU::ERR
          ok = false
        end

        if alarm["evaluation_periods"].nil?
          MU.log "You must specify 'evaluation_periods' when creating an alarm", MU::ERR
          ok = false
        end

        if alarm["threshold"].nil?
          MU.log "You must specify 'threshold' when creating an alarm", MU::ERR
          ok = false
        end

        if alarm["comparison_operator"].nil?
          MU.log "You must specify 'comparison_operator' when creating an alarm", MU::ERR
          ok = false
        end

        if alarm["enable_notifications"]
          if alarm["comparison_operator"].nil?
            MU.log "You must specify 'comparison_operator' when creating an alarm", MU::ERR
            ok = false
          end

          if alarm["notification_group"].nil?
            MU.log "You must specify 'notification_group' when 'enable_notifications' is set to true", MU::ERR
            ok = false
          end

          if alarm["notification_type"].nil?
            MU.log "You must specify 'notification_type' when 'enable_notifications' is set to true", MU::ERR
            ok = false
          end

          #if alarm["notification_endpoint"].nil?
          #  MU.log "You must specify 'notification_endpoint' when 'enable_notifications' is set to true", MU::ERR
          #  ok = false
          #end
        end
        alarm["notification_endpoint"] ||= MU.muCfg['mu_admin_email']
        
        if alarm["dimensions"]
          alarm["dimensions"].each{ |dimension|
            if dimension["mu_name"] && dimension["cloud_id"]
              MU.log "You can only specfiy 'mu_name' or 'cloud_id'", MU::ERR
              ok = false
            end

            if dimension["cloud_class"].nil?
              ok = false
              MU.log "You must specify 'cloud_class'", MU::ERR
            end
          }
        end

        if alarm["enable_notifications"]
          if !alarm["notification_group"].match(/^arn:/i)
            if !configurator.haveLitterMate?(alarm["notification_group"], "notifiers")
              notifier = {
                "name" => alarm["notification_group"],
                "region" => alarm["region"],
                "cloud" => alarm["cloud"],
                "credentials" => alarm["credentials"],
                "subscriptions" => [
                  {
                    "endpoint" => alarm["notification_endpoint"],
                    "type" => alarm["notification_type"],
                  }
                ]
              }
              ok = false if !configurator.insertKitten(notifier, "notifiers")
            end
            alarm["dependencies"] ||= []
            alarm["dependencies"] << {
              "name" => alarm["notification_group"],
              "type" => "notifier"
            }
          end
        end

        ok
      end

    end
  end
end
