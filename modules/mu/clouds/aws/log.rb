# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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
  class Cloud
    class AWS
      # A logging facility as configured in {MU::Config::BasketofKittens::logs}
      class Log < MU::Cloud::Log
        @deploy = nil
        @config = nil

        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::logs}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          @config["log_group_name"] = @mu_name
          @config["log_stream_name"] =
            if @config["enable_cloudtrail_logging"]
              "#{MU::Cloud::AWS.credToAcct(@config['credentials'])}_CloudTrail_#{@config["region"]}"
            else
              @mu_name
            end

          tags = MU::MommaCat.listStandardTags
          if @config['optional_tags']
            MU::MommaCat.listOptionalTags.each_pair { |name, value|
              tags[name] = value
            }
          end
          if @config['tags']
            @config['tags'].each { |tag|
              tags[tag['key']] = tag['value']
            }
          end

          MU.log "Creating log group #{@mu_name}"
          MU::Cloud::AWS.cloudwatchlogs(region: @config["region"], credentials: @config["credentials"]).create_log_group(
            log_group_name: @config["log_group_name"],
            tags: tags
          )
          @cloud_id = @mu_name

          retries = 0
          max_retries = 5
          begin
            resp = MU::Cloud::AWS::Log.getLogGroupByName(@config["log_group_name"], region: @config["region"])
            if resp.nil?
              if retries >= max_retries
                raise MuError, "Cloudwatch Logs group #{@config["log_group_name"]} creation hasn't succeeded after #{(retries*max_retries).to_s}s"
              else
                retries += 1
                sleep 30
              end
            end
          end while resp.nil?

          MU::Cloud::AWS.cloudwatchlogs(region: @config["region"], credentials: @config["credentials"]).create_log_stream(
            log_group_name: @config["log_group_name"],
            log_stream_name: @config["log_stream_name"]
          )

          MU::Cloud::AWS.cloudwatchlogs(region: @config["region"], credentials: @config["credentials"]).put_retention_policy(
            log_group_name: @config["log_group_name"],
            retention_in_days: @config["retention_period"]
          )

          if @config["filters"] && !@config["filters"].empty?
            @config["filters"].each{ |filter|
              MU::Cloud::AWS.cloudwatchlogs(region: @config["region"], credentials: @config["credentials"]).put_metric_filter(
                log_group_name: @config["log_group_name"],
                filter_name: filter["name"],
                filter_pattern: filter["search_pattern"],
                metric_transformations: [
                  metric_name: filter["metric_name"],
                  metric_namespace: filter["namespace"],
                  metric_value: filter["value"]
                ]
              )
            }
          end

          if @config["enable_cloudtrail_logging"]
            trail_resp = MU::Cloud::AWS.cloudtrail(region: @config["region"], credentials: @config["credentials"]).describe_trails.trail_list.first
            raise MuError, "Can't find a cloudtrail in #{MU::Cloud::AWS.credToAcct(@config['credentials'])}/#{@config["region"]}. Please create cloudtrail before enabling logging on it" unless trail_resp

            iam_policy = '{
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Sid": "AWSCloudTrail",
                  "Effect": "Allow",
                  "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEventsBatch",
                    "logs:PutLogEvents"
                  ],
                  "Resource": "arn:'+(MU::Cloud::AWS.isGovCloud?(@config["region"]) ? "aws-us-gov" : "aws")+':logs:'+@config["region"]+':'+MU::Cloud::AWS.credToAcct(@config['credentials'])+':log-group:'+@config["log_group_name"]+':log-stream:'+@config["log_stream_name"]+'*"
                }
              ]
            }'

            iam_assume_role_policy = '{
              "Version": "2012-10-17",
              "Statement": [
                  {
                      "Effect": "Allow",
                      "Principal": {
                          "Service": [
                              "cloudtrail.amazonaws.com",
                              "cloudtrail.preprod.amazonaws.com"
                          ]
                      },
                      "Action": [
                          "sts:AssumeRole"
                      ]
                  }
              ]
            }'

            iam_role_name = "#{@mu_name}-CloudTrail"
            MU.log "Creating IAM role #{iam_role_name}"
            iam_resp = MU::Cloud::AWS.iam.create_role(
              role_name: iam_role_name,
              assume_role_policy_document: iam_assume_role_policy
            )

            MU::Cloud::AWS.iam.put_role_policy(
              role_name: iam_role_name,
              policy_name: "CloudTrail_CloudWatchLogs",
              policy_document: iam_policy
            )

            log_group_resp = MU::Cloud::AWS::Log.getLogGroupByName(@config["log_group_name"], region: @config["region"])

            retries = 0
            begin 
              MU::Cloud::AWS.cloudtrail(region: @config["region"], credentials: @config["credentials"]).update_trail(
                name: trail_resp.name,
                cloud_watch_logs_log_group_arn: log_group_resp.arn,
                cloud_watch_logs_role_arn: iam_resp.role.arn
              )
            rescue Aws::CloudTrail::Errors::InvalidCloudWatchLogsRoleArnException => e
              if retries < 10
                MU.log "Got #{e.inspect} while enabling logging for CloudTrail, retrying a few times", MU::WARN
                sleep 15
                retry
              else
                raise MuError, "Exhausted retries while waiting to enable CloudTrail logging, giving up. #{e}"
              end
            end
          end

          @cloud_id = @mu_name
        end

        # Grant put access for logs to a cloud service.
        # @param service [String]: The policy document name of an AWS service, e.g. route53.amazonaws.com or elasticsearch.amazonaws.com
        # @param log_arn [String]: The ARN of the log group to which we're granting access
        # @param region [String]: The region in which to allow access
        def self.allowService(service, log_arn, region = MU.myRegion)
          prettyname = service.sub(/\..*/, "").capitalize
          doc = '{ "Version": "2012-10-17", "Statement": [ { "Sid": "'+prettyname+'LogsToCloudWatchLogs", "Effect": "Allow", "Principal": { "Service": [ "'+service+'" ] }, "Action": [ "logs:PutLogEvents", "logs:PutLogEventsBatch", "logs:CreateLogStream" ], "Resource": "'+log_arn+'" } ] }'

          MU::Cloud::AWS.cloudwatchlogs(region: region).put_resource_policy(
            policy_name: "Allow"+prettyname,
            policy_document: doc
          )
        end

        # Return the cloud descriptor for the Log Group
        def cloud_desc
          MU::Cloud::AWS::Log.find(cloud_id: @cloud_id).values.first
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc.arn
        end

        # Return the metadata for this log configuration
        # @return [Hash]
        def notify
          {
            "log_group_name" => @config["log_group_name"],
            "log_stream_name" => @config["log_stream_name"]
          }
        end

        # Remove all logs associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          log_groups =
            begin 
              MU::Cloud::AWS.cloudwatchlogs(credentials: credentials, region: region).describe_log_groups.log_groups
            # TO DO: Why is it returning UnknownOperationException instead of valid error?
            rescue Aws::CloudWatchLogs::Errors::UnknownOperationException => e
              MU.log e.inspect
              []
            end

          if !log_groups.empty?
            log_groups.each{ |lg|
              if lg.log_group_name.match(MU.deploy_id)
                log_streams = MU::Cloud::AWS.cloudwatchlogs(credentials: credentials, region: region).describe_log_streams(log_group_name: lg.log_group_name).log_streams
                if !log_streams.empty?
                  log_streams.each{ |ls|
                    MU::Cloud::AWS.cloudwatchlogs(credentials: credentials, region: region).delete_log_stream(
                      log_group_name: lg.log_group_name,
                      log_stream_name: ls.log_stream_name
                    ) unless noop

                    MU.log "Deleted log stream #{ls.log_stream_name} from log group #{lg.log_group_name}"
                  }
                end

                MU::Cloud::AWS.cloudwatchlogs(credentials: credentials, region: region).delete_log_group(
                  log_group_name: lg.log_group_name
                ) unless noop
                MU.log "Deleted log group #{lg.log_group_name}"
              end
            }
          end

          unless noop
            MU::Cloud::AWS.iam(credentials: credentials).list_roles.roles.each{ |role|
              match_string = "#{MU.deploy_id}.*CloudTrail"
              # Maybe we should have a more generic way to delete IAM profiles and policies. The call itself should be moved from MU::Cloud::AWS::Server.
#              MU::Cloud::AWS::Server.removeIAMProfile(role.role_name) if role.role_name.match(match_string)
            }
          end
        end

        # Locate an existing log group.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching log group.
        def self.find(cloud_id: nil, region: MU.curRegion, credentials: nil, flags: {})
          found = nil
          if !cloud_id.nil? and !cloud_id.match(/^arn:/i)
            found ||= {}
            found[cloud_id] = MU::Cloud::AWS::Log.getLogGroupByName(cloud_id, region: region, credentials: nil)
          else
            resp = MU::Cloud::AWS.cloudwatchlogs(region: region, credentials: credentials).describe_log_groups.log_groups.each { |group|
              if group.arn == cloud_id or group.arn.sub(/:\*$/, "") == cloud_id
                found ||= {}
                found[group.log_group_name] = group
                break
              end
            }
          end

          found
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "retention_period" => {
              "type" => "integer",
              "description" => "The number of days to keep log events in the log group before deleting them.",
              "default" => 14,
              "enum" => [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653]
            },
            "enable_cloudtrail_logging"=> {
              "type" => "boolean",
              "default" => false
            },
            "filters" => {
              "type" => "array",
              "minItems" => 1,
              "items" => {
                "description" => "Create a filter on a CloudWachLogs log group.",
                "type" => "object",
                "title" => "CloudWatchLogs filter Parameters",
                "required" => ["name", "search_pattern", "metric_name", "namespace", "value"],
                "additionalProperties" => false,
                "properties" => {
                  "name" => {
                    "type" => "string"
                  },
                  "search_pattern" => {
                    "type" => "string",
                    "description" => "A search pattern that will match values in the log"
                  },
                  "metric_name" => {
                    "type" => "string",
                    "description" => "A descriptive and easy to find name for the metric. This can be used to create Alarm(s)"
                  },
                  "namespace" => {
                    "type" => "string",
                    "description" => "A new or existing name space to add the metric to. Use the same namespace for all filters/metrics that are logically grouped together. Will be used to to create Alarm(s)"
                  },
                  "value" => {
                    "type" => "string",
                    "description" => ""
                  }
                }
              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::logs}, bare and unvalidated.
        # @param log [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(log, configurator)
          ok = true

          if log["filters"] && !log["filters"].empty?
            log["filters"].each{ |filter|
              if filter["namespace"].start_with?("AWS/")
                MU.log "'namespace' can't be under the 'AWS/' namespace", MU::ERR
                ok = false
              end
            }
          end

          ok
        end

        # Retrieve the complete cloud provider description of a log group.
        # @param name [String]: The cloud provider's identifier for this log group.
        # @param region [String]: The cloud provider region
        # @return [OpenStruct]
        def self.getLogGroupByName(name, region: MU.curRegion, credentials: nil)
          MU::Cloud::AWS.cloudwatchlogs(region: region, credentials: credentials).describe_log_groups(log_group_name_prefix: name).log_groups.first
        end
      end
    end
  end
end
