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

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          @config["log_group_name"] = @mu_name
          @config["log_stream_name"] =
            if @config["enable_cloudtrail_logging"]
              "#{MU::Cloud::AWS.credToAcct(@credentials)}_CloudTrail_#{@region}"
            else
              @mu_name
            end

          MU.log "Creating log group #{@mu_name}"
          MU::Cloud::AWS.cloudwatchlogs(region: @region, credentials: @credentials).create_log_group(
            log_group_name: @config["log_group_name"],
            tags: @tags
          )
          @cloud_id = @mu_name

          retries = 0
          max_retries = 5
          begin
            resp = MU::Cloud::AWS::Log.getLogGroupByName(@config["log_group_name"], region: @region)
            if resp.nil?
              if retries >= max_retries
                raise MuError, "Cloudwatch Logs group #{@config["log_group_name"]} creation hasn't succeeded after #{(retries*max_retries).to_s}s"
              else
                retries += 1
                sleep 30
              end
            end
          end while resp.nil?

          MU::Cloud::AWS.cloudwatchlogs(region: @region, credentials: @credentials).create_log_stream(
            log_group_name: @config["log_group_name"],
            log_stream_name: @config["log_stream_name"]
          )

          MU::Cloud::AWS.cloudwatchlogs(region: @region, credentials: @credentials).put_retention_policy(
            log_group_name: @config["log_group_name"],
            retention_in_days: @config["retention_period"]
          )

          if @config["filters"] && !@config["filters"].empty?
            @config["filters"].each{ |filter|
              MU::Cloud::AWS.cloudwatchlogs(region: @region, credentials: @credentials).put_metric_filter(
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
            trail_resp = MU::Cloud::AWS.cloudtrail(region: @region, credentials: @credentials).describe_trails.trail_list.first
            raise MuError, "Can't find a cloudtrail in #{MU::Cloud::AWS.credToAcct(@credentials)}/#{@region}. Please create cloudtrail before enabling logging on it" unless trail_resp

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
                  "Resource": "arn:'+(MU::Cloud::AWS.isGovCloud?(@region) ? "aws-us-gov" : "aws")+':logs:'+@region+':'+MU::Cloud::AWS.credToAcct(@credentials)+':log-group:'+@config["log_group_name"]+':log-stream:'+@config["log_stream_name"]+'*"
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

            log_group_resp = MU::Cloud::AWS::Log.getLogGroupByName(@config["log_group_name"], region: @region)

            retries = 0
            begin 
              MU::Cloud::AWS.cloudtrail(region: @region, credentials: @credentials).update_trail(
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

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc ? cloud_desc.arn : nil
        end

        # Return the metadata for this log configuration
        # @return [Hash]
        def notify
          {
            "log_group_name" => @config["log_group_name"],
            "log_stream_name" => @config["log_stream_name"]
          }
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::BETA
        end

        # Remove all logs associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU.log "AWS::Log.cleanup: need to support flags['known']", MU::DEBUG, details: flags
          MU.log "Placeholder: AWS Log artifacts do not support tags, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: ignoremaster

          log_groups = self.find(credentials: credentials, region: region).values
          if !log_groups.empty?
            log_groups.each{ |lg|
              if lg.log_group_name.match(deploy_id)
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

#          unless noop
#            MU::Cloud::AWS.iam(credentials: credentials).list_roles.roles.each{ |role|
#              match_string = "#{deploy_id}.*CloudTrail"
              # Maybe we should have a more generic way to delete IAM profiles and policies. The call itself should be moved from MU::Cloud.resourceClass("AWS", "Server").
#              MU::Cloud.resourceClass("AWS", "Server").removeIAMProfile(role.role_name) if role.role_name.match(match_string)
#            }
#          end
        end

        # Locate an existing log group.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching log group.
        def self.find(**args)
          found = {}
          if !args[:cloud_id].nil? and !args[:cloud_id].match(/^arn:/i)
            exists = MU::Cloud::AWS::Log.getLogGroupByName(args[:cloud_id], region: args[:region], credentials: args[:credentials])
            found[args[:cloud_id]] = exists if exists
          else
            next_token = nil
            begin
              resp = MU::Cloud::AWS.cloudwatchlogs(region: args[:region], credentials: args[:credentials]).describe_log_groups(next_token: next_token)
              return found if resp.nil? or resp.log_groups.nil?

              resp.log_groups.each { |group|
                if group.arn == args[:cloud_id] or group.arn.sub(/:\*$/, "") == args[:cloud_id] or !args[:cloud_id]
                  found[group.log_group_name] = group
                  break if args[:cloud_id]
                end
              }
              next_token = resp.next_token
            end while next_token
          end

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**_args)
          bok = {
            "cloud" => "AWS",
            "credentials" => @credentials,
            "cloud_id" => @cloud_id,
            "region" => @region
          }

          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end

          bok['name'] = cloud_desc.log_group_name.sub(/.*?\/([^\/]+)$/, '\1')

          if cloud_desc.metric_filter_count > 0
            resp = MU::Cloud::AWS.cloudwatchlogs(region: @region, credentials: @credentials).describe_metric_filters(
              log_group_name: @cloud_id
            )
            resp.metric_filters.each { |filter|
              bok["filters"] ||= []
              bok["filters"] << {
                "name" => filter.filter_name,
                "search_pattern" => filter.filter_pattern,
                "metric_name" => filter.metric_transformations.first.metric_name,
                "namespace" => filter.metric_transformations.first.metric_namespace,
                "value" => filter.metric_transformations.first.metric_value
              }
            }
          end

          if cloud_desc.retention_in_days
            bok["retention_period"] = cloud_desc.retention_in_days
          end

          bok
        end


        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
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
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(log, _configurator)
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
