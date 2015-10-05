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
      # A log as configured in {MU::Config::BasketofKittens::logs}
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
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          @config["log_group_name"] = @mu_name
          @config["log_stream_name"] =
            if @config["enable_cloudtrail_logging"]
              "#{MU.account_number}_CloudTrail_#{@config["region"]}"
            else
              @mu_name
            end

          MU.log "Creating log group #{@mu_name}"

          MU::Cloud::AWS.cloudwatchlogs(@config["region"]).create_log_group(
            log_group_name: @config["log_group_name"]
          )

          MU::Cloud::AWS.cloudwatchlogs(@config["region"]).create_log_stream(
            log_group_name: @config["log_group_name"],
            log_stream_name: @config["log_stream_name"]
          )

          MU::Cloud::AWS.cloudwatchlogs(@config["region"]).put_retention_policy(
            log_group_name: @config["log_group_name"],
            retention_in_days: @config["retention_period"]
          )

          if @config["filters"] && !@config["filters"].empty?
            @config["filters"].each{ |filter|
              MU::Cloud::AWS.cloudwatchlogs(@config["region"]).put_metric_filter(
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
            trail_resp = MU::Cloud::AWS.cloudtrail(@config["region"]).describe_trails.trail_list.first
            raise MuError, "Can't find a cloudtrail in #{MU.account_number}/#{@config["region"]}. Please create cloudtrail before enabling logging on it" unless trail_resp

            iam_policy = '{
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Sid": "AWSCloudTrail",
                  "Effect": "Allow",
                  "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                  ],
                  "Resource": "arn:aws:logs:'+@config["region"]+':'+MU.account_number+':log-group:'+@config["log_group_name"]+':log-stream:'+@config["log_stream_name"]+'*"
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

            MU.log "Creating IAM role #{@mu_name}"
            iam_resp = MU::Cloud::AWS.iam(@config["region"]).create_role(
              role_name: @mu_name,
              assume_role_policy_document: iam_assume_role_policy
            )

            MU::Cloud::AWS.iam(@config["region"]).put_role_policy(
              role_name: @mu_name,
              policy_name: "CloudTrail_CloudWatchLogs",
              policy_document: iam_policy
            )

            log_group_resp = MU::Cloud::AWS::Log.getLogGroupByName(@config["log_group_name"], region: @config["region"])

            retries = 0
            begin 
              MU::Cloud::AWS.cloudtrail(@config["region"]).update_trail(
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

        # Return the metadata for this log cofiguration
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
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          log_groups =
            begin 
              MU::Cloud::AWS.cloudwatchlogs(region).describe_log_groups.log_groups
            # TO DO: Why is it returning UnknownOperationException instead of valid error?
            rescue Aws::CloudWatchLogs::Errors::UnknownOperationException
              []
            end

          if !log_groups.empty?
            log_groups.each{ |lg|
              if lg.log_group_name.match(MU.deploy_id)
                log_streams = MU::Cloud::AWS.cloudwatchlogs(region).describe_log_streams(log_group_name: lg.log_group_name).log_streams
                if !log_streams.empty?
                  log_streams.each{ |ls|
                    MU::Cloud::AWS.cloudwatchlogs(region).delete_log_stream(
                      log_group_name: lg.log_group_name,
                      log_stream_name: ls.log_stream_name
                    ) unless noop

                    MU.log "Deleted log stream #{ls.log_stream_name} from log group #{lg.log_group_name}"
                  }
                end

                MU::Cloud::AWS.cloudwatchlogs(region).delete_log_group(
                  log_group_name: lg.log_group_name
                ) unless noop
                MU.log "Deleted log group #{lg.log_group_name}"
              end
            }
          end
        end

        # Locate an existing log group.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching log group.
        def self.find(cloud_id: nil, region: MU.curRegion)
          MU::Cloud::AWS::Log.getLogGroupByName(cloud_id, region: region)
        end

        # Retrieve the complete cloud provider description of a log group.
        # @param name [String]: The cloud provider's identifier for this log group.
        # @param region [String]: The cloud provider region
        # @return [OpenStruct]
        def self.getLogGroupByName(name, region: MU.curRegion)
          MU::Cloud::AWS.cloudwatchlogs(region).describe_log_groups(log_group_name_prefix: name).log_groups.first
        end
      end
    end
  end
end
