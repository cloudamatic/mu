# Copyright:: Copyright (c) 2016 eGlobalTech, Inc., all rights reserved
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
    class CloudFormation
      # A log target as configured in {MU::Config::BasketofKittens::logs}
      class Log < MU::Cloud::Log

        @deploy = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        attr_reader :cfm_template
        attr_reader :cfm_name

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::logs}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name ||= @deploy.getResourceName(@config["name"])
          end
        end

        # Populate @cfm_template with a resource description for this log
        # in CloudFormation language.
        def create
          @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase("loggroup", self, scrub_mu_isms: @config['scrub_mu_isms'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "RetentionInDays", @config["retention_period"])

          @config["log_stream_name"] =
            if @config["enable_cloudtrail_logging"]
              { "Fn::Join" => [
                  "",
                  [
                    { "Ref" => "AWS::AccountId" },
                    "_CloudTrail_",
                    { "Ref" => "AWS::Region" }
                  ]
                ]
              }
            else
              @mu_name
            end

          stream_name, stream_template = MU::Cloud::CloudFormation.cloudFormationBase("logstream", self, scrub_mu_isms: @config['scrub_mu_isms'])
          MU::Cloud::CloudFormation.setCloudFormationProp(stream_template[stream_name], "LogGroupName", { "Ref" => @cfm_name })
          MU::Cloud::CloudFormation.setCloudFormationProp(stream_template[stream_name], "LogStreamName", @config["log_stream_name"])
          MU::Cloud::CloudFormation.setCloudFormationProp(stream_template[stream_name], "DependsOn", @cfm_name)
          @cfm_template.merge!(stream_template)

          if @config["filters"] && !@config["filters"].empty?
            @config["filters"].each{ |filter|
              metric_name, metric_template = MU::Cloud::CloudFormation.cloudFormationBase("logmetricfilter", self, name: @mu_name+"filter"+filter["name"], scrub_mu_isms: @config['scrub_mu_isms'])
              MU::Cloud::CloudFormation.setCloudFormationProp(metric_template[metric_name], "FilterPattern", filter["search_pattern"])
              MU::Cloud::CloudFormation.setCloudFormationProp(metric_template[metric_name], "MetricTransformations", { "MetricName" => filter["metric_name"], "MetricNamespace" => filter["namespace"], "MetricValue" => filter["value"] } )
              MU::Cloud::CloudFormation.setCloudFormationProp(metric_template[metric_name], "LogGroupName", { "Ref" => @cfm_name })
              MU::Cloud::CloudFormation.setCloudFormationProp(metric_template[metric_name], "DependsOn", @cfm_name)
              @cfm_template.merge!(metric_template)
            }
          end


          if @config["enable_cloudtrail_logging"]
            role_name, role_template = MU::Cloud::CloudFormation.cloudFormationBase("iamrole", name: @mu_name, scrub_mu_isms: @config['scrub_mu_isms'])
            iam_policy = {
              "Version" => "2012-10-17",
              "Statement" => [
                {
                  "Sid" => "AWSCloudTrail",
                  "Effect" => "Allow",
                  "Action" => [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                  ],
                  "Resource" => { "Fn::Join" => [
                      "",
                      [
                        "arn:#{MU::Cloud::AWS.isGovCloud?(@config["region"]) ? "aws-us-gov" : "aws"}:logs:",
                        { "Ref" => "AWS::Region" },
                        ":",
                        { "Ref" => "AWS::AccountId" },
                        ":log-group:#{@cfm_name}:log-stream:",
                        @config["log_stream_name"]
                      ]
                    ]
                  }
                }
              ]
            }
            MU::Cloud::CloudFormation.setCloudFormationProp(role_template[role_name], "Policies", { "PolicyName" => "#{@mu_name}-CloudTrail", "PolicyDocument" => iam_policy })
            iam_assume_role_policy = {
              "Version" => "2012-10-17",
              "Statement" => [
                  {
                      "Effect" => "Allow",
                      "Principal" => {
                          "Service" => [
                              "cloudtrail.amazonaws.com",
                              "cloudtrail.preprod.amazonaws.com"
                          ]
                      },
                      "Action" => [
                          "sts:AssumeRole"
                      ]
                  }
              ]
            }
            MU::Cloud::CloudFormation.setCloudFormationProp(role_template[role_name], "AssumeRolePolicyDocument", iam_assume_role_policy)
            @cfm_template.merge!(role_template)
            MU.log "You must manually associate the Log Group #{@cfm_name} and IAM Role #{role_name} with your account's Cloud Trail after this CloudFormation stack has been built.", MU::WARN
          end
        end

        # Return the metadata for this CacheCluster
        # @return [Hash]
        def notify
          {}
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def self.find(*args)
          MU.log "find() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def self.cleanup(*args)
          MU.log "cleanup() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          MU::Cloud::AWS::Log.schema(config)
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::servers}, bare and unvalidated.
        # @param server [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(server, configurator)
          MU::Cloud::AWS::Log.validateConfig(server, configurator)
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          MU::Cloud::AWS::Log.isGlobal?
        end

      end
    end
  end
end
