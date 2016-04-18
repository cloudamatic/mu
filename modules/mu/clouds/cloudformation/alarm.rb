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
      # A Cloud Watch alarm as configured in {MU::Config::BasketofKittens::alarm}
      class Alarm < MU::Cloud::Alarm

        @deploy = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        attr_reader :cfm_template
        attr_reader :cfm_name

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::alarms}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          else
            @mu_name ||= @deploy.getResourceName(@config["name"])
          end
        end

        # Populate @cfm_template with a resource description for this alarm
        # in CloudFormation language.
        def create
          @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase(self.class.cfg_name, self)
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "AlarmName", @mu_name)
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "AlarmDescription", @mu_name)
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "ComparisonOperator", @config['comparison_operator'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "EvaluationPeriods", @config['evaluation_periods'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "MetricName", @config['metric_name'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Namespace", @config['namespace'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Period", @config['period'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Statistic", @config['statistic'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Threshold", @config['threshold'])

          @config['insufficient_data_actions'] = @config['no_data_actions']
          ["alarm_actions", "ok_actions", "insufficient_data_actions"].each { |arg|
            if @config[arg]
              key = ""
              arg.split(/_/).each { |chunk| key = key + ((chunk == "ok") ? chunk.upcase : chunk.capitalize) }
              @config[arg].each { |action|
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], key, action)
              }
            end
          }
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Unit", @config['unit']) if @config['unit']


          notif_name = notif_template = nil
          if @config["enable_notifications"]
            notif_name, notif_template = MU::Cloud::CloudFormation.cloudFormationBase("notification", name: @config["notification_group"])
            MU::Cloud::CloudFormation.setCloudFormationProp(notif_template[notif_name], "TopicName", @config["notification_group"])
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "AlarmActions", { "Ref" => notif_name } )
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "OKActions", { "Ref" => notif_name } )
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", notif_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(notif_template[notif_name], "Subscription", { "Endpoint" => @config['notification_endpoint'], "Protocol" => @config['notification_type'] })
            @cfm_template.merge!(notif_template)
          end

          if @config["dimensions"]
            @config["dimensions"].each { |dimension|
              cloudid =
              # If we specified mu_name/deploy_id try to find the cloud_id of the resource. if we specified a cloud_id directly then use it.
                if dimension["name"] and dimension["depclass"]
                    if @dependencies.has_key?(dimension["depclass"])
                      { "Ref" => @dependencies[dimension["depclass"]][dimension["name"]].cloudobj.cfm_name }

                    else
                      raise MuError, "Couldn't find cloud resource referenced by dimension in alarm #{@mu_name} (#{dimension})"
                    end
                elsif dimension["cloud_id"]
                  dimension["cloud_id"]
                else
                  MU.log "Cannot identify a resource from #{dimension} when targeting CloudFormation output", MU::WARN
                  nil
                end
              next if cloudid.nil?
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Dimensions", {"Name" => dimension["cloud_class"], "Value" => cloudid})
            }
          elsif @config['namespace'] == "AWS/EC2"
            MU.log "Will create Alarm #{@mu_name} with no associated Dimensions. If this Alarm is part of a ServerPool, you may need to manually associate individual instances once they are created.", MU::NOTICE
          else
            MU.log "Will create Alarm #{@mu_name} with no associated Dimensions", MU::WARN
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

      end
    end
  end
end
