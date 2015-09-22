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
      # A alarm as configured in {MU::Config::BasketofKittens::Alerts}
      class Alert < MU::Cloud::Alert

        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::Alerts}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          MU::Cloud::AWS::Alert.createAlarm(
            name: @mu_name,
            ok_actions: @config["ok_actions"],
            alarm_actions: @config["alarm_actions"],
            insufficient_data_actions: @config["no_data_actions"],
            metric_name: @config["metric_name"],
            namespace: @config["namespace"],
            statistic: @config["statistic"],
            dimensions: @config["dimensions"],
            period: @config["period"],
            unit: @config["unit"],
            evaluation_periods: @config["evaluation_periods"],
            threshold: @config["threshold"],
            comparison_operator: @config["comparison_operator"],
            region: @config["region"]
          )

          @cloud_id = @mu_name
        end

        # Return the metadata for this Alert rule
        # @return [Hash]
        def notify
          deploy_struct = {
            "ok_actions" => @config["ok_actions"],
            "alarm_actions" => @config["alarm_actions"],
            "insufficient_data_actions" => @config["no_data_actions"],
            "metric_name" => @config["metric_name"],
            "namespace" => @config["namespace"],
            "statistic" => @config["statistic"],
            "dimensions" => @config["dimensions"],
            "period" => @config["period"],
            "unit" => @config["unit"],
            "evaluation_periods" => @config["evaluation_periods"],
            "threshold" => @config["threshold"],
            "comparison_operator" => @config["comparison_operator"]
          }
          return deploy_struct
        end

        # Remove all alerts associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
        alarms = []
          MU::Cloud::AWS.cloudwatch(region).describe_alarms.metric_alarms.each { |alarm|
            # We don't have a way to tag alarms, so we try to delete them by the deploy ID. 
            # This can miss alerts in some cases (eg. cache_cluster) so we might want to delete alerts from each API as well.
            alarms << alarm.alarm_name if alarm.alarm_name.match(MU.deploy_id)
          }

          if !alarms.empty?
            MU::Cloud::AWS.cloudwatch(region).delete_alarms(alarm_names: alarms)
            MU.log "Deleted alarms #{alarms.join(', ')}"
          end
        end

        # Locate an existing alarm.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching alert.
        def self.find(cloud_id: nil, region: MU.curRegion)
          MU::Cloud::AWS::Alert.getAlarmByName(cloud_id, region: region)
        end

        def self.createAlarm(
                name: nil, ok_actions: [], alarm_actions: [], insufficient_data_actions: [], metric_name: nil, namespace: nil, statistic: nil,
                dimensions: [], period: nil, unit: nil, evaluation_periods: nil, threshold: nil, comparison_operator: nil, region: MU.curRegion
               )

          MU::Cloud::AWS.cloudwatch(region).put_metric_alarm(
            alarm_name: name,
            alarm_description: name,
            actions_enabled: true,
            ok_actions: ok_actions,
            alarm_actions: alarm_actions,
            insufficient_data_actions: insufficient_data_actions,
            metric_name: metric_name,
            namespace: namespace,
            statistic: statistic,
            dimensions: dimensions,
            period: period,
            unit: unit,
            evaluation_periods: evaluation_periods,
            threshold: threshold,
            comparison_operator: comparison_operator
          )
          
          MU.log "Alarm #{name} created"
        end

        def self.getAlarmByName(name, region: MU.curRegion)
          MU::Cloud::AWS.cloudwatch(region).describe_alarms(alarm_names: [name]).metric_alarms.first
        end

        def self.createMetric
          MU::Cloud::AWS.cloudwatch(region).put_metric_data(namespace: nil, metric_data: [], region: MU.curRegion)
        end
        
        def self.enableAlarmAction(name, region: MU.curRegion)
          MU::Cloud::AWS.cloudwatch(region).enable_alarm_actions(alarm_names: [name])
        end
      end
    end
  end
end
