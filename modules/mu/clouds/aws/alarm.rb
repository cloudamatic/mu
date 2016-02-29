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
      # A alarm as configured in {MU::Config::BasketofKittens::alarms}
      class Alarm < MU::Cloud::Alarm
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        @cloudformation_data = {}
        attr_reader :cloudformation_data

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::alarms}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          if @config["dimensions"]
            dimensions = []
            @config["dimensions"].each { |dimension|
              cloudid = 
              # If we specified mu_name/deploy_id try to find the cloud_id of the resource. if we specified a cloud_id directly then use it.
                if dimension["mu_name"] || dimension["deploy_id"]
                  deps_class = 
                    if dimension["cloud_class"] == "InstanceId"
                      "server"
                    elsif dimension["cloud_class"] == "DBInstanceIdentifier"
                      "database"
                    elsif dimension["cloud_class"] == "LoadBalancerName"
                      "loadbalancer"
                    elsif dimension["cloud_class"] == "CacheClusterId"
                      "cache_cluster"
                    end

                    if @dependencies.has_key?(deps_class)
                      # instance_id = @dependencies["server"][dimension["mu_name"]].cloud_desc.instance_id
                      @dependencies[deps_class][dimension["mu_name"]].deploydata["cloud_id"]
                    else
                      found = MU::MommaCat.findStray("AWS", deps_class, deploy_id: dimension["deploy_id"], mu_name: dimension["mu_name"], region: @config["region"])
                      raise MuError, "Couldn't find #{deps_class} #{dimension["mu_name"]}" if found.nil? || found.empty?
                      resp = found.first.deploydata["cloud_id"]
                      resp.downcase if %w{database cache_cluster}.include?(deps_class)
                    end
                else
                  dimension["cloud_id"]
                end            
              dimensions << {:name => dimension["cloud_class"], :value => cloudid}
            }
            @config["dimensions"] = dimensions
          end

          if @config["enable_notifications"]
            @config["alarm_actions"] = [] if @config["alarm_actions"].nil?
            @config["ok_actions"] = [] if @config["ok_actions"].nil?

            topic_arn = MU::Cloud::AWS::Notification.createTopic(@config["notification_group"], region: @config["region"])
            MU::Cloud::AWS::Notification.subscribe(arn: topic_arn, protocol: @config["notification_type"], endpoint: @config["notification_endpoint"], region: @config["region"])

            @config["alarm_actions"] << topic_arn
            @config["ok_actions"] << topic_arn
          end

          MU::Cloud::AWS::Alarm.createAlarm(
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

        # Return the metadata for this Alarm rule
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

        # Remove all alarms associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          alarms = []
          MU::Cloud::AWS.cloudwatch(region).describe_alarms.metric_alarms.each { |alarm|
            # We don't have a way to tag alarms, so we try to delete them by the deploy ID. 
            # This can miss alarms in some cases (eg. cache_cluster) so we might want to delete alarms from each API as well.
            alarms << alarm.alarm_name if alarm.alarm_name.match(MU.deploy_id)
          }

          if !alarms.empty?
            MU::Cloud::AWS.cloudwatch(region).delete_alarms(alarm_names: alarms) unless noop
            MU.log "Deleted alarms #{alarms.join(', ')}"
          end
        end

        # Locate an existing alarm.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching alarm.
        def self.find(cloud_id: nil, region: MU.curRegion)
          MU::Cloud::AWS::Alarm.getAlarmByName(cloud_id, region: region)
        end

        # Create an alarm.
        def self.createAlarm(
                name: nil, ok_actions: [], alarm_actions: [], insufficient_data_actions: [], metric_name: nil, namespace: nil, statistic: nil,
                dimensions: [], period: nil, unit: nil, evaluation_periods: nil, threshold: nil, comparison_operator: nil, region: MU.curRegion
               )

          unless getAlarmByName(name, region: region)
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
        end

        # Retrieve the complete cloud provider description of a alarm.
        # @param name [String]: The cloud provider's identifier for this alarm.
        # @param region [String]: The cloud provider region
        # @return [OpenStruct]
        def self.getAlarmByName(name, region: MU.curRegion)
          MU::Cloud::AWS.cloudwatch(region).describe_alarms(alarm_names: [name]).metric_alarms.first
        end

        # Publish logging data, or create a new custom container/group for your logging data
        # @param namespace [String]: The name of the container, or group the data will be added to to.
        # @param metric_data [Array]: The data points describing your new metric.
        # @param region [String]: The cloud provider region.
        def self.createMetric(namespace: nil, metric_data: [], region: MU.curRegion)
          MU::Cloud::AWS.cloudwatch(region).put_metric_data(namespace: namespace, metric_data: metric_data, region: region)
        end

        # Enable the state of the alarm
        # @param name [String]: The cloud provider's identifier for this alarm.
        # @param region [String]: The cloud provider region.
        def self.enableAlarmAction(name, region: MU.curRegion)
          MU::Cloud::AWS.cloudwatch(region).enable_alarm_actions(alarm_names: [name])
        end
      end
    end
  end
end
