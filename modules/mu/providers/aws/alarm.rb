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

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          if @config["dimensions"]
            dimensions = []
            @config["dimensions"].each { |dimension|
              cloudid = 
                if dimension["name"] and dimension["depclass"]
                  if @dependencies.has_key?(dimension["depclass"])
                    @dependencies[dimension["depclass"]][dimension["name"]].cloudobj.cloud_id
                  end
                elsif dimension["mu_name"] and dimension["deploy_id"]
                  found = MU::MommaCat.findStray("AWS", deps_class, deploy_id: dimension["deploy_id"], mu_name: dimension["mu_name"], region: @region)
                  raise MuError, "Couldn't find #{deps_class} #{dimension["mu_name"]}" if found.nil? || found.empty?
                  resp = found.first.deploydata["cloud_id"]
                  resp.downcase if %w{database cache_cluster}.include?(deps_class)
                else
                  dimension["cloud_id"]
                end
              dimensions << {:name => dimension["cloud_class"], :value => cloudid}
            }
            @config["dimensions"] = dimensions
          end

          @config["alarm_actions"] = [] if @config["alarm_actions"].nil?
          @config["ok_actions"] = [] if @config["ok_actions"].nil?
          if @config["enable_notifications"]

            topic_arn = if @config["notification_group"].match(/^arn:/)
              @config["notification_group"]
            else
              topic = @deploy.findLitterMate(name: @config["notification_group"], type: "notifiers")
              topic.cloudobj.arn
            end

            @config["alarm_actions"] << topic_arn
            @config["ok_actions"] << topic_arn
          end
          @config["ok_actions"].uniq!
          @config["alarm_actions"].uniq!

          MU::Cloud::AWS::Alarm.setAlarm(
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
            region: @region,
            credentials: @credentials
          )

          @cloud_id = @mu_name
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc.alarm_arn
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

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false
        end

        # Remove all alarms associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU.log "AWS::Alarm.cleanup: need to support flags['known']", MU::DEBUG, details: flags
          MU.log "Placeholder: AWS Alarm artifacts do not support tags, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: ignoremaster
          alarms = []
          # We don't have a way to tag alarms, so we try to delete them by the deploy ID. 
          # This can miss alarms in some cases (eg. cache_cluster) so we might want to delete alarms from each API as well.
          MU::Cloud::AWS.cloudwatch(credentials: credentials, region: region).describe_alarms.each { |page|
            page.metric_alarms.map(&:alarm_name).each { |alarm_name|
              alarms << alarm_name if alarm_name.match(deploy_id)
            }
          }

          if !alarms.empty?
            MU::Cloud::AWS.cloudwatch(credentials: credentials, region: region).delete_alarms(alarm_names: alarms) unless noop
            MU.log "Deleted alarms #{alarms.join(', ')}"
          end
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::RELEASE
        end

        # Locate an existing alarm.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching alarms
        def self.find(**args)
          found = {}
          if args[:cloud_id]
            found[args[:cloud_id]] = MU::Cloud::AWS::Alarm.getAlarmByName(args[:cloud_id], region: args[:region], credentials: args[:credentials])
          else
            resp = MU::Cloud::AWS.cloudwatch(region: args[:region], credentials: args[:credentials]).describe_alarms
            if resp and resp.metric_alarms
              resp.metric_alarms.each { |a|
                found[a.alarm_name] = a
              }
            end
          end

          found
        end

        # Create an alarm.
        def self.setAlarm(
                name: nil, ok_actions: [], alarm_actions: [], insufficient_data_actions: [], metric_name: nil, namespace: nil, statistic: nil,
                dimensions: [], period: nil, unit: nil, evaluation_periods: nil, threshold: nil, comparison_operator: nil, region: MU.curRegion, credentials: nil
               )

          # If the alarm already exists, then assume we're updating it and
          # munge in potentially new arguments.
          ext_alarm = getAlarmByName(name, region: region, credentials: credentials)
          if ext_alarm
            if !ext_alarm.dimensions.empty?
              ext_alarm.dimensions.each { |dim|
                dimensions << dim.to_h
              }
              dimensions.uniq!
            end
            if alarm_actions
              alarm_actions.concat(ext_alarm.alarm_actions)
              alarm_actions.uniq!
            end
            if ok_actions
              ok_actions.concat(ext_alarm.ok_actions)
              ok_actions.uniq!
            end
            if insufficient_data_actions
              insufficient_data_actions.concat(ext_alarm.insufficient_data_actions)
              insufficient_data_actions.uniq!
            end
            MU.log "Modifying alarm #{name}"
          else
            MU.log "Creating alarm #{name}"
          end

          begin
            MU::Cloud::AWS.cloudwatch(region: region, credentials: credentials).put_metric_alarm(
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
          rescue Aws::CloudWatch::Errors::ValidationError => e
            # Dopey but ultimately harmless race condition
            if e.message.match(/A separate request to update this alarm is in progress/)
              MU.log "Duplicate request to create alarm #{name}. This one came from #{caller[0]}", MU::WARN
              sleep 15
              retry
            else
              raise e
            end
          end

        end

        # Retrieve the complete cloud provider description of a alarm.
        # @param name [String]: The cloud provider's identifier for this alarm.
        # @param region [String]: The cloud provider region
        # @return [OpenStruct]
        def self.getAlarmByName(name, region: MU.curRegion, credentials: nil)
          MU::Cloud::AWS.cloudwatch(region: region, credentials: credentials).describe_alarms(alarm_names: [name]).metric_alarms.first
        end

        # Publish logging data, or create a new custom container/group for your logging data
        # @param namespace [String]: The name of the container, or group the data will be added to to.
        # @param metric_data [Array]: The data points describing your new metric.
        # @param region [String]: The cloud provider region.
        def self.createMetric(namespace: nil, metric_data: [], region: MU.curRegion)
          MU::Cloud::AWS.cloudwatch(region: region).put_metric_data(namespace: namespace, metric_data: metric_data, region: region)
        end

        # Enable the state of the alarm
        # @param name [String]: The cloud provider's identifier for this alarm.
        # @param region [String]: The cloud provider region.
        def self.enableAlarmAction(name, region: MU.curRegion)
          MU::Cloud::AWS.cloudwatch(region: region).enable_alarm_actions(alarm_names: [name])
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {}
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::alarms}, bare and unvalidated.
        # @param alarm [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(alarm, configurator)
          ok = true
          alarm["dimensions"] ||= []

          if alarm["#TARGETCLASS"] == "cache_cluster"
            alarm['dimensions'] << { "name" => alarm["#TARGETNAME"], "cloud_class" => "CacheClusterId" }
            alarm["namespace"] = "AWS/ElastiCache" if alarm["namespace"].nil?
          elsif alarm["#TARGETCLASS"] == "server"
            alarm['dimensions'] << { "name" => alarm["#TARGETNAME"], "cloud_class" => "InstanceId" }
            alarm["namespace"] = "AWS/EC2" if alarm["namespace"].nil?
          elsif alarm["#TARGETCLASS"] == "database"
            alarm['dimensions'] << { "name" => alarm["#TARGETNAME"], "cloud_class" => "DBInstanceIdentifier" }
            alarm["namespace"] = "AWS/RDS" if alarm["namespace"].nil?
          end

          alarm.delete("#TARGETCLASS")
          alarm.delete("#TARGETNAME")

          if alarm["dimensions"]
            alarm["dimensions"].each{ |dimension|
              if dimension["cloud_class"].nil?
                MU.log "You must specify 'cloud_class'", MU::ERR
                ok = false
              end
  
              alarm["namespace"], depclass = 
                if ["InstanceId", "server", "Server"].include?(dimension["cloud_class"])
                  dimension["cloud_class"] = "InstanceId"
                  ["AWS/EC2", "server"]
                elsif ["AutoScalingGroupName", "server_pool", "ServerPool"].include?(dimension["cloud_class"])
                  dimension["cloud_class"] = "AutoScalingGroupName"
                  ["AWS/EC2", "server_pool"]
                elsif ["DBInstanceIdentifier", "database", "Database"].include?(dimension["cloud_class"])
                  dimension["cloud_class"] = "DBInstanceIdentifier"
                  ["AWS/RDS", "database"]
                elsif ["LoadBalancerName", "loadbalancer", "LoadBalancer"].include?(dimension["cloud_class"])
                  dimension["cloud_class"] = "LoadBalancerName"
                  ["AWS/ELB", "loadbalancer"]
                elsif ["CacheClusterId", "cache_cluster", "CacheCluster"].include?(dimension["cloud_class"])
                  dimension["cloud_class"] = "CacheClusterId"
                  ["AWS/ElastiCache", "cache_cluster"]
                elsif ["VolumeId", "volume", "Volume"].include?(dimension["cloud_class"])
                  dimension["cloud_class"] = "VolumeId"
                  ["AWS/EBS", nil]
                elsif ["BucketName", "bucket", "Bucket"].include?(dimension["cloud_class"])
                  dimension["cloud_class"] = "BucketName"
                  ["AWS/S3", nil]
                elsif ["TopicName", "notification", "Notification"].include?(dimension["cloud_class"])
                  dimension["cloud_class"] = "TopicName"
                  ["AWS/SNS", nil]
                end
  
              if !depclass.nil?
                dimension["depclass"] = depclass
                if !dimension["name"].nil? and !dimension["name"].empty?
                  MU::Config.addDependency(alarm, dimension["name"], depclass)
                end
              end
            }
          end

          ok = false unless MU::Config::Alarm.validate(alarm, configurator) # XXX the stuff in this method is probably also AWS-specific

          ok
        end

      end
    end
  end
end
