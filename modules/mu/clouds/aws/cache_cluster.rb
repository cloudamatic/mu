# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#	http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

module MU
  class Cloud
    class AWS
      # A cache cluster as configured in {MU::Config::BasketofKittens::cache_clusters}
      class CacheCluster < MU::Cloud::CacheCluster
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :cloud_id
        attr_reader :config

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::cache_clusters}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          # @mu_name = mu_name ? mu_name : @deploy.getResourceName(@config["name"])

          @mu_name ||=
            if @config["create_replication_group"]
              @deploy.getResourceName(@config["name"], max_length: 16, need_unique_string: true)
            else
              @deploy.getResourceName(@config["name"], max_length: 20, need_unique_string: true)
            end

          @mu_name.gsub!(/(--|-$)/i, "")
        end

        # Locate an existing Cache Cluster or Cache Clusters and return an array containing matching AWS resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching Cache Clusters.
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil)
          map = {}
          if cloud_id
            cache_cluster = MU::Cloud::AWS::CacheCluster.getCacheClusterById(cloud_id, region: region)
            map[cloud_id] = cache_cluster if cache_cluster
          end

          if tag_value
            MU::Cloud::AWS.elasticache(region).describe_cache_clusters.cache_clusters.each { |cc|
              resp = MU::Cloud::AWS.elasticache(region).list_tags_for_resource(
                  resource_name: MU::Cloud::AWS::CacheCluster.getARN(cc.cache_cluster_id, "cluster", "elasticache", region: region)
              )
              if resp && resp.tag_list && !resp.tag_list.empty?
                resp.tag_list.each { |tag|
                    map[cc.cache_cluster_id] = cc if tag.key == tag_key and tag.value == tag_value
                }
              end
            }
          end

          return map
        end

        # Construct an Amazon Resource Name for an AWS resource.
        # Some APIs require this identifier in order to do things that other APIs can do with shorthand.
        # @param resource [String]: The name of the resource
        # @param client_type [String]: The name of the client (eg. elasticache, rds, ec2, s3)
        # @param resource_type [String]: The type of the resource
        # @param region [String]: The region in which the resource resides.
        # @param account_number [String]: The account in which the resource resides.
        # @return [String]
        def self.getARN(resource, resource_type, client_type, region: MU.curRegion, account_number: MU.account_number)
          "arn:aws:#{client_type}:#{region}:#{account_number}:#{resource_type}:#{resource}"
        end

        # Construct all our tags.
        # @return [Array]: All our standard tags and any custom tags.
        def allTags
          tags = []
          MU::MommaCat.listStandardTags.each_pair { |name, value|
            tags << {key: name, value: value}
          }

          if @config['tags']
            @config['tags'].each { |tag|
              tags << {key: tag['key'], value: tag['value']}
            }
          end

          return tags
        end

        # Add our standard tag set to an Amazon ElasticCache resource.
        # @param resource [String]: The name of the resource
        # @param resource_type [String]: The type of the resource
        # @param region [String]: The cloud provider region
        def addStandardTags(resource, resource_type, region: MU.curRegion)
          MU.log "Adding tags to ElasticCache resource #{resource}"
          MU::Cloud::AWS.elasticache(region).add_tags_to_resource(
            resource_name: MU::Cloud::AWS::CacheCluster.getARN(resource, resource_type, "elasticache", region: region),
            tags: allTags
          )
        end

        # Called automatically by {MU::Deploy#createResources}
        # @return [String]: The cloud provider's identifier for this cache cluster instance.
        def create
          @config["snapshot_id"] =
            if @config["creation_style"] == "existing_snapshot"
              getExistingSnapshot ? getExistingSnapshot : createNewSnapshot
            elsif @config["creation_style"] == "new_snapshot"
              createNewSnapshot
            end

            # Should we base all our resource names on @mu_name even though only the cache cluster / cache replication group identifiers are the isssue? 
          @config['identifier'] = @mu_name
          @config["subnet_group_name"] = @mu_name
          createSubnetGroup

          # Shared configuration elements between cache clusters and cache replication groups
          config_struct = {
            cache_node_type: @config["size"],
            engine: @config["engine"],
            engine_version: @config["engine_version"],
            cache_subnet_group_name: @config["subnet_group_name"],
            preferred_maintenance_window: @config["preferred_maintenance_window"],
            port: @config["port"],
            auto_minor_version_upgrade: @config["auto_minor_version_upgrade"],
            security_group_ids: @config["security_group_ids"],
            tags: allTags
          }

          if @config["engine"] == "redis"
            config_struct[:snapshot_name] = @config["snapshot_id"] if @config["snapshot_id"]
            config_struct[:snapshot_arns] = @config["snapshot_arn"] if @config["snapshot_arn"]
            config_struct[:snapshot_retention_limit] = @config["snapshot_retention_limit"] if @config["snapshot_retention_limit"]
            config_struct[:snapshot_window] = @config["snapshot_window"] if @config["snapshot_window"]
          end

          if @config.has_key?("parameter_group_family")
            # downcasing parameter_group_name because  AWS downcases the name for us and we won't be able to find it.
            # AWS downcases all resource names in ElastiCache for some reason, 
            # but other resources don't seem to be case sensitive when we try to retrieve them.
            @config["parameter_group_name"] = @mu_name.downcase
            createParameterGroup
            config_struct[:cache_parameter_group_name] = @config["parameter_group_name"]
          end

          config_struct[:notification_topic_arn] = @config["notification_topic_arn"] if @config["notification_topic_arn"]

          # Mu already cleans up our resources for us when we fail mid creation, so not doing begin/ensure to cleanup in case we fail.
          if @config["create_replication_group"]
            config_struct[:automatic_failover_enabled] = @config['automatic_failover']
            config_struct[:replication_group_id] = @config['identifier']
            config_struct[:replication_group_description] = @mu_name
            config_struct[:num_cache_clusters] = @config["node_count"]
            # config_struct[:primary_cluster_id] = @config["primary_cluster_id"]
            # config_struct[:preferred_cache_cluster_a_zs] = @config["preferred_cache_cluster_azs"]

            MU.log "Creating cache replication group #{@config['identifier']}"
            resp = MU::Cloud::AWS.elasticache(@config['region']).create_replication_group(config_struct).replication_group

            wait_start_time = Time.now
            retries = 0
            begin
              MU::Cloud::AWS.elasticache(@config['region']).wait_until(:replication_group_available, replication_group_id: @config['identifier']) do |waiter|
                waiter.max_attempts = nil
                waiter.before_attempt do |attempts|
                  MU.log "Waiting for cache replication group #{@config['identifier']} to become available", MU::NOTICE if attempts % 5 == 0
                end
                waiter.before_wait do |attempts, resp|
                  throw :success if resp.replication_groups.first.status == "available"
                  throw :failure if Time.now - wait_start_time > 1800
                end
              end
            rescue Aws::Waiters::Errors::TooManyAttemptsError => e
              raise MuError, "Waited #{(Time.now - wait_start_time).round/60*(retries+1)} minutes for #{@config['identifier']} become available, giving up. #{e}" if retries > 2
              wait_start_time = Time.now
              retries += 1
              retry
            end

            resp = MU::Cloud::AWS::CacheCluster.getCacheReplicationGroupById(@config['identifier'], region: @config['region'])

            # We want to make sure the clusters in the cache replication group get our tags
            resp.member_clusters.each { |member|
              addStandardTags(member, "cluster", region: @config['region'])
            }

            MU::Cloud::AWS::DNSZone.genericMuDNSEntry(
              name: resp.replication_group_id,
              target: "#{resp.node_groups.first.primary_endpoint.address}.",
              cloudclass: MU::Cloud::CacheCluster,
              sync_wait: @config['dns_sync_wait']
            )

            resp.node_groups.first.node_group_members.each { |member|
              MU::Cloud::AWS::DNSZone.genericMuDNSEntry(
                name: member.cache_cluster_id,
                target: "#{member.read_endpoint.address}.",
                cloudclass: MU::Cloud::CacheCluster,
                sync_wait: @config['dns_sync_wait']
              )

              createAlarm(member.cache_cluster_id) if @config["alarms"] && !@config["alarms"].empty?
            }

            MU.log "Cache replication group #{@config['identifier']} is ready to use"
            @cloud_id = resp.replication_group_id
          else
            config_struct[:cache_cluster_id] = @config['identifier']
            config_struct[:az_mode] = @config["az_mode"]
            config_struct[:num_cache_nodes] = @config["node_count"]
            # config_struct[:replication_group_id] = @config["replication_group_id"] if @config["replication_group_id"]
            # config_struct[:preferred_availability_zone] = @config["preferred_availability_zone"] if @config["preferred_availability_zone"] && @config["az_mode"] == "single-az"
            # config_struct[:preferred_availability_zones] = @config["preferred_availability_zones"] if @config["preferred_availability_zones"] && @config["az_mode"] == "cross-az"

            MU.log "Creating cache cluster #{@config['identifier']}"
            resp = MU::Cloud::AWS.elasticache(@config['region']).create_cache_cluster(config_struct).cache_cluster

            wait_start_time = Time.now
            retries = 0
            begin
              MU::Cloud::AWS.elasticache(@config['region']).wait_until(:cache_cluster_available, cache_cluster_id: @config['identifier']) do |waiter|
                waiter.max_attempts = nil
                waiter.before_attempt do |attempts|
                  MU.log "Waiting for cache cluster #{@config['identifier']} to become available", MU::NOTICE if attempts % 5 == 0
                end
                waiter.before_wait do |attempts, resp|
                  throw :success if resp.cache_clusters.first.cache_cluster_status  == "available"
                  throw :failure if Time.now - wait_start_time > 1800
                end
              end
            rescue Aws::Waiters::Errors::TooManyAttemptsError => e
              raise MuError, "Waited #{(Time.now - wait_start_time).round/60*(retries+1)} minutes for #{@config['identifier']} to become available, giving up. #{e}" if retries > 2
              wait_start_time = Time.now
              retries += 1
              retry
            end

            resp = MU::Cloud::AWS::CacheCluster.getCacheClusterById(@config['identifier'], region: @config['region'])
            MU.log "Cache Cluster #{@config['identifier']} is ready to use"
            createAlarm(resp.cache_cluster_id) if @config["alarms"] && !@config["alarms"].empty?
            @cloud_id = resp.cache_cluster_id
          end
        end

        # Create a subnet group for a Cache Cluster with the given config.
        def createSubnetGroup
          subnet_ids = []

          if @config["vpc"] && !@config["vpc"].empty?
            raise MuError, "Didn't find the VPC specified in #{@config["vpc"]}" unless @vpc

            vpc_id = @vpc.cloud_id

            # Getting subnet IDs
            if @config["vpc"]["subnets"].empty?
              @vpc.subnets.each { |subnet|
                subnet_ids << subnet.cloud_id
              }
              MU.log "No subnets specified for #{@config['identifier']}, adding all subnets in #{@vpc}", MU::DEBUG
            else
              @config["vpc"]["subnets"].each { |subnet|
                subnet_obj = @vpc.getSubnet(cloud_id: subnet["subnet_id"], name: subnet["subnet_name"])
                raise MuError, "Couldn't find a live subnet matching #{subnet} in #{@vpc} (#{@vpc.subnets})" if subnet_obj.nil?
                subnet_ids << subnet_obj.cloud_id
              }
            end
          else
            # If we didn't specify a VPC try to figure out if the account has a default VPC
            vpc_id = nil
            subnets = []
            MU::Cloud::AWS.ec2(@config['region']).describe_vpcs.vpcs.each { |vpc|
              if vpc.is_default
                vpc_id = vpc.vpc_id
                subnets = MU::Cloud::AWS.ec2(@config['region']).describe_subnets(
                  filters: [
                    {
                      name: "vpc-id", 
                      values: [vpc_id]
                    }
                  ]
                ).subnets
                break
              end
            }

            if !subnets.empty?
              mu_subnets = []
              subnets.each { |subnet|
                subnet_ids << subnet.subnet_id
                mu_subnets << {"subnet_id" => subnet.subnet_id}
              }

              @config['vpc'] = {
                  "vpc_id" => vpc_id,
                  "subnets" => mu_subnets
              }
              using_default_vpc = true
              MU.log "Using default VPC for cache cluster #{@config['identifier']}"
            end
          end

          if subnet_ids.empty?
            raise MuError, "Can't create subnet group #{@config["subnet_group_name"]} because I couldn't find a VPC or subnets"
          else
            MU.log "Creating subnet group #{@config["subnet_group_name"]} for cache cluster #{@config['identifier']}"

            resp = MU::Cloud::AWS.elasticache(@config['region']).create_cache_subnet_group(
              cache_subnet_group_name: @config["subnet_group_name"],
              cache_subnet_group_description: @config["subnet_group_name"],
              subnet_ids: subnet_ids
            )

            # Find NAT and create holes in security groups.
            # Adding just for consistency, but do we really need this for cache clusters? I guess Nagios and such..
            if @config["vpc"]["nat_host_name"] || @config["vpc"]["nat_host_id"] || @config["vpc"]["nat_host_tag"] || @config["vpc"]["nat_host_ip"]
              nat = @nat
              if nat.is_a?(Struct) && nat.nat_gateway_id && nat.nat_gateway_id.start_with?("nat-")
                MU.log "Using NAT Gateway, not modifying security groups"
              else
                nat_name, nat_conf, nat_deploydata = @nat.describe
                @deploy.kittens['firewall_rules'].each_pair { |name, acl|
  # XXX if a user doesn't set up dependencies correctly, this can die horribly on a NAT that's still in mid-creation. Fix this... possibly in the config parser.
                  if acl.config["admin"]
                    acl.addRule([nat_deploydata["private_ip_address"]], proto: "tcp")
                    acl.addRule([nat_deploydata["private_ip_address"]], proto: "udp")
                    break
                  end
                }
              end
            end

            if @dependencies.has_key?('firewall_rule')
              @config["security_group_ids"] = []
                @dependencies['firewall_rule'].values.each { |sg|
                  @config["security_group_ids"] << sg.cloud_id
              }
            end
          end
        end

        # Create a Cache Cluster parameter group.
        def createParameterGroup        
          MU.log "Creating a cache cluster parameter group #{@config["parameter_group_name"]}"
          resp = MU::Cloud::AWS.elasticache(@config['region']).create_cache_parameter_group(
            cache_parameter_group_name: @config["parameter_group_name"],
            cache_parameter_group_family: @config["parameter_group_family"],
            description: "Parameter group for #{@config["parameter_group_family"]}"
          )

          if @config.has_key?("parameter_group_parameters") && !@config["parameter_group_parameters"].empty?
            params = []
            @config["parameter_group_parameters"].each { |item|
              params << {parameter_name: item['name'], parameter_value: item['value']}
            }

            MU.log "Modifiying cache cluster parameter group #{@config["parameter_group_name"]}"
            MU::Cloud::AWS.elasticache(@config['region']).modify_cache_parameter_group(
              cache_parameter_group_name: @config["parameter_group_name"],
              parameter_name_values: params
            )
          end
        end

        # Set a CloudWatch alarm for this cache cluster.
        # @param cluster_id [String]: The AWS identifier for the cluster to alarm.
        def createAlarm(cluster_id)
          @config["alarms"].each { |alarm|
            alarm["dimensions"] = [{:name => "CacheClusterId", :value => cluster_id}]

            if alarm["enable_notifications"]
              topic_arn = MU::Cloud::AWS::Notification.createTopic(alarm["notification_group"], region: @config["region"])
              MU::Cloud::AWS::Notification.subscribe(arn: topic_arn, protocol: alarm["notification_type"], endpoint: alarm["notification_endpoint"], region: @config["region"])
              alarm["alarm_actions"] = [topic_arn]
              alarm["ok_actions"] = [topic_arn]
            end

            MU::Cloud::AWS::Alarm.createAlarm(
              name: @deploy.getResourceName("#{@config["name"]}-#{alarm["name"]}-#{cluster_id}"),
              ok_actions: alarm["ok_actions"],
              alarm_actions: alarm["alarm_actions"],
              insufficient_data_actions: alarm["no_data_actions"],
              metric_name: alarm["metric_name"],
              namespace: alarm["namespace"],
              statistic: alarm["statistic"],
              dimensions: alarm["dimensions"],
              period: alarm["period"],
              unit: alarm["unit"],
              evaluation_periods: alarm["evaluation_periods"],
              threshold: alarm["threshold"],
              comparison_operator: alarm["comparison_operator"],
              region: @config["region"]
            )
          }
        end

        # Retrieve a Cache Cluster parameter group name of on existing parameter group.
        # @return [String]: Cache Cluster parameter group name.
        def getParameterGroup
          MU::Cloud::AWS.elasticache(@config['region']).describe_cache_parameter_groups(
            cache_parameter_group_name: @config["parameter_group_name"]
          ).cache_parameter_groups.first.cache_parameter_group_name
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          # Do we have anything to do here??
        end

        # Retrieve the complete cloud provider description of a cache cluster.
        # @param cc_id [String]: The cloud provider's identifier for this cache cluster.
        # @param region [String]: The cloud provider's region.
        # @return [OpenStruct]
        def self.getCacheClusterById(cc_id, region: MU.curRegion)
          MU::Cloud::AWS.elasticache(region).describe_cache_clusters(cache_cluster_id: cc_id).cache_clusters.first
        end
        
        # Retrieve the complete cloud provider description of a cache replication group.
        # @param repl_group_id [String]: The cloud provider's identifier for this cache replication group.
        # @param region [String]: The cloud provider's region.
        # @return [OpenStruct]
        def self.getCacheReplicationGroupById(repl_group_id, region: MU.curRegion)
          MU::Cloud::AWS.elasticache(region).describe_replication_groups(replication_group_id: repl_group_id).replication_groups.first
        end

        # Register a description of this cache cluster / cache replication group with this deployment's metadata. 
        def notify
          ### TO DO: Flatten the replication group deployment metadata structure. It is probably waaaaaaay too nested.
          if @config["create_replication_group"]
            repl_group = MU::Cloud::AWS::CacheCluster.getCacheReplicationGroupById(@config['identifier'], region: @config['region'])
            # DNS records for the "real" zone should always be registered as late as possible so override_existing only overwrites the records after the resource is ready to use.
            if @config['dns_records']
              @config['dns_records'].each { |dnsrec|
                dnsrec['name'] = repl_group.node_groups.first.primary_endpoint.address.downcase if !dnsrec.has_key?('name')
                dnsrec['name'] = "#{dnsrec['name']}.#{MU.environment.downcase}" if dnsrec["append_environment_name"] && !dnsrec['name'].match(/\.#{MU.environment.downcase}$/)
              }
            end
            # XXX this should be a call to @deploy.nameKitten
            MU::Cloud::AWS::DNSZone.createRecordsFromConfig(@config['dns_records'], target: repl_group.node_groups.first.primary_endpoint.address)

            deploy_struct = {
              "identifier" => repl_group.replication_group_id,
              "create_style" => @config["create_style"],
              "region" => @config["region"],
              "members" => repl_group.member_clusters,
              "automatic_failover" => repl_group.automatic_failover,
              "snapshotting_cluster_id" => repl_group.snapshotting_cluster_id,
              "primary_endpoint" => repl_group.node_groups.first.primary_endpoint.address,
              "primary_port" => repl_group.node_groups.first.primary_endpoint.port
            }

            repl_group.member_clusters.each { |id|
              cluster = MU::Cloud::AWS::CacheCluster.getCacheClusterById(id, region: @config['region'])

              vpc_sg_ids = []
              cluster.security_groups.each { |vpc_sg|
                vpc_sg_ids << vpc_sg.security_group_id
              }

              cache_sg_ids = []
              unless cluster.cache_security_groups.empty?
                cluster.cache_security_groups.each { |cache_sg|
                  cache_sg_ids << cache_sg.security_group_id
                }
              end

              deploy_struct[id] = {
                "configuration_endpoint" => cluster.configuration_endpoint,
                "cache_node_type" => cluster.cache_node_type,
                "engine" => cluster.engine,
                "engine_version" => cluster.engine_version,
                "num_cache_nodes" => cluster.num_cache_nodes,
                "preferred_maintenance_window" => cluster.preferred_maintenance_window,
                "notification_configuration" => cluster.notification_configuration,
                "cache_security_groups" => cache_sg_ids,
                "cache_parameter_group" => cluster.cache_parameter_group.cache_parameter_group_name,
                "cache_subnet_group_name" => cluster.cache_subnet_group_name,
                "cache_nodes" => cluster.cache_nodes,
                "auto_minor_version_upgrade" => cluster.auto_minor_version_upgrade,
                "vpc_security_groups" => vpc_sg_ids,
                "replication_group_id" => cluster.replication_group_id,
                "snapshot_retention_limit" => cluster.snapshot_retention_limit,
                "snapshot_window" => cluster.snapshot_window              
              }
            }

            repl_group.node_groups.first.node_group_members.each{ |member| 
              deploy_struct[member.cache_cluster_id]["cache_node_id"] = member.cache_node_id
              deploy_struct[member.cache_cluster_id]["read_endpoint_address"] = member.read_endpoint.address
              deploy_struct[member.cache_cluster_id]["read_endpoint_port"] = member.read_endpoint.port
              deploy_struct[member.cache_cluster_id]["current_role"] = member.current_role
            }
          else
            cluster = MU::Cloud::AWS::CacheCluster.getCacheClusterById(@config['identifier'], region: @config['region'])
            vpc_sg_ids = []
            cluster.security_groups.each { |vpc_sg|
              vpc_sg_ids << vpc_sg.security_group_id
            }

            cache_sg_ids = []
            unless cluster.cache_security_groups.empty?
              cluster.cache_security_groups.each { |cache_sg|
                cache_sg_ids << cache_sg.security_group_id
              }
            end

            deploy_struct = {
              "configuration_endpoint_address" => cluster.configuration_endpoint.address,
              "configuration_endpoint_port" => cluster.configuration_endpoint.port,
              "cache_node_type" => cluster.cache_node_type,
              "engine" => cluster.engine,
              "engine_version" => cluster.engine_version,
              "num_cache_nodes" => cluster.num_cache_nodes,
              "preferred_maintenance_window" => cluster.preferred_maintenance_window,
              "notification_configuration" => cluster.notification_configuration,
              "cache_security_groups" => cache_sg_ids,
              "cache_parameter_group" => cluster.cache_parameter_group.cache_parameter_group_name,
              "cache_subnet_group_name" => cluster.cache_subnet_group_name,
              "cache_nodes" => cluster.cache_nodes,
              "auto_minor_version_upgrade" => cluster.auto_minor_version_upgrade,
              "vpc_security_groups" => vpc_sg_ids,
              "replication_group_id" => cluster.replication_group_id,
              "snapshot_retention_limit" => cluster.snapshot_retention_limit,
              "snapshot_window" => cluster.snapshot_window              
            }
          end

          return deploy_struct
        end

        # Generate a snapshot from the Cache Cluster described in this instance.
        # @return [String]: The cloud provider's identifier for the snapshot.
        def createNewSnapshot
          snap_id = @deploy.getResourceName(@config["name"]) + Time.new.strftime("%M%S").to_s

          attempts = 0
          begin
           snapshot = MU::Cloud::AWS.elasticache(@config['region']).create_snapshot(
              cache_cluster_id: @config["identifier"],
              snapshot_name: snap_id
            )
          rescue Aws::ElastiCache::Errors::InvalidCacheClusterState => e
            if attempts < 10
              MU.log "Tried to create snapshot for #{@config["identifier"]} but cache cluster is busy, retrying a few times"
              attempts += 1
              sleep 30
              retry
            else
              raise MuError, "Failed to create snpashot for cache cluster #{@config["identifier"]}: #{e.inspect}"
            end
          end
          
          attempts = 0
          loop do
            MU.log "Waiting for snapshot of cache cluster  #{@config["identifier"]} to be ready...", MU::NOTICE if attempts % 20 == 0
            MU.log "Waiting for snapshot of cache cluster #{@config["identifier"]} to be ready...", MU::DEBUG

            snapshot_resp = MU::Cloud::AWS.elasticache(@config['region']).describe_snapshots(snapshot_name: snap_id)
            attempts += 1
            break unless snapshot_resp.snapshots.first.snapshot_status != "available"
            sleep 15
          end

          return snap_id
        end

        # @return [String]: The cloud provider's identifier for the snapshot.
        def getExistingSnapshot
          MU::Cloud::AWS.elasticache(@config['region']).describe_snapshots(snapshot_name: @config["identifier"]).snapshots.first.snapshot_name
        rescue NoMethodError
          raise MuError, "Snapshot #{@config["identifier"]} doesn't exist, make sure you provided a valid snapshot ID/Name"
        end

        # Called by {MU::Cleanup}. Locates resources that were created by the currently-loaded deployment and purges them.
        # @param noop [Boolean]: If true, will only print what would be done.
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server.
        # @param region [String]: The cloud provider's region in which to operate.
        # @return [void]
        def self.cleanup(skipsnapshots: false, noop: false, ignoremaster: false, region: MU.curRegion, flags: {})        
          all_clusters = MU::Cloud::AWS.elasticache(region).describe_cache_clusters
          our_clusters = []
          our_replication_group_ids = []

          # Because we can't run list_tags_for_resource on a cache cluster that isn't in "available" state we're loading the deploy to make sure we have a cache cluster to cleanup.
          # To ensure we don't miss cache clusters that have been terminated mid creation we'll load the 'original_config'. We might want to find a better approach for this.
          deploy = MU::MommaCat.getLitter(MU.deploy_id)
          if deploy.original_config && deploy.original_config.has_key?("cache_clusters") && !deploy.original_config["cache_clusters"].empty?

            # The ElastiCache API and documentation are a mess, the replication group ARN resource_type is not documented, and is not easily guessable.
            # So instead of searching for replication groups directly we'll get their IDs from the cache clusters.
            all_clusters.cache_clusters.each { |cluster|
              cluster_id = cluster.cache_cluster_id

              # ElastiCache API is buggy... It will throw a CacheClusterNotFound if we run list_tags_for_resource on a cahe cluster that isn't in an "available" state.
              if cluster.cache_cluster_status != "available"
                if %w{deleting deleted}.include?(cluster.cache_cluster_status)
                  # The cahe cluster might not be ours so don't notify us about it.
                  next
                else
                  # We can replace this with an AWS waiter.
                  loop do
                    MU.log "Waiting for #{cluster_id} to be in a removable state", MU::NOTICE
                    cluster = MU::Cloud::AWS::CacheCluster.getCacheClusterById(cluster_id, region: region)
                    break unless %w{creating modifying backing-up}.include?(cluster.cache_cluster_status)
                    sleep 60
                  end
                end
              end

              arn = MU::Cloud::AWS::CacheCluster.getARN(cluster_id, "cluster", "elasticache", region: region)
              attempts = 0

              begin
                tags = MU::Cloud::AWS.elasticache(region).list_tags_for_resource(resource_name: arn).tag_list
              rescue Aws::ElastiCache::Errors::CacheClusterNotFound => e
                if attempts < 10
                  MU.log "Can't get tags for #{cluster_id}, retrying a few times in case of a lagging resource", MU::WARN
                  MU.log "arn #{arn}", MU::WARN
                  attempts += 1
                  sleep 30
                  retry
                else
                  raise MuError, "Failed to get tags for cache cluster #{cluster_id}, MU-ID #{MU.deploy_id}: #{e.inspect}"
                end
              end

              found_muid = false
              found_master = false
              tags.each { |tag|
                found_muid = true if tag.key == "MU-ID" && tag.value == MU.deploy_id
                found_master = true if tag.key == "MU-MASTER-IP" && tag.value == MU.mu_public_ip
              }
              next if !found_muid

              delete =
                if ignoremaster && found_muid
                  true
                elsif !ignoremaster && found_muid && found_master
                  true
                else
                  false
                end

              if delete
                cluster.replication_group_id ? our_replication_group_ids << cluster.replication_group_id : our_clusters << cluster
              end
            }

            threads = []

            # Make sure we have only uniqe replication group IDs
            our_replication_group_ids = our_replication_group_ids.uniq
            if !our_replication_group_ids.empty?
              our_replication_group_ids.each { |group_id|
                replication_group = MU::Cloud::AWS::CacheCluster.getCacheReplicationGroupById(group_id, region: region)
                parent_thread_id = Thread.current.object_id
                threads << Thread.new(replication_group) { |myrepl_group|
                  MU.dupGlobals(parent_thread_id)
                  Thread.abort_on_exception = true
                  MU::Cloud::AWS::CacheCluster.terminate_replication_group(myrepl_group, noop, skipsnapshots, region: region, deploy_id: MU.deploy_id, cloud_id: myrepl_group.replication_group_id)
                }
              }
            end

            # Hmmmm. Do we need to have seperate thread groups for clusters and replication groups?
            if !our_clusters.empty?
              our_clusters.each { |cluster|
                parent_thread_id = Thread.current.object_id
                threads << Thread.new(cluster) { |mycluster|
                  MU.dupGlobals(parent_thread_id)
                  Thread.abort_on_exception = true
                  MU::Cloud::AWS::CacheCluster.terminate_cache_cluster(mycluster, noop, skipsnapshots, region: region, deploy_id: MU.deploy_id, cloud_id: mycluster.cache_cluster_id)
                }
              }
            end

            # Wait for all of the cache cluster  and replication groups to finish cleanup before proceeding
            threads.each { |t|
              t.join
            }
          end
        end

        private

        # Remove a Cache Cluster and associated artifacts
        # @param cluster [OpenStruct]: The cloud provider's description of the Cache Cluster artifact.
        # @param noop [Boolean]: If true, will only print what would be done.
        # @param skipsnapshots [Boolean]: If true, will not create a last snapshot before terminating the Cache Cluster.
        # @param region [String]: The cloud provider's region in which to operate.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @return [void]
        def self.terminate_cache_cluster(cluster, noop = false, skipsnapshots = false, region: MU.curRegion, deploy_id: MU.deploy_id, mu_name: nil, cloud_id: nil)
          raise MuError, "terminate_cache_cluster requires a non-nil cache cluster descriptor" if cluster.nil? || cluster.empty?

          cluster_id = cluster.cache_cluster_id
          subnet_group = cluster.cache_subnet_group_name
          parameter_group = cluster.cache_parameter_group.cache_parameter_group_name

          # hmmmmm we can use an AWS waiter for this...
          unless cluster.cache_cluster_status == "available"
            loop do
              MU.log "Waiting for #{cluster_id} to be in a removable state...", MU::NOTICE
              cluster = MU::Cloud::AWS::CacheCluster.getCacheClusterById(cluster_id, region: region)
              break unless %w{creating modifying backing-up}.include?(cluster.cache_cluster_status)
              sleep 60
            end
          end

          # The API is broken, cluster.cache_nodes is returnning an empty array, and the only URL we can get is the config one with cluster.configuration_endpoint.address.
          # MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: cluster_id, target: , cloudclass: MU::Cloud::CacheCluster, delete: true)
          
          if %w{deleting deleted}.include?(cluster.cache_cluster_status)
            MU.log "#{cluster_id} has already been terminated", MU::WARN
          else          
            unless noop
              def self.clusterSkipSnap(cluster_id, region)
                # We're calling this several times so lets declare it once
                MU.log "Terminating #{cluster_id}. Not saving final snapshot"
                MU::Cloud::AWS.elasticache(region).delete_cache_cluster(cache_cluster_id: cluster_id)
              end

              def self.clusterCreateSnap(cluster_id, region)
                MU.log "Terminating #{cluster_id}. Final snapshot name: #{cluster_id}-mufinal"
                MU::Cloud::AWS.elasticache(region).delete_cache_cluster(cache_cluster_id: cluster_id, final_snapshot_identifier: "#{cluster_id}-MUfinal")
              end

              retries = 0
              begin
                if cluster.engine == "memcached"
                  clusterSkipSnap(cluster_id, region)
                else
                  skipsnapshots ? clusterSkipSnap(cluster_id, region) : clusterCreateSnap(cluster_id, region)
                end
              rescue Aws::ElastiCache::Errors::InvalidCacheClusterState => e
                if retries < 5
                  MU.log "#{cluster_id} is not in a removable state, retrying several times", MU::WARN
                  retries += 1
                  sleep 30
                  retry
                else
                  MU.log "#{cluster_id} is not in a removable state after several retries, giving up. #{e.inspect}", MU::ERR
                  return
                end
              rescue Aws::ElastiCache::Errors::SnapshotAlreadyExistsFault
                MU.log "Snapshot #{cluster_id}-MUfinal already exists", MU::WARN
                clusterSkipSnap(cluster_id, region)
              rescue Aws::ElastiCache::Errors::SnapshotQuotaExceededFault
                MU.log "Snapshot quota exceeded while deleting #{cluster_id}", MU::ERR
                clusterSkipSnap(cluster_id, region)
              end

              wait_start_time = Time.now
              retries = 0
              begin
                MU::Cloud::AWS.elasticache(region).wait_until(:cache_cluster_deleted, cache_cluster_id: cluster_id) do |waiter|
                  waiter.max_attempts = nil
                  waiter.before_attempt do |attempts|
                    MU.log "Waiting for cache cluster #{cluster_id} to delete..", MU::NOTICE if attempts % 10 == 0
                  end
                  waiter.before_wait do |attempts, resp|
                    throw :success if resp.cache_clusters.first.cache_cluster_status  == "deleted"
                    throw :failure if Time.now - wait_start_time > 1800
                  end
                end
              rescue Aws::Waiters::Errors::TooManyAttemptsError => e
                raise MuError, "Waited for #{(Time.now - wait_start_time).round/60*(retries+1)} minutes for cache cluster to delete, giving up. #{e}" if retries > 2
                wait_start_time = Time.now
                retries += 1
                retry
              rescue Aws::Waiters::Errors::FailureStateError
                MU.log "#{cluster_id} disappeared on us"
              end
            end
          end

          MU.log "#{cluster_id} has been terminated"

          unless noop
            MU::Cloud::AWS::CacheCluster.delete_subnet_group(subnet_group, region: region) if subnet_group
            MU::Cloud::AWS::CacheCluster.delete_parameter_group(parameter_group, region: region) if parameter_group && !parameter_group.start_with?("default")
          end
        end

        # Remove a Cache Cluster Replication Group and associated artifacts
        # @param repl_group [OpenStruct]: The cloud provider's description of the Cache Cluster artifact.
        # @param noop [Boolean]: If true, will only print what would be done.
        # @param skipsnapshots [Boolean]: If true, will not create a last snapshot before terminating the Cache Cluster.
        # @param region [String]: The cloud provider's region in which to operate.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @return [void]
        def self.terminate_replication_group(repl_group, noop = false, skipsnapshots = false, region: MU.curRegion, deploy_id: MU.deploy_id, mu_name: nil, cloud_id: nil)
          raise MuError, "terminate_replication_group requires a non-nil cache replication group descriptor" if repl_group.nil? || repl_group.empty?

          repl_group_id = repl_group.replication_group_id
          # We're assuming that all clusters in this replication group where created in the same deployment so have the same subnet group, parameter group, etc...
          cluster_id = repl_group.member_clusters.first
          cluster = MU::Cloud::AWS::CacheCluster.getCacheClusterById(cluster_id, region: region)
          subnet_group = cluster.cache_subnet_group_name
          parameter_group = cluster.cache_parameter_group.cache_parameter_group_name

          # hmmmmm we can use an AWS waiter for this...
          unless repl_group.status == "available"
            loop do
              MU.log "Waiting for #{repl_group_id} to be in a removable state...", MU::NOTICE
              repl_group = MU::Cloud::AWS::CacheCluster.getCacheReplicationGroupById(repl_group_id, region: region)
              break unless %w{creating modifying backing-up}.include?(repl_group.status)
              sleep 60
            end
          end

          # What's the likelihood of having more than one node group? maybe iterate over node_groups instead of assuming there is only one?
          MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: repl_group_id, target: repl_group.node_groups.first.primary_endpoint.address, cloudclass: MU::Cloud::CacheCluster, delete: true)
          # Assuming we also created DNS records for each of our cluster's read endpoint.
          repl_group.node_groups.first.node_group_members.each { |member|
            MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: member.cache_cluster_id, target: member.read_endpoint.address, cloudclass: MU::Cloud::CacheCluster, delete: true)
          }
          
          if %w{deleting deleted}.include?(repl_group.status)
            MU.log "#{repl_group_id} has already been terminated", MU::WARN
          else
            unless noop
              def self.skipSnap(repl_group_id, region)
                # We're calling this several times so lets declare it once
                MU.log "Terminating #{repl_group_id}. Not saving final snapshot"
                MU::Cloud::AWS.elasticache(region).delete_replication_group(
                  replication_group_id: repl_group_id,
                  retain_primary_cluster: false
                )
              end

              def self.createSnap(repl_group_id, region)
                MU.log "Terminating #{repl_group_id}. Final snapshot name: #{repl_group_id}-mufinal"
                MU::Cloud::AWS.elasticache(region).delete_replication_group(
                  replication_group_id: repl_group_id,
                  retain_primary_cluster: false,
                  final_snapshot_identifier: "#{repl_group_id}-mufinal"
                )
              end

              retries = 0
              begin
                skipsnapshots ? skipSnap(repl_group_id, region) : createSnap(repl_group_id, region)
              rescue Aws::ElastiCache::Errors::InvalidReplicationGroupState => e
                if retries < 5
                  MU.log "#{repl_group_id} is not in a removable state, retrying several times", MU::WARN
                  retries += 1
                  sleep 30
                  retry
                else
                  MU.log "#{repl_group_id} is not in a removable state after several retries, giving up. #{e.inspect}", MU::ERR
                  return
                end
              rescue Aws::ElastiCache::Errors::SnapshotAlreadyExistsFault
                MU.log "Snapshot #{repl_group_id}-MUfinal already exists", MU::WARN
                skipSnap(repl_group_id, region)
              rescue Aws::ElastiCache::Errors::SnapshotQuotaExceededFault
                MU.log "Snapshot quota exceeded while deleting #{repl_group_id}", MU::ERR
                skipSnap(repl_group_id, region)
              end

              wait_start_time = Time.now
              retries = 0
              begin
                MU::Cloud::AWS.elasticache(region).wait_until(:replication_group_deleted, replication_group_id: repl_group_id) do |waiter|
                  waiter.max_attempts = nil
                  waiter.before_attempt do |attempts|
                    MU.log "Waiting for #{repl_group_id} to delete..", MU::NOTICE if attempts % 10 == 0
                  end
                  waiter.before_wait do |attempts, resp|
                    throw :success if resp.replication_groups.first.status == "deleted"
                    throw :failure if Time.now - wait_start_time > 1800
                  end
                end
              rescue Aws::Waiters::Errors::TooManyAttemptsError => e
                raise MuError, "Waited for #{(Time.now - wait_start_time).round/60*(retries+1)} minutes for #{repl_group_id} to delete, giving up. #{e}" if retries > 2
                wait_start_time = Time.now
                retries += 1
                retry
              rescue Aws::Waiters::Errors::FailureStateError
                MU.log "#{repl_group_id} disappeared on us"
              end
            end
          end

          MU.log "#{repl_group_id} has been terminated"
          unless noop
            MU::Cloud::AWS::CacheCluster.delete_subnet_group(subnet_group, region: region) if subnet_group
            MU::Cloud::AWS::CacheCluster.delete_parameter_group(parameter_group, region: region) if parameter_group && !parameter_group.start_with?("default")
          end
        end

        # Remove a Cache Cluster Subnet Group.
        # @param subnet_group_id [string]: The cloud provider's ID of the cache cluster subnet group.
        # @param region [String]: The cloud provider's region in which to operate.
        # @return [void]
        def self.delete_subnet_group(subnet_group_id, region: MU.curRegion)
          retries ||= 0
          MU.log "Deleting Subnet group #{subnet_group_id}"
          MU::Cloud::AWS.elasticache(region).delete_cache_subnet_group(cache_subnet_group_name: subnet_group_id)
        rescue Aws::ElastiCache::Errors::CacheSubnetGroupNotFoundFault
          MU.log "Subnet group #{subnet_group_id} disappeared before we could remove it", MU::WARN
        rescue Aws::ElastiCache::Errors::CacheSubnetGroupInUse => e
          if retries < 5
            MU.log "Subnet group #{subnet_group_id} is not in a removable state, retrying", MU::WARN
            retries += 1
            sleep 30
            retry
          else
            MU.log "Subnet group #{subnet_group_id} is not in a removable state after several retries, giving up. #{e.inspect}", MU::ERR
          end
        end

        # Remove a Cache Cluster Parameter Group.
        # @param parameter_group_id [string]: The cloud provider's ID of the cache cluster parameter group.
        # @param region [String]: The cloud provider's region in which to operate.
        # @return [void]
        def self.delete_parameter_group(parameter_group_id, region: MU.curRegion)
          retries ||= 0
          MU.log "Deleting parameter group #{parameter_group_id}"
          MU::Cloud::AWS.elasticache(region).delete_cache_parameter_group(
            cache_parameter_group_name: parameter_group_id
          )
        rescue Aws::ElastiCache::Errors::CacheParameterGroupNotFound
          MU.log "Parameter group #{parameter_group_id} disappeared before we could remove it", MU::WARN
        rescue Aws::ElastiCache::Errors::InvalidCacheParameterGroupState => e
          if retries < 5
            MU.log "Parameter group #{parameter_group_id} is not in a removable state, retrying", MU::WARN
            retries += 1
            sleep 30
            retry
          else
            MU.log "Parameter group #{parameter_group_id} is not in a removable state after several retries, giving up. #{e.inspect}", MU::ERR
          end
        end
      end
    end
  end
end
