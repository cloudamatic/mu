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

autoload :Net, 'net/ssh/gateway'

module MU
  class Cloud
    class AWS
      # A database as configured in {MU::Config::BasketofKittens::databases}
      class Database < MU::Cloud::Database
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :cloud_id
        attr_reader :config
        attr_reader :groomer    

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::databases}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          # @mu_name = mu_name ? mu_name : @deploy.getResourceName(@config["name"])
          @config["groomer"] = MU::Config.defaultGroomer unless @config["groomer"]
          @groomclass = MU::Groomer.loadGroomer(@config["groomer"])

          @mu_name ||=
            if @config["engine"].match(/^sqlserver/)
              @deploy.getResourceName(@config["name"], max_length: 15)
            else
              @deploy.getResourceName(@config["name"], max_length: 63)
            end

          @mu_name.gsub(/(--|-$)/i, "").gsub(/(_)/, "-").gsub!(/^[^a-z]/i, "")
        end

        # Called automatically by {MU::Deploy#createResources}
        # @return [String]: The cloud provider's identifier for this database instance.
        def create
          # RDS is picky, we can't just use our regular node names for things like
          # the default schema or username. And it varies from engine to engine.
          basename = @config["name"]+@deploy.timestamp+MU.seed.downcase
          basename.gsub!(/[^a-z0-9]/i, "")
          @config["db_name"] = getName(basename, type: "dbname")
          @config['master_user'] = getName(basename, type: "dbuser") unless @config['master_user']

          # Lets make sure automatic backups are enabled when DB instance is deployed in Multi-AZ so failover actually works. Maybe default to 1 instead?
          if @config['multi_az_on_create'] or @config['multi_az_on_deploy'] or config["create_cluster"]
            if @config["backup_retention_period"].nil? or @config["backup_retention_period"] == 0
              @config["backup_retention_period"] = 35
              MU.log "Multi-AZ deployment specified but backup retention period disabled or set to 0. Changing to #{@config["backup_retention_period"]} ", MU::WARN
            end

            if @config["preferred_backup_window"].nil?
              @config["preferred_backup_window"] = "05:00-05:30"
              MU.log "Multi-AZ deployment specified but no backup window specified. Changing to #{@config["preferred_backup_window"]} ", MU::WARN
            end
          end

          @config["snapshot_id"] =
            if @config["creation_style"] == "existing_snapshot"
              getExistingSnapshot ? getExistingSnapshot : createNewSnapshot
            elsif @config["creation_style"] == "new_snapshot"
              createNewSnapshot
            end

          @config['source_identifier'] = @config['identifier'] if @config["creation_style"] == "point_in_time"
          @config['identifier'] = @mu_name
          @config["subnet_group_name"] = @mu_name

          if config["create_cluster"]
            getPassword
            createSubnetGroup

            if @config.has_key?("parameter_group_family")
              @config["parameter_group_name"] = @config['identifier']
              createDBClusterParameterGroup
            end

            @cloud_id = createDbCluster
          elsif @config["add_cluster_node"]
            cluster = nil
            rr = @config["member_of_cluster"]
            cluster = @deploy.findLitterMate(type: "database", name: rr['db_name']) if rr['db_name']

            if cluster.nil?
              tag_key, tag_value = rr['tag'].split(/=/, 2) if !rr['tag'].nil?
              found = MU::MommaCat.findStray(
                rr['cloud'],
                "database",
                deploy_id: rr["deploy_id"],
                cloud_id: rr["db_id"],
                tag_key: tag_key,
                tag_value: tag_value,
                region: rr["region"],
                dummy_ok: true
              )
              cluster = found.first if found.size == 1
            end

            raise MuError, "Couldn't resolve cluster node reference to a unique live Database in #{@mu_name}" if cluster.nil? || cluster.cloud_id.nil?
            @config['cluster_identifier'] = cluster.cloud_id.downcase
            # We're overriding @config["subnet_group_name"] because we need each cluster member to use the cluster's subnet group instead of a unique subnet group
            @config["subnet_group_name"] = @config['cluster_identifier']
            @config["creation_style"] = "new" if @config["creation_style"] != "new"

            if @config.has_key?("parameter_group_family")
              @config["parameter_group_name"] = @config['identifier']
              createDBParameterGroup
            end

            @cloud_id = createDb
          else
            source_db = nil
            if @config['read_replica_of']
              rr = @config['read_replica_of']
              source_db = @deploy.findLitterMate(type: "database", name: rr['db_name']) if rr['db_name']

              if source_db.nil?
                tag_key, tag_value = rr['tag'].split(/=/, 2) if !rr['tag'].nil?
                found = MU::MommaCat.findStray(
                    rr['cloud'],
                    "database",
                    deploy_id: rr["deploy_id"],
                    cloud_id: rr["db_id"],
                    tag_key: tag_key,
                    tag_value: tag_value,
                    region: rr["region"],
                    dummy_ok: true
                )
                source_db = found.first if found.size == 1
              end

              raise MuError, "Couldn't resolve read replica reference to a unique live Database in #{@mu_name}" if source_db.nil? or source_db.cloud_id.nil?
              @config['source_identifier'] = source_db.cloud_id
            end

            getPassword
            createSubnetGroup if source_db.nil? or @config['region'] != source_db.config['region']

            if @config.has_key?("parameter_group_family")
              @config["parameter_group_name"] = @config['identifier']
              createDBParameterGroup
            end

            @cloud_id = createDb
          end
        end

        # Locate an existing Database or Databases and return an array containing matching AWS resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching Databases
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil)
          map = {}
          if cloud_id
            db = MU::Cloud::AWS::Database.getDatabaseById(cloud_id, region: region)
            map[cloud_id] = db if db
          end

          if tag_value
            MU::Cloud::AWS.rds(region).describe_db_instances.db_instances.each { |db|
              resp = MU::Cloud::AWS.rds(region).list_tags_for_resource(
                  resource_name: MU::Cloud::AWS::Database.getARN(db.db_instance_identifier, "db", "rds", region: region)
              )
              if resp && resp.tag_list && !resp.tag_list.empty?
                resp.tag_list.each { |tag|
                  map[db.db_instance_identifier] = db if tag.key == tag_key and tag.value == tag_value
                }
              end
            }
          end

          return map
        end

        # Construct an Amazon Resource Name for an RDS resource. The RDS API is
        # peculiar, and we often need this identifier in order to do things that
        # the other APIs can do with shorthand.
        # @param resource [String]: The name of the resource
        # @param resource_type [String]: The type of the resource (one of `db, es, og, pg, ri, secgrp, snapshot, subgrp`)
        # @param client_type [String]: The name of the client (eg. elasticache, rds, ec2, s3)
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

        # Add our standard tag set to an Amazon RDS resource.
        # @param resource [String]: The name of the resource
        # @param resource_type [String]: The type of the resource (one of `db, es, og, pg, ri, secgrp, snapshot, subgrp`)
        # @param region [String]: The cloud provider region
        def addStandardTags(resource, resource_type, region: MU.curRegion)
          MU.log "Adding tags to RDS resource #{resource}: #{allTags}"
          MU::Cloud::AWS.rds(region).add_tags_to_resource(
              resource_name: MU::Cloud::AWS::Database.getARN(resource, resource_type, "rds", region: region),
              tags: allTags
          )
        end

        # Getting the password for the master user, and saving it in a database / cluster specif vault
        def getPassword
          if @config['password'].nil?
            if @config['auth_vault'] && !@config['auth_vault'].empty?
              @config['password'] = @groomclass.getSecret(
                vault: @config['auth_vault']['vault'],
                item: @config['auth_vault']['item'],
                field: @config['auth_vault']['password_field']
              )
            else
              # Should we use random instead?
              @config['password'] = Password.pronounceable(10..12)
            end
          end

          creds = {
            "username" => @config["master_user"],
            "password" => @config["password"]
          }
          @groomclass.saveSecret(vault: @config['identifier'], item: "database_credentials", data: creds)
        end

        # Create the database described in this instance
        # @return [String]: The cloud provider's identifier for this database instance.
        def createDb
          # Shared configuration elements between most database creation styles
          config = {
            db_instance_identifier: @config['identifier'],
            db_instance_class: @config["size"],
            engine: @config["engine"],
            auto_minor_version_upgrade: @config["auto_minor_version_upgrade"],
            license_model: @config["license_model"],
            db_subnet_group_name: @config["subnet_group_name"],
            publicly_accessible: @config["publicly_accessible"],
            copy_tags_to_snapshot: true,
            tags: allTags
          }

          unless @config["add_cluster_node"]
            config[:storage_type] = @config["storage_type"] 
            config[:port] = @config["port"] if @config["port"]
            config[:iops] = @config["iops"] if @config['storage_type'] == "io1"
            config[:multi_az] = @config['multi_az_on_create']
          end

          if @config["creation_style"] == "new"
            unless @config["add_cluster_node"]
              config[:preferred_backup_window] = @config["preferred_backup_window"]
              config[:backup_retention_period] = @config["backup_retention_period"]
              config[:storage_encrypted] = @config["storage_encrypted"]
              config[:allocated_storage] = @config["storage"]
              config[:db_name] = @config["db_name"]
              config[:master_username] = @config['master_user']
              config[:master_user_password] = @config['password']
              config[:vpc_security_group_ids] = @config["vpc_security_group_ids"]
            end

            config[:engine_version] = @config["engine_version"]
            config[:preferred_maintenance_window] = @config["preferred_maintenance_window"] if @config["preferred_maintenance_window"]
            config[:db_parameter_group_name] = @config["parameter_group_name"] if @config["parameter_group_name"]
            config[:db_cluster_identifier] = @config["cluster_identifier"] if @config["add_cluster_node"]
          end
          
          if %w{existing_snapshot new_snapshot}.include?(@config["creation_style"])
            config[:db_snapshot_identifier] = @config["snapshot_id"]
          end

          if @config["creation_style"] == "point_in_time"
            point_in_time_config = config
            point_in_time_config.delete(:db_instance_identifier)
            point_in_time_config[:source_db_instance_identifier] = @config['source_identifier']
            point_in_time_config[:target_db_instance_identifier] = @config['identifier']
            point_in_time_config[:restore_time] = @config['restore_time'] unless @config["restore_time"] == "latest"
            point_in_time_config[:use_latest_restorable_time] = true if @config['restore_time'] == "latest"
          end

          if @config["read_replica_of"] || @config["create_read_replica"]
            read_replica_struct = {
              db_instance_identifier: @config['identifier'],
              source_db_instance_identifier: @config['source_identifier'],
              db_instance_class: @config["size"],
              auto_minor_version_upgrade: @config["auto_minor_version_upgrade"],
              publicly_accessible: @config["publicly_accessible"],
              tags: allTags,
              db_subnet_group_name: @config["subnet_group_name"],
              storage_type: @config["storage_type"]
            }

            read_replica_struct[:port] = @config["port"] if @config["port"]
            read_replica_struct[:iops] = @config["iops"] if @config['storage_type'] == "io1"
          end

          # Creating DB instance
          attempts = 0

          begin
            if %w{existing_snapshot new_snapshot}.include?(@config["creation_style"])
              MU.log "Creating database instance #{@config['identifier']} from snapshot #{@config["snapshot_id"]}"
              resp = MU::Cloud::AWS.rds(@config['region']).restore_db_instance_from_db_snapshot(config)
            elsif @config["creation_style"] == "point_in_time"
              MU.log "Creating database instance #{@config['identifier']} based on point in time backup #{@config['restore_time']} of #{@config['source_identifier']}"
              resp = MU::Cloud::AWS.rds(@config['region']).restore_db_instance_to_point_in_time(point_in_time_config)
            elsif @config["read_replica_of"]
              MU.log "Creating read replica database instance #{@config['identifier']} for #{@config['source_identifier']}"
              begin
                resp = MU::Cloud::AWS.rds(@config['region']).create_db_instance_read_replica(read_replica_struct)
              rescue Aws::RDS::Errors::DBSubnetGroupNotAllowedFault
                read_replica_struct.delete(:db_subnet_group_name)
                resp = MU::Cloud::AWS.rds(@config['region']).create_db_instance_read_replica(read_replica_struct)
              end
            else
              MU.log "Creating database instance #{@config['identifier']}"
              resp = MU::Cloud::AWS.rds(@config['region']).create_db_instance(config)
            end
          rescue Aws::RDS::Errors::InvalidParameterValue => e
            if attempts < 5
              MU.log "Got #{e.inspect} creating #{@config['identifier']}, will retry a few times in case of transient errors.", MU::WARN
              attempts += 1
              sleep 10
              retry
            else
              raise MuError, "Exhausted retries trying to create database instance #{@config['identifier']}: e.inspect"
            end
          end

          wait_start_time = Time.now
          retries = 0

          begin
            MU::Cloud::AWS.rds(@config['region']).wait_until(:db_instance_available, db_instance_identifier: @config['identifier']) do |waiter|
              # Does create_db_instance implement wait_until_available ?
              waiter.max_attempts = nil
              waiter.before_attempt do |attempts|
                MU.log "Waiting for RDS database #{@config['identifier']} to be ready..", MU::NOTICE if attempts % 10 == 0
              end
              waiter.before_wait do |attempts, resp|
                throw :success if resp.db_instances.first.db_instance_status == "available"
                throw :failure if Time.now - wait_start_time > 3600
              end
            end
          rescue Aws::Waiters::Errors::TooManyAttemptsError => e
            raise MuError, "Waited #{(Time.now - wait_start_time).round/60*(retries+1)} minutes for #{@config['identifier']} to become available, giving up. #{e}" if retries > 2
            wait_start_time = Time.now
            retries += 1
            retry
          end

          database = MU::Cloud::AWS::Database.getDatabaseById(@config['identifier'], region: @config['region'])
          MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: database.db_instance_identifier, target: "#{database.endpoint.address}.", cloudclass: MU::Cloud::Database, sync_wait: @config['dns_sync_wait'])

          if @config["alarms"] && !@config["alarms"].empty?
            @config["alarms"].each { |alarm|
              alarm["dimensions"] = [{:name => "DBInstanceIdentifier", :value => database.db_instance_identifier}]

              if alarm["enable_notifications"]
                topic_arn = MU::Cloud::AWS::Notification.createTopic(alarm["notification_group"], region: @config["region"])
                MU::Cloud::AWS::Notification.subscribe(arn: topic_arn, protocol: alarm["notification_type"], endpoint: alarm["notification_endpoint"], region: @config["region"])
                alarm["alarm_actions"] = [topic_arn]
                alarm["ok_actions"] = [topic_arn]
              end

              MU::Cloud::AWS::Alarm.createAlarm(
                name: @deploy.getResourceName("#{@config["name"]}-#{alarm["name"]}"),
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

          # When creating from a snapshot, some of the create arguments aren't
          # applicable- but we can apply them after the fact with a modify.
          if %w{existing_snapshot new_snapshot point_in_time}.include?(@config["creation_style"])
            mod_config = Hash.new
            mod_config[:db_instance_identifier] = database.db_instance_identifier
            mod_config[:preferred_backup_window] = @config["preferred_backup_window"]
            mod_config[:backup_retention_period] = @config["backup_retention_period"]
            mod_config[:preferred_maintenance_window] = @config["preferred_maintenance_window"] if @config["preferred_maintenance_window"]
            mod_config[:engine_version] = @config["engine_version"]
            mod_config[:allow_major_version_upgrade] = @config["allow_major_version_upgrade"] if @config['allow_major_version_upgrade']
            mod_config[:apply_immediately] = true
            mod_config[:db_parameter_group_name] = @config["parameter_group_name"] if @config["parameter_group_name"]
            mod_config[:master_user_password] = @config['password']
            mod_config[:allocated_storage] = @config["storage"] if @config["storage"]
            mod_config[:vpc_security_group_ids] = @config["vpc_security_group_ids"]

            MU::Cloud::AWS.rds(@config['region']).modify_db_instance(mod_config)
            wait_start_time = Time.now
            retries = 0

            begin
              MU::Cloud::AWS.rds(@config['region']).wait_until(:db_instance_available, db_instance_identifier: @config['identifier']) do |waiter|
                # Does create_db_instance implement wait_until_available ?
                waiter.max_attempts = nil
                waiter.before_attempt do |attempts|
                  MU.log "Waiting for RDS database #{@config['identifier'] } to be ready..", MU::NOTICE if attempts % 10 == 0
                end
                waiter.before_wait do |attempts, resp|
                  throw :success if resp.db_instances.first.db_instance_status == "available"
                  throw :failure if Time.now - wait_start_time > 2400
                end
              end
            rescue Aws::Waiters::Errors::TooManyAttemptsError => e
              raise MuError, "Waited #{(Time.now - wait_start_time).round/60*(retries+1)} minutes for #{@config['identifier']} to become available, giving up. #{e}" if retries > 2
              wait_start_time = Time.now
              retries += 1
              retry
            end
          end

          # Maybe wait for DB instance to be in available state. DB should still be writeable at this state
          if @config['allow_major_version_upgrade'] && @config["creation_style"] == "new"
            MU.log "Setting major database version upgrade on #{@config['identifier']}'"
            MU::Cloud::AWS.rds(@config['region']).modify_db_instance(
              db_instance_identifier: @config['identifier'],
              apply_immediately: true,
              allow_major_version_upgrade: true
            )
          end

          MU.log "Database #{@config['identifier']} is ready to use"
          return database.db_instance_identifier
        end

        # Create the database cluster described in this instance
        # @return [String]: The cloud provider's identifier for this database cluster.
        def createDbCluster
          cluster_config_struct = {
            db_cluster_identifier: @config['identifier'],
            # downcasing @config["subnet_group_name"] becuase the API is choking on upper case.
            db_subnet_group_name: @config["subnet_group_name"].downcase,
            vpc_security_group_ids: @config["vpc_security_group_ids"],
            tags: allTags
          }
          cluster_config_struct[:port] = @config["port"] if @config["port"]

          if %w{existing_snapshot new_snapshot}.include?(@config["creation_style"])
            cluster_config_struct[:snapshot_identifier] = @config["snapshot_id"]
            cluster_config_struct[:engine] = @config["engine"]
            cluster_config_struct[:engine_version] = @config["engine_version"]
            cluster_config_struct[:database_name] = @config["db_name"]
          end

          if @config["creation_style"] == "new"
            cluster_config_struct[:backup_retention_period] = @config["backup_retention_period"]
            cluster_config_struct[:database_name] = @config["db_name"]
            cluster_config_struct[:db_cluster_parameter_group_name] = @config["parameter_group_name"]
            cluster_config_struct[:engine] = @config["engine"]
            cluster_config_struct[:engine_version] = @config["engine_version"]
            cluster_config_struct[:master_username] = @config["master_user"]
            cluster_config_struct[:master_user_password] = @config["password"]
            cluster_config_struct[:preferred_backup_window] = @config["preferred_backup_window"]
            cluster_config_struct[:preferred_maintenance_window] = @config["preferred_maintenance_window"]
          end

          if @config["creation_style"] == "point_in_time"
            cluster_config_struct[:source_db_cluster_identifier] = @config["source_identifier"]
            cluster_config_struct[:restore_to_time] = @config["restore_time"] unless @config["restore_time"] == "latest"
            cluster_config_struct[:use_latest_restorable_time] = true if @config["restore_time"] == "latest"
          end

          attempts = 0
          begin
            resp = 
              if @config["creation_style"] == "new"
                MU.log "Creating new database cluster #{@config['identifier']}"
                MU::Cloud::AWS.rds(@config['region']).create_db_cluster(cluster_config_struct)
              elsif %w{existing_snapshot new_snapshot}.include?(@config["creation_style"])
                MU.log "Creating new database cluster #{@config['identifier']} from snapshot #{@config["snapshot_id"]}"
                MU::Cloud::AWS.rds(@config['region']).restore_db_cluster_from_snapshot(cluster_config_struct)
              elsif @config["creation_style"] == "point_in_time"
                MU.log "Creating new database cluster #{@config['identifier']} from point in time backup #{@config["restore_time"]} of #{@config["source_identifier"]}"
                MU::Cloud::AWS.rds(@config['region']).restore_db_cluster_to_point_in_time(cluster_config_struct)
              end
          rescue Aws::RDS::Errors::InvalidParameterValue => e
            if attempts < 5
              MU.log "Got #{e.inspect} while creating database cluster #{@config['identifier']}, will retry a few times in case of transient errors.", MU::WARN
              attempts += 1
              sleep 10
              retry
            else
              raise MuError, "Exhausted retries trying to create database cluster #{@config['identifier']}", MU::ERR, details: e.inspect
            end
          end

          attempts = 0
          loop do
            MU.log "Waiting for #{@config['identifier']} to become available", MU::NOTICE if attempts % 5 == 0
            attempts += 1
            cluster = MU::Cloud::AWS::Database.getDatabaseClusterById(@config['identifier'], region: @config['region'])
            break unless cluster.status != "available"
            sleep 30
          end

          if %w{existing_snapshot new_snapshot point_in_time}.include?(@config["creation_style"])
            modify_db_cluster_struct = {
              db_cluster_identifier: @config['identifier'],
              apply_immediately: true,
              backup_retention_period: @config["backup_retention_period"],
              db_cluster_parameter_group_name: @config["parameter_group_name"],
              master_user_password: @config["password"],
              preferred_backup_window: @config["preferred_backup_window"]
            }

            modify_db_cluster_struct[:preferred_maintenance_window] = @config["preferred_maintenance_window"] if @config["preferred_maintenance_window"]
            MU::Cloud::AWS.rds(@config['region']).modify_db_cluster(modify_db_cluster_struct)

            attempts = 0
            loop do
              MU.log "Waiting for #{@config['identifier']} to become available", MU::NOTICE if attempts % 5 == 0
              attempts += 1
              cluster = MU::Cloud::AWS::Database.getDatabaseClusterById(@config['identifier'], region: @config['region'])
              break unless cluster.status != "available"
              sleep 30
            end
          end

          cluster = MU::Cloud::AWS::Database.getDatabaseClusterById(@config['identifier'], region: @config['region'])
          MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: cluster.db_cluster_identifier, target: "#{cluster.endpoint}.", cloudclass: MU::Cloud::Database, sync_wait: @config['dns_sync_wait'])
          return cluster.db_cluster_identifier
        end

        # Create a subnet group for a database.
        def createSubnetGroup
          # Finding subnets, creating security groups/adding holes, create subnet group
          subnet_ids = []

          if @config['vpc'] and !@config['vpc'].empty?
            raise MuError, "Didn't find the VPC specified in #{@config["vpc"]}" unless @vpc

            vpc_id = @vpc.cloud_id
            # Getting subnet IDs
            subnets =
              if @config["vpc"]["subnets"].empty?
                @vpc.subnets
              else
                subnet_objects= []
                @config["vpc"]["subnets"].each { |subnet|
                  subnet_objects << @vpc.getSubnet(cloud_id: subnet["subnet_id"], name: subnet["subnet_name"])
                }
                subnet_objects
              end

            subnets.each{ |subnet|
              if @config["publicly_accessible"]
                subnet_ids << subnet.cloud_id if !subnet.private?
              elsif !@config["publicly_accessible"]
                subnet_ids << subnet.cloud_id if subnet.private?
              end
            }
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
              # Default VPC has only public subnets by default so setting publicly_accessible = true
              @config["publicly_accessible"] = true
              using_default_vpc = true
              MU.log "Using default VPC for cache cluster #{@config['identifier']}"
            end
          end

          if subnet_ids.empty?
            raise MuError, "Couldn't find subnets in #{@vpc} to add to #{@config["subnet_group_name"]}. Make sure the subnets are valid and publicly_accessible is set correctly"
          else
            # Create subnet group
            resp = MU::Cloud::AWS.rds(@config['region']).create_db_subnet_group(
                db_subnet_group_name: @config["subnet_group_name"],
                db_subnet_group_description: @config["subnet_group_name"],
                subnet_ids: subnet_ids,
                tags: allTags
            )

            if @dependencies.has_key?('firewall_rule')
                @config["vpc_security_group_ids"] = []
                @dependencies['firewall_rule'].values.each { |sg|
                  @config["vpc_security_group_ids"] << sg.cloud_id
              }
            end
          end

          # Find NAT and create holes in security groups.
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
        end

        # Create a database cluster parameter group.
        def createDBClusterParameterGroup
          MU.log "Creating a cluster parameter group #{@config["parameter_group_name"]}"

          MU::Cloud::AWS.rds(@config['region']).create_db_cluster_parameter_group(
            db_cluster_parameter_group_name: @config["parameter_group_name"],
            db_parameter_group_family: @config["parameter_group_family"],
            description: "Parameter group for #{@config["parameter_group_family"]}",
            tags: allTags
          )

          if @config["cluster_parameter_group_parameters"] && !@config["cluster_parameter_group_parameters"].empty?
            params = []
            @config["cluster_parameter_group_parameters"].each { |item|
              params << {parameter_name: item['name'], parameter_value: item['value'], apply_method: item['apply_method']}
            }

            MU.log "Modifiying cluster parameter group #{@config["parameter_group_name"]}"
            MU::Cloud::AWS.rds(@config['region']).modify_db_cluster_parameter_group(
              db_cluster_parameter_group_name: @config["parameter_group_name"],
              parameters: params
            )
          end
        end

        # Create a database parameter group.
        def createDBParameterGroup
          MU.log "Creating a database parameter group #{@config["parameter_group_name"]}"
          MU::Cloud::AWS.rds(@config['region']).create_db_parameter_group(
            db_parameter_group_name: @config["parameter_group_name"],
            db_parameter_group_family: @config["parameter_group_family"],
            description: "Parameter group for #{@config["parameter_group_family"]}",
            tags: allTags
          )

          if @config["db_parameter_group_parameters"] && !@config["db_parameter_group_parameters"].empty?
            params = []
            @config["db_parameter_group_parameters"].each { |item|
              params << {parameter_name: item['name'], parameter_value: item['value'], apply_method: item['apply_method']}
            }

            MU.log "Modifiying database parameter group #{@config["parameter_group_name"]}"
            MU::Cloud::AWS.rds(@config['region']).modify_db_parameter_group(
              db_parameter_group_name: @config["parameter_group_name"],
              parameters: params
            )
          end
        end

        # Retrieve a complete description of a database cluster parameter group.
        # @param param_group_id [String]: The cloud provider's identifier for this parameter group.
        # @param region [String]: The cloud provider region
        # @return [OpenStruct]
        def self.getDBClusterParameterGroup(param_group_id, region: MU.curRegion)
          MU::Cloud::AWS.rds(region).describe_db_cluster_parameter_groups(db_cluster_parameter_group_name: param_group_id).db_cluster_parameter_groups.first
          # rescue DBClusterParameterGroupNotFound => e
          # Of course the API will return DBParameterGroupNotFound instead of the documented DBClusterParameterGroupNotFound error.
        rescue Aws::RDS::Errors::DBParameterGroupNotFound => e
          #we're fine returning nil
        end

        # Retrieve a complete description of a database parameter group.
        # @param param_group_id [String]: The cloud provider's identifier for this parameter group.
        # @param region [String]: The cloud provider region
        # @return [OpenStruct]
        def self.getDBParameterGroup(param_group_id, region: MU.curRegion)
          MU::Cloud::AWS.rds(region).describe_db_parameter_groups(db_parameter_group_name: param_group_id).db_parameter_groups.first
        rescue Aws::RDS::Errors::DBParameterGroupNotFound => e
          #we're fine returning nil
        end

        # Retrieve a complete description of a database subnet group.
        # @param subnet_id [String]: The cloud provider's identifier for this subnet group.
        # @param region [String]: The cloud provider region
        # @return [OpenStruct]
        def self.getSubnetGroup(subnet_id, region: MU.curRegion)
          MU::Cloud::AWS.rds(region).describe_db_subnet_groups(db_subnet_group_name: subnet_id).db_subnet_groups.first
        rescue Aws::RDS::Errors::DBSubnetGroupNotFoundFault => e
          #we're fine returning nil
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          unless @config["create_cluster"]
            database = MU::Cloud::AWS::Database.getDatabaseById(@config['identifier'], region: @config['region'])

            # Run SQL on deploy
            if @config['run_sql_on_deploy']
              MU.log "Running initial SQL commands on #{@config['name']}", details: @config['run_sql_on_deploy']

              # check if DB is private or public
              if !database.publicly_accessible
                # This doesn't necessarily mean what we think it does. publicly_accessible = true means resolve to public address.
                # publicly_accessible can still be set to true even when only private subnets are included in the subnet group. We try to solve this during creation.
                is_private = true
              else
                is_private = false
              end

              #Setting up connection params
              ssh_keydir = Etc.getpwuid(Process.uid).dir+"/.ssh"
              keypairname, ssh_private_key, ssh_public_key = @deploy.SSHKey
              if is_private and @vpc
                if @config['vpc']['nat_host_name']
                  begin
                    proxy_cmd = "ssh -q -o StrictHostKeyChecking=no -W %h:%p #{nat_ssh_user}@#{nat_host_name}"
                    gateway = Net::SSH::Gateway.new(
                        @config['vpc']['nat_host_name'],
                        @config['vpc']['nat_ssh_user'],
                        :keys => [ssh_keydir+"/"+keypairname],
                        :keys_only => true,
                        :auth_methods => ['publickey'],
  #								:verbose => :info
                    )
                    port = gateway.open(database.endpoint.address, database.endpoint.port)
                    address = "127.0.0.1"
                    MU.log "Tunneling #{@config['engine']} connection through #{nat_host_name} via local port #{port}", MU::DEBUG
                  rescue IOError => e
                    MU.log "Got #{e.inspect} while connecting to #{@config['identifier']} through NAT #{nat_host_name}", MU::ERR
                  end
                else
                  MU.log "Can't run initial SQL commands! Database #{@config['identifier']} is not publicly accessible, but we have no NAT host for connecting to it", MU::WARN, details: @config['run_sql_on_deploy']
                end
              else
                port = database.endpoint.port
                address = database.endpoint.address
              end

              # Running SQL on deploy
              if @config['engine'] == "postgres"
                autoload :PG, 'pg'
                begin
                  conn = PG::Connection.new(
                      :host => address,
                      :port => port,
                      :user => @config['master_user'],
                      :dbname => database.db_name,
                      :password => @config['password']
                  )
                  @config['run_sql_on_deploy'].each { |cmd|
                    MU.log "Running #{cmd} on database #{@config['name']}"
                    conn.exec(cmd)
                  }
                  conn.finish
                rescue PG::Error => e
                  MU.log "Failed to run initial SQL commands on #{@config['name']} via #{address}:#{port}: #{e.inspect}", MU::WARN, details: conn
                end
              elsif @config['engine'] == "mysql"
                autoload :Mysql, 'mysql'
                MU.log "Initiating mysql connection to #{address}:#{port} as #{@config['master_user']}"
                conn = Mysql.new(address, @config['master_user'], @config['password'], "mysql", port)
                @config['run_sql_on_deploy'].each { |cmd|
                  MU.log "Running #{cmd} on database #{@config['name']}"
                  conn.query(cmd)
                }
                conn.close
              end

              # close the SQL on deploy sessions
              if is_private
                begin
                  gateway.close(port)
                rescue IOError => e
                  MU.log "Failed to close ssh session to NAT after running sql_on_deploy", MU::ERR, details: e.inspect
                end
              end
            end

            # set multi-az on deploy
            if @config['multi_az_on_deploy']
              if !database.multi_az
                MU.log "Setting multi-az on #{@config['identifier']}"
                attempts = 0
                begin
                  MU::Cloud::AWS.rds(@config['region']).modify_db_instance(
                      db_instance_identifier: @config['identifier'],
                      apply_immediately: true,
                      multi_az: true
                  )
                rescue Aws::RDS::Errors::InvalidParameterValue, Aws::RDS::Errors::InvalidDBInstanceState => e
                  if attempts < 15
                    MU.log "Got #{e.inspect} while setting Multi-AZ on #{@config['identifier']}, retrying."
                    attempts += 1
                    sleep 15
                    retry
                  else
                    MU.log "Couldn't set Multi-AZ on #{@config['identifier']} after several retries, giving up. #{e.inspect}", MU::ERR
                  end
                end
              end
            end
          end
        end

        # Generate database user, database identifier, database name based on engine-specific constraints
        # @return [String]: Name
        def getName(basename, type: 'dbname')
          if type == 'dbname'
            # Apply engine-specific db name constraints
            if @config["engine"].match(/^oracle/)
              (MU.seed.downcase+@config["name"])[0..7]
            elsif @config["engine"].match(/^sqlserver/)
              nil
            elsif @config["engine"].match(/^mysql/)
              basename[0..63]
            elsif @config["engine"].match(/^aurora/)
              (MU.seed.downcase+@config["name"])[0..7]
            else
              basename
            end
          elsif type == 'dbuser'
            # Apply engine-specific master username constraints
            if @config["engine"].match(/^oracle/)
              basename[0..29].gsub(/[^a-z0-9]/i, "")
            elsif @config["engine"].match(/^sqlserver/)
              basename[0..127].gsub(/[^a-z0-9]/i, "")
            elsif @config["engine"].match(/^mysql/)
              basename[0..15].gsub(/[^a-z0-9]/i, "")
            elsif @config["engine"].match(/^aurora/)
              basename[0..15].gsub(/[^a-z0-9]/i, "")
            else
              basename.gsub(/[^a-z0-9]/i, "")
            end
          end
        end

        # Permit a host to connect to the given database instance.
        # @param cidr [String]: The CIDR-formatted IP address or block to allow access.
        # @return [void]
        def allowHost(cidr)
          # If we're an old, Classic-style database with RDS-specific
          # authorization, punch holes in that.
          if !cloud_desc.db_security_groups.empty?
            cloud_desc.db_security_groups.each { |rds_sg|
              begin
                MU::Cloud::AWS.rds(@config['region']).authorize_db_security_group_ingress(
                    db_security_group_name: rds_sg.db_security_group_name,
                    cidrip: cidr
                )
              rescue Aws::RDS::Errors::AuthorizationAlreadyExists => e
                MU.log "CIDR #{cidr} already in database instance #{@cloud_id} security group", MU::WARN
              end
            }
          end

          # Otherwise go get our generic EC2 ruleset and punch a hole in it
          if @dependencies.has_key?('firewall_rule')
            @dependencies['firewall_rule'].values.each { |sg|
              sg.addRule([cidr], proto: "tcp", port: cloud_desc.endpoint.port)
              break
            }
          end
        end

        # Retrieve the complete cloud provider description of a database instance.
        # @param db_id [String]: The cloud provider's identifier for this database.
        # @param region [String]: The cloud provider region
        # @return [OpenStruct]
        def self.getDatabaseById(db_id, region: MU.curRegion)
          MU::Cloud::AWS.rds(region).describe_db_instances(db_instance_identifier: db_id).db_instances.first
        rescue Aws::RDS::Errors::DBInstanceNotFound => e
          # We're fine with this returning nil when searching for a database instance the doesn't exist.
        end

        # Retrieve the complete cloud provider description of a database cluster.
        # @param db_cluster_id [String]: The cloud provider's identifier for this database cluster.
        # @param region [String]: The cloud provider region
        # @return [OpenStruct]
        def self.getDatabaseClusterById(db_cluster_id, region: MU.curRegion)
          MU::Cloud::AWS.rds(region).describe_db_clusters(db_cluster_identifier: db_cluster_id).db_clusters.first
        rescue Aws::RDS::Errors::DBClusterNotFoundFault => e
          # We're fine with this returning nil when searching for a database cluster the doesn't exist.
        end

        # Register a description of this database instance with this deployment's metadata.
        # Register read replicas as separate instances, while we're
        # at it.
        def notify
          my_dbs = [@config]
          if @config['read_replica']
            @config['read_replica']['creation_style'] = "read_replica"
            @config['read_replica']['password'] = @config["password"]
            my_dbs << @config['read_replica']
          end

          deploy_struct = {}
          my_dbs.each { |db|
          deploy_struct = 
            if db["create_cluster"]
              cluster = MU::Cloud::AWS::Database.getDatabaseClusterById(db["identifier"], region: db['region'])
              # DNS records for the "real" zone should always be registered as late as possible so override_existing only overwrites the records after the resource is ready to use.
              if db['dns_records']
                db['dns_records'].each { |dnsrec|
                  dnsrec['name'] = cluster.db_cluster_identifier if !dnsrec.has_key?('name')
                  dnsrec['name'] = "#{dnsrec['name']}.#{MU.environment.downcase}" if dnsrec["append_environment_name"] && !dnsrec['name'].match(/\.#{MU.environment.downcase}$/)
                }
                end
              # XXX this should be a call to @deploy.nameKitten
              MU::Cloud::AWS::DNSZone.createRecordsFromConfig(db['dns_records'], target: cluster.endpoint)

              vpc_sg_ids = []
              cluster.vpc_security_groups.each { |vpc_sg|
                vpc_sg_ids << vpc_sg.vpc_security_group_id
              }

              {
                "allocated_storage" => cluster.allocated_storage,
                "parameter_group" => cluster.db_cluster_parameter_group,
                "subnet_group" => cluster.db_subnet_group,
                "identifier" => cluster.db_cluster_identifier,
                "region" => db['region'],
                "engine" => cluster.engine,
                "engine_version" => cluster.engine_version,
                "backup_retention_period" => cluster.backup_retention_period,
                "preferred_backup_window" => cluster.preferred_backup_window,
                "preferred_maintenance_window" => cluster.preferred_maintenance_window,
                "endpoint" => cluster.endpoint,
                "port" => cluster.port,
                "username" => cluster.master_username,
                "vpc_sgs" => vpc_sg_ids,
                "azs" => cluster.availability_zones,
                "vault_name" => cluster.db_cluster_identifier.upcase,
                "vault_item" => "database_credentials",
                "password_field" => "password",
                "create_style" => db['creation_style'],
                "db_name" => cluster.database_name,
                "db_cluster_members" => cluster.db_cluster_members
              }
            else
              database = MU::Cloud::AWS::Database.getDatabaseById(db["identifier"], region: db['region'])
              # DNS records for the "real" zone should always be registered as late as possible so override_existing only overwrites the records after the resource is ready to use.
              unless db["add_cluster_node"]
                # It isn't necessarily clear what we should do with DNS records of cluster members. Probably need to expose this to the BoK somehow.
                if db['dns_records']
                  db['dns_records'].each { |dnsrec|
                    dnsrec['name'] = database.db_instance_identifier if !dnsrec.has_key?('name')
                    dnsrec['name'] = "#{dnsrec['name']}.#{MU.environment.downcase}" if dnsrec["append_environment_name"] && !dnsrec['name'].match(/\.#{MU.environment.downcase}$/)
                  }
                end
                # XXX this should be a call to @deploy.nameKitten
                MU::Cloud::AWS::DNSZone.createRecordsFromConfig(db['dns_records'], target: database.endpoint.address)
              end

              vpc_sg_ids = Array.new
              database.vpc_security_groups.each { |vpc_sg|
                vpc_sg_ids << vpc_sg.vpc_security_group_id
              }

              rds_sg_ids = Array.new
              database.db_security_groups.each { |rds_sg|
                rds_sg_ids << rds_sg.db_security_group_name
              }

              subnet_ids = []
              if database.db_subnet_group and database.db_subnet_group.subnets
                database.db_subnet_group.subnets.each { |subnet|
                  subnet_ids << subnet.subnet_identifier
                }
              end

              {
                "identifier" => database.db_instance_identifier,
                "region" => db['region'],
                "engine" => database.engine,
                "engine_version" => database.engine_version,
                "backup_retention_period" => database.backup_retention_period,
                "preferred_backup_window" => database.preferred_backup_window,
                "preferred_maintenance_window" => database.preferred_maintenance_window,
                "auto_minor_version_upgrade" => database.auto_minor_version_upgrade,
                "storage_encrypted" => database.storage_encrypted,
                "endpoint" => database.endpoint.address,
                "port" => database.endpoint.port,
                "username" => database.master_username,
                "rds_sgs" => rds_sg_ids,
                "vpc_sgs" => vpc_sg_ids,
                "az" => database.availability_zone,
                "vault_name" => database.db_instance_identifier.upcase,
                "vault_item" => "database_credentials",
                "password_field" => "password",
                "create_style" => db['creation_style'],
                "db_name" => database.db_name,
                "multi_az" => database.multi_az,
                "publicly_accessible" => database.publicly_accessible,
                "ca_certificate_identifier" => database.ca_certificate_identifier,
                "subnets" => subnet_ids,
                "read_replica_source_db" => database.read_replica_source_db_instance_identifier,
                "read_replica_instance_identifiers" => database.read_replica_db_instance_identifiers,
                "cluster_identifier" => database.db_cluster_identifier,
                "size" => database.db_instance_class,
                "storage" => database.allocated_storage
              }
            end
          }

          raise MuError, "Can't find any deployment metadata" if deploy_struct.empty?
          return deploy_struct
        end

        # Generate a snapshot from the database described in this instance.
        # @return [String]: The cloud provider's identifier for the snapshot.
        def createNewSnapshot
          snap_id = @deploy.getResourceName(@config["name"]) + Time.new.strftime("%M%S").to_s

          attempts = 0
          begin
            snapshot = 
              if @config["create_cluster"]
                MU::Cloud::AWS.rds(@config['region']).create_db_cluster_snapshot(
                  db_cluster_snapshot_identifier: snap_id,
                  db_cluster_identifier: @config["identifier"],
                  tags: allTags
                )
              else
                MU::Cloud::AWS.rds(@config['region']).create_db_snapshot(
                  db_snapshot_identifier: snap_id,
                  db_instance_identifier: @config["identifier"],
                  tags: allTags
                )
              end
          rescue Aws::RDS::Errors::InvalidDBInstanceState, Aws::RDS::Errors::InvalidDBClusterStateFault => e
            raise MuError, e.inspect if attempts >= 10
            attempts += 1
            sleep 60
            retry
          end

          attempts = 0
          loop do
            MU.log "Waiting for RDS snapshot of #{@config["identifier"]} to be ready...", MU::NOTICE if attempts % 20 == 0
            MU.log "Waiting for RDS snapshot of #{@config["identifier"]} to be ready...", MU::DEBUG
            snapshot_resp =
              if @config["create_cluster"]
                MU::Cloud::AWS.rds(@config['region']).describe_db_cluster_snapshots(db_cluster_snapshot_identifier: snap_id)
              else
                MU::Cloud::AWS.rds(@config['region']).describe_db_snapshots(db_snapshot_identifier: snap_id)
              end

            if @config["create_cluster"]
              break unless snapshot_resp.db_cluster_snapshots.first.status != "available"
            else
              break unless snapshot_resp.db_snapshots.first.status != "available"
            end
            attempts += 1
            sleep 15
          end

          return snap_id
        end

        # Fetch the latest snapshot of the database described in this instance.
        # @return [String]: The cloud provider's identifier for the snapshot.
        def getExistingSnapshot
          resp =
            if @config["create_cluster"]
              MU::Cloud::AWS.rds(@config['region']).describe_db_cluster_snapshots(db_cluster_snapshot_identifier: @config["identifier"])
            else
              MU::Cloud::AWS.rds(@config['region']).describe_db_snapshots(db_snapshot_identifier: @config["identifier"])
            end

          snapshots = @config["create_cluster"] ? resp.db_cluster_snapshots : resp.db_snapshots

          if snapshots.empty?
            nil
          else
            sorted_snapshots = snapshots.sort_by { |snap| snap.snapshot_create_time }
            @config["create_cluster"] ? sorted_snapshots.last.db_cluster_snapshot_identifier : sorted_snapshots.last.db_snapshot_identifier
          end
        end

        # Called by {MU::Cleanup}. Locates resources that were created by the
        # currently-loaded deployment, and purges them.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region in which to operate
        # @return [void]
        def self.cleanup(skipsnapshots: false, noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          resp = MU::Cloud::AWS.rds(region).describe_db_instances
          threads = []

          resp.db_instances.each { |db|
            db_id = db.db_instance_identifier
            arn = MU::Cloud::AWS::Database.getARN(db.db_instance_identifier, "db", "rds", region: region)
            tags = MU::Cloud::AWS.rds(region).list_tags_for_resource(resource_name: arn).tag_list

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
              parent_thread_id = Thread.current.object_id
              threads << Thread.new(db) { |mydb|
                MU.dupGlobals(parent_thread_id)
                Thread.abort_on_exception = true
                MU::Cloud::AWS::Database.terminate_rds_instance(mydb, noop, skipsnapshots, region: region, deploy_id: MU.deploy_id, cloud_id: db.db_instance_identifier, mu_name: db.db_instance_identifier.upcase)
              }
            end
          }

          # Wait for all of the databases to finish cleanup before proceeding
          threads.each { |t|
            t.join
          }

          # Cleanup database clusters
          threads = []
          resp = MU::Cloud::AWS.rds(region).describe_db_clusters
          resp.db_clusters.each { |cluster|
            cluster_id = cluster.db_cluster_identifier
            arn = MU::Cloud::AWS::Database.getARN(cluster_id, "cluster", "rds", region: region)
            tags = MU::Cloud::AWS.rds(region).list_tags_for_resource(resource_name: arn).tag_list

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
              parent_thread_id = Thread.current.object_id
              threads << Thread.new(cluster) { |mydbcluster|
                MU.dupGlobals(parent_thread_id)
                Thread.abort_on_exception = true
                MU::Cloud::AWS::Database.terminate_rds_cluster(mydbcluster, noop, skipsnapshots, region: region, deploy_id: MU.deploy_id, cloud_id: cluster_id, mu_name: cluster_id.upcase)
              }
            end
          }

          # Wait for all of the database clusters to finish cleanup before proceeding
          threads.each { |t|
            t.join
          }

          threads = []
          # Cleanup database subnet group
          MU::Cloud::AWS.rds(region).describe_db_subnet_groups.db_subnet_groups.each { |sub_group|
            sub_group_id = sub_group.db_subnet_group_name
            arn = MU::Cloud::AWS::Database.getARN(sub_group_id, "subgrp", "rds", region: region)
            tags = MU::Cloud::AWS.rds(region).list_tags_for_resource(resource_name: arn).tag_list

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
              parent_thread_id = Thread.current.object_id
              threads << Thread.new(sub_group) { |mysubgroup|
                MU.dupGlobals(parent_thread_id)
                Thread.abort_on_exception = true
                MU::Cloud::AWS::Database.delete_subnet_group(sub_group_id, region: region) unless noop
              }
            end
          }
            
          # Cleanup database parameter group
          MU::Cloud::AWS.rds(region).describe_db_parameter_groups.db_parameter_groups.each { |param_group|
            param_group_id = param_group.db_parameter_group_name
            arn = MU::Cloud::AWS::Database.getARN(param_group_id, "pg", "rds", region: region)
            tags = MU::Cloud::AWS.rds(region).list_tags_for_resource(resource_name: arn).tag_list

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
              parent_thread_id = Thread.current.object_id
              threads << Thread.new(param_group) { |myparamgroup|
                MU.dupGlobals(parent_thread_id)
                Thread.abort_on_exception = true
                MU::Cloud::AWS::Database.delete_db_parameter_group(param_group_id, region: region) unless noop
              }
            end
          }
            
          # Cleanup database cluster parameter group
          MU::Cloud::AWS.rds(region).describe_db_cluster_parameter_groups.db_cluster_parameter_groups.each { |param_group|
            param_group_id = param_group.db_cluster_parameter_group_name
            arn = MU::Cloud::AWS::Database.getARN(param_group_id, "cluster-pg", "rds", region: region)
            tags = MU::Cloud::AWS.rds(region).list_tags_for_resource(resource_name: arn).tag_list

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
              parent_thread_id = Thread.current.object_id
              threads << Thread.new(param_group) { |myparamgroup|
                MU.dupGlobals(parent_thread_id)
                Thread.abort_on_exception = true
                MU::Cloud::AWS::Database.delete_db_cluster_parameter_group(param_group_id, region: region) unless noop
              }
            end
          }

          # Wait for all of the databases subnet/parameter groups to finish cleanup before proceeding
          threads.each { |t|
            t.join
          }
          end

        private

        # Remove an RDS database and associated artifacts
        # @param db [OpenStruct]: The cloud provider's description of the database artifact
        # @return [void]
        def self.terminate_rds_instance(db, noop = false, skipsnapshots = false, region: MU.curRegion, deploy_id: MU.deploy_id, mu_name: nil, cloud_id: nil)
          raise MuError, "terminate_rds_instance requires a non-nil database descriptor" if db.nil?
          db_id = db.db_instance_identifier

          database_obj = MU::MommaCat.findStray(
              "AWS",
              "database",
              region: region,
              deploy_id: deploy_id,
              cloud_id: cloud_id,
              mu_name: mu_name
          ).first

          subnet_group = nil
          begin
            subnet_group = db.db_subnet_group.db_subnet_group_name if db.db_subnet_group
          rescue NoMethodError
            # ignorable for non-VPC databases
          end

          rdssecgroups = Array.new
          begin
            secgroup = MU::Cloud::AWS.rds(region).describe_db_security_groups(db_security_group_name: db_id)
          rescue Aws::RDS::Errors::DBSecurityGroupNotFound
            # this is normal in VPC world
          end

          rdssecgroups << db_id if !secgroup.nil?
          parameter_group = db.db_parameter_groups.first.db_parameter_group_name

          # We can use an AWS waiter for this.
          unless db.db_instance_status == "available"
            loop do
              MU.log "Waiting for #{db_id} to be in a removable state...", MU::NOTICE
              db = MU::Cloud::AWS::Database.getDatabaseById(db_id, region: region)
              break unless %w{creating modifying backing-up}.include?(db.db_instance_status)
              sleep 60
            end
          end

          MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: db_id, target: db.endpoint.address, cloudclass: MU::Cloud::Database, delete: true)

          if %w{deleting deleted}.include?(db.db_instance_status)
            MU.log "#{db_id} has already been terminated", MU::WARN
          else
            def self.dbSkipSnap(db_id, region)
              # We're calling this several times so lets declare it once
              MU.log "Terminating #{db_id} (not saving final snapshot)"
              MU::Cloud::AWS.rds(region).delete_db_instance(db_instance_identifier: db_id, skip_final_snapshot: true)
            end

            def self.dbCreateSnap(db_id, region)
              MU.log "Terminating #{db_id} (final snapshot: #{db_id}-mufinal)"
              MU::Cloud::AWS.rds(region).delete_db_instance(db_instance_identifier: db_id, final_db_snapshot_identifier: "#{db_id}-mufinal", skip_final_snapshot: false)
            end

            if !noop
              retries = 0
              begin
                if db.db_cluster_identifier || db.read_replica_source_db_instance_identifier
                  # make sure we don't create final snapshot for a database instance that is part of a cluster, or if it's a read replica database instance
                  dbSkipSnap(db_id, region)
                else
                  skipsnapshots ? dbSkipSnap(db_id, region) : dbCreateSnap(db_id, region)
                end
              rescue Aws::RDS::Errors::InvalidDBInstanceState => e
                if retries < 5
                  MU.log "#{db_id} is not in a removable state, retrying several times #{e.inspect}", MU::WARN
                  retries += 1
                  sleep 30
                  retry
                else
                  MU.log "#{db_id} is not in a removable state after several retries, giving up. #{e.inspect}", MU::ERR
                end
              rescue Aws::RDS::Errors::DBSnapshotAlreadyExists
                dbSkipSnap(db_id, region)
                MU.log "Snapshot of #{db_id} already exists", MU::WARN
              rescue Aws::RDS::Errors::SnapshotQuotaExceeded
                dbSkipSnap(db_id, region)
                MU.log "Snapshot quota exceeded while deleting #{db_id}", MU::ERR
              end
            end
          end

          begin
            del_db = MU::Cloud::AWS::Database.getDatabaseById(db_id, region: region)
            while !del_db.nil? and del_db.db_instance_status != "deleted" and !noop
              MU.log "Waiting for #{db_id} termination to complete", MU::NOTICE
              sleep 60
              del_db = MU::Cloud::AWS::Database.getDatabaseById(db_id, region: region)
            end
          rescue Aws::RDS::Errors::DBInstanceNotFound
            # we are ok with this
          end

          # RDS security groups can depend on EC2 security groups, do these last
          begin
            rdssecgroups.each { |sg|
              MU.log "Removing RDS Security Group #{sg}"
              MU::Cloud::AWS.rds(region).delete_db_security_group(db_security_group_name: sg) if !noop
            }
          rescue Aws::RDS::Errors::DBSecurityGroupNotFound
            MU.log "RDS Security Group #{sg} disappeared before we could remove it", MU::WARN
          end

          # Cleanup the database vault
          grommer = 
            if database_obj
              database_obj.config.has_key?("groomer") ? database_obj.config["groomer"] : MU::Config.defaultGroomer
            else
              MU::Config.defaultGroomer
            end

          groomclass = MU::Groomer.loadGroomer(grommer)
          groomclass.deleteSecret(vault: db_id.upcase) if !noop
          MU.log "#{db_id} has been terminated"
        end

        # Remove an RDS database cluster and associated artifacts
        # @param cluster [OpenStruct]: The cloud provider's description of the database artifact
        # @return [void]
        def self.terminate_rds_cluster(cluster, noop = false, skipsnapshots = false, region: MU.curRegion, deploy_id: MU.deploy_id, mu_name: nil, cloud_id: nil)
          raise MuError, "terminate_rds_cluster requires a non-nil database cluster descriptor" if cluster.nil?
          cluster_id = cluster.db_cluster_identifier

          cluster_obj = MU::MommaCat.findStray(
            "AWS",
            "database",
            region: region,
            deploy_id: deploy_id,
            cloud_id: cloud_id,
            mu_name: mu_name
          ).first

          subnet_group = cluster.db_subnet_group
          cluster_parameter_group = cluster.db_cluster_parameter_group

          # We can use an AWS waiter for this.
          unless cluster.status == "available"
            loop do
              MU.log "Waiting for #{cluster_id} to be in a removable state...", MU::NOTICE
              cluster = MU::Cloud::AWS::Database.getDatabaseClusterById(cluster_id, region: region)
              break unless %w{creating modifying backing-up}.include?(cluster.status)
              sleep 60
            end
          end

          MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: cluster_id, target: cluster.endpoint, cloudclass: MU::Cloud::Database, delete: true)

          if %w{deleting deleted}.include?(cluster.status)
            MU.log "#{cluster_id} has already been terminated", MU::WARN
          else
            unless noop
              def self.clusterSkipSnap(cluster_id, region)
                # We're calling this several times so lets declare it once
                MU.log "Terminating #{cluster_id}. Not saving final snapshot"
                MU::Cloud::AWS.rds(region).delete_db_cluster(db_cluster_identifier: cluster_id, skip_final_snapshot: true)
              end

              def self.clusterCreateSnap(cluster_id, region)
                MU.log "Terminating #{cluster_id}. Saving final snapshot: #{cluster_id}-mufinal"
                MU::Cloud::AWS.rds(region).delete_db_cluster(db_cluster_identifier: cluster_id, skip_final_snapshot: false, final_db_snapshot_identifier: "#{cluster_id}-mufinal")
              end

              retries = 0
              begin
                skipsnapshots ? clusterSkipSnap(cluster_id, region) : clusterCreateSnap(cluster_id, region)
              rescue Aws::RDS::Errors::InvalidDBClusterStateFault => e
                if retries < 5
                  MU.log "#{cluster_id} is not in a removable state, retrying several times", MU::WARN
                  retries += 1
                  sleep 30
                  retry
                else
                  MU.log "#{cluster_id} is not in a removable state after several retries, giving up. #{e.inspect}", MU::ERR
                end
              rescue Aws::RDS::Errors::DBClusterSnapshotAlreadyExistsFault
                clusterSkipSnap(cluster_id, region)
                MU.log "Snapshot of #{cluster_id} already exists", MU::WARN
              rescue Aws::RDS::Errors::DBClusterQuotaExceeded
                clusterSkipSnap(cluster_id, region)
                MU.log "Snapshot quota exceeded while deleting #{cluster_id}", MU::ERR
              end
            end
          end

          # We're wating until getDatabaseClusterById returns nil. This assumes the database cluster object doesn't linger around in "deleted" state for a while.
          loop do
            MU.log "Waiting for #{cluster_id} to terminate", MU::NOTICE
            cluster = MU::Cloud::AWS::Database.getDatabaseClusterById(cluster_id, region: region)
            break unless cluster
            sleep 30
          end

          # Cleanup the cluster vault
          grommer = 
            if cluster_obj
              cluster_obj.config.has_key?("groomer") ? cluster_obj.config["groomer"] : MU::Config.defaultGroomer
            else
              MU::Config.defaultGroomer
            end

          groomclass = MU::Groomer.loadGroomer(grommer)
          groomclass.deleteSecret(vault: cluster_id.upcase) if !noop

          MU.log "#{cluster_id} has been terminated"
        end

        # Remove a database subnet group.
        # @param subnet_group_id [string]: The cloud provider's ID of the database subnet group.
        # @param region [String]: The cloud provider's region in which to operate.
        # @return [void]
        def self.delete_subnet_group(subnet_group_id, region: MU.curRegion)
          retries ||= 0
          MU.log "Deleting DB subnet group #{subnet_group_id}"
          MU::Cloud::AWS.rds(region).delete_db_subnet_group(db_subnet_group_name: subnet_group_id)
        rescue Aws::RDS::Errors::DBSubnetGroupNotFoundFault => e
          MU.log "DB subnet group #{subnet_group_id} disappeared before we could remove it", MU::WARN
        rescue Aws::RDS::Errors::InvalidDBSubnetGroupStateFault=> e
          if retries < 5
            MU.log "DB subnet group #{subnet_group_id} is not in a removable state, retrying", MU::WARN
            retries += 1
            sleep 30
            retry
          else
            MU.log "#{subnet_group_id} is not in a removable state after several retries, giving up. #{e.inspect}", MU::ERR
          end
        end
        
        # Remove a database parameter group.
        # @param parameter_group_id [string]: The cloud provider's ID of the database parameter group.
        # @param region [String]: The cloud provider's region in which to operate.
        # @return [void]
        def self.delete_db_parameter_group(parameter_group_id, region: MU.curRegion)
          retries ||= 0
          MU.log "Deleting DB parameter group #{parameter_group_id}"
          MU::Cloud::AWS.rds(region).delete_db_parameter_group(db_parameter_group_name: parameter_group_id)
        rescue Aws::RDS::Errors::DBParameterGroupNotFound
          MU.log "DB parameter group #{parameter_group_id} disappeared before we could remove it", MU::WARN
        rescue Aws::RDS::Errors::InvalidDBParameterGroupState => e
          if retries < 5
            MU.log "DB parameter group #{parameter_group_id} is not in a removable state, retrying", MU::WARN
            retries += 1
            sleep 30
            retry
          else
            MU.log "DB parameter group #{parameter_group_id} is not in a removable state after several retries, giving up. #{e.inspect}", MU::ERR
          end
        end

        # Remove a database cluster parameter group.
        # @param parameter_group_id [string]: The cloud provider's ID of the database cluster parameter group.
        # @param region [String]: The cloud provider's region in which to operate.
        # @return [void]
        def self.delete_db_cluster_parameter_group(parameter_group_id, region: MU.curRegion)
          retries ||= 0
          MU.log "Deleting cluster parameter group #{parameter_group_id}"
          MU::Cloud::AWS.rds(region).delete_db_cluster_parameter_group(db_cluster_parameter_group_name: parameter_group_id)
          # AWS API sucks. instead of returning the documented error DBClusterParameterGroupNotFoundFault it errors out with DBParameterGroupNotFound.
        rescue Aws::RDS::Errors::DBParameterGroupNotFound
          MU.log "Cluster parameter group #{parameter_group_id} disappeared before we could remove it", MU::WARN
        rescue Aws::RDS::Errors::InvalidDBParameterGroupState => e
          if retries < 5
            MU.log "Cluster parameter group #{parameter_group_id} is not in a removable state, retrying", MU::WARN
            retries += 1
            sleep 30
            retry
          else
            MU.log "Cluster parameter group #{parameter_group_id} is not in a removable state after several retries, giving up. #{e.inspect}", MU::ERR
          end
        end

      end #class
    end #class
  end
end #module
