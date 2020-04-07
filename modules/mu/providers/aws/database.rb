## Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#  http://egt-labs.com/mu/LICENSE.html
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

        # Map legal storage values for each disk type and database engine so
        # our validator can check them for us.
        STORAGE_RANGES = {
          "io1" => {
            "postgres" => 100..65536,
            "mysql" => 100..65536,
            "mariadb" => 100..65536,
            "oracle-se1" => 100..65536,
            "oracle-se2" => 100..65536,
            "oracle-se" => 100..65536,
            "oracle-ee" => 100..65536,
            "sqlserver-ex" => 100..16384,
            "sqlserver-web" => 100..16384,
            "sqlserver-ee" => 200..16384,
            "sqlserver-se" =>  200..16384
          },
          "gp2" => {
            "postgres" => 20..65536,
            "mysql" => 20..65536,
            "mariadb" => 20..65536,
            "oracle-se1" => 20..65536,
            "oracle-se2" => 20..65536,
            "oracle-se" => 20..65536,
            "oracle-ee" => 20..65536,
            "sqlserver-ex" => 20..16384,
            "sqlserver-web" => 20..16384,
            "sqlserver-ee" => 200..16384,
            "sqlserver-se" =>  200..16384
          },
          "standard" => {
            "postgres" => 5..3072,
            "mysql" => 5..3072,
            "mariadb" => 5..3072,
            "oracle-se1" => 10..3072,
            "oracle-se2" => 10..3072,
            "oracle-se" => 10..3072,
            "oracle-ee" => 10..3072,
            "sqlserver-ex" => 20..1024, # ???
            "sqlserver-web" => 20..1024, # ???
            "sqlserver-ee" => 200..4096, # ???
            "sqlserver-se" =>  200..4096 # ???
          }
        }.freeze

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @config["groomer"] = MU::Config.defaultGroomer unless @config["groomer"]
          @groomclass = MU::Groomer.loadGroomer(@config["groomer"])

          @mu_name ||=
            if @config and @config['engine'] and @config["engine"].match(/^sqlserver/)
              @deploy.getResourceName(@config["name"], max_length: 15)
            else
              @deploy.getResourceName(@config["name"], max_length: 63)
            end

          @mu_name.gsub(/(--|-$)/i, "").gsub(/(_)/, "-").gsub!(/^[^a-z]/i, "")

          if @config['source']
            @config["source"] = MU::Config::Ref.get(@config["source"])
          elsif @config["read_replica_of"]
            @config["source"] = MU::Config::Ref.get(@config["read_replica_of"])
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        # @return [String]: The cloud provider's identifier for this database instance.
        def create
          # RDS is picky, we can't just use our regular node names for things like
          # the default schema or username. And it varies from engine to engine.
          basename = @config["name"]+@deploy.timestamp+MU.seed.downcase
          basename.gsub!(/[^a-z0-9]/i, "")
          @config["db_name"] = MU::Cloud::AWS::Database.getName(basename, type: "dbname", config: @config)
          @config['master_user'] = MU::Cloud::AWS::Database.getName(basename, type: "dbuser", config: @config) unless @config['master_user']
          @cloud_id = @mu_name

          # Lets make sure automatic backups are enabled when DB instance is deployed in Multi-AZ so failover actually works. Maybe default to 1 instead?
          if @config['multi_az_on_create'] or @config['multi_az_on_deploy'] or @config["create_cluster"]
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

          @config["subnet_group_name"] = @mu_name if @vpc

          if @config["create_cluster"]
            getPassword
            createSubnetGroup

            if @config.has_key?("parameter_group_family")
              @config["parameter_group_name"] = @mu_name
              createDBParameterGroup(true)
            end

            @config["cluster_identifier"] ||= @cloud_id

            if @config['creation_style'] == "point_in_time"
              create_point_in_time
            else
              create_basic
            end

            wait_until_available

            if %w{existing_snapshot new_snapshot point_in_time}.include?(@config["creation_style"])
              modify_db_cluster_struct = {
                db_cluster_identifier: @cloud_id,
                apply_immediately: true,
                backup_retention_period: @config["backup_retention_period"],
                db_cluster_parameter_group_name: @config["parameter_group_name"],
                master_user_password: @config["password"],
                preferred_backup_window: @config["preferred_backup_window"]
              }

              modify_db_cluster_struct[:preferred_maintenance_window] = @config["preferred_maintenance_window"] if @config["preferred_maintenance_window"]
              MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).modify_db_cluster(modify_db_cluster_struct)
              wait_until_available
            end

            do_naming
          elsif @config["add_cluster_node"]
            add_cluster_node
          else
            add_basic
          end
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc.db_instance_arn
        end

        # Locate an existing Database or Databases and return an array containing matching AWS resource descriptors for those that match.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching Databases
        def self.find(**args)
          found = {}

          if args[:cloud_id]
            if !args[:cluster]
              begin
                resp = MU::Cloud::AWS.rds(region: args[:region], credentials: args[:credentials]).describe_db_instances(db_instance_identifier: args[:cloud_id]).db_instances.first
                return { args[:cloud_id] => resp } if resp
              rescue Aws::RDS::Errors::DBInstanceNotFound
                MU.log "No results found looking for RDS instance #{args[:cloud_id]}", MU::DEBUG
              end
            end
            begin
              resp = MU::Cloud::AWS.rds(region: args[:region], credentials: args[:credentials]).describe_db_clusters(db_cluster_identifier: args[:cloud_id]).db_clusters.first
            rescue Aws::RDS::Errors::DBClusterNotFoundFault
              MU.log "No results found looking for RDS cluster #{args[:cloud_id]}", MU::DEBUG
            end
            return { args[:cloud_id] => resp } if resp

          else
            fetch = Proc.new { |noun|
              marker = nil
              begin
                resp = MU::Cloud::AWS.rds(credentials: args[:credentials], region: args[:region]).send("describe_db_#{noun}s".to_sym)
                marker = resp.marker
                resp.send("db_#{noun}s").each { |db|
                  found[db.send("db_#{noun}_identifier".to_sym)] = db
                }
              end while marker.nil?
            }
            if !args[:cluster]
              fetch.call("instance")
            elsif args[:cluster] or !args.has_key?(:cluster)
              fetch.call("cluster")
            end
            if args[:tag_key] and args[:tag_value]
              keep = []
              found.each_pair { |id, desc|
                noun = desc.is_a?(Aws::RDS::Types::DBCluster) ? "cluster" : "db"
                resp = MU::Cloud::AWS.rds(credentials: args[:credentials], region: args[:region]).list_tags_for_resource(
                  resource_name: MU::Cloud::AWS::Database.getARN(id, noun, "rds", region: args[:region], credentials: args[:credentials])
                )
                if resp and resp.tag_list
                  resp.tag_list.each { |tag|
                    if tag.key == args[:tag_key] and tag.value == args[:tag_value]
                      keep << id
                      break
                    end
                  }
                end
              }
              found.reject! { |k, _v| !keep.include?(k) }
            end
          end

          return found
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
        def self.getARN(resource, resource_type, client_type, region: MU.curRegion, account_number: nil, credentials: nil)
          account_number ||= MU::Cloud::AWS.credToAcct(credentials)
          aws_str = MU::Cloud::AWS.isGovCloud?(region) ? "aws-us-gov" : "aws"
          "arn:#{aws_str}:#{client_type}:#{region}:#{account_number}:#{resource_type}:#{resource}"
        end

        # Construct all our tags.
        # @return [Array]: All our standard tags and any custom tags.
        def allTags
          @tags.each_key.map { |k| { :key => k, :value => @tags[k] } }
        end

        # Create a subnet group for a database.
        def createSubnetGroup
          # Finding subnets, creating security groups/adding holes, create subnet group
          subnet_ids = []

dependencies
          raise MuError.new "Didn't find the VPC specified for #{@mu_name}", details: @config["vpc"].to_h unless @vpc

          mySubnets.each { |subnet|
            next if @config["publicly_accessible"] and subnet.private?
            subnet_ids << subnet.cloud_id
          }

          if @config['creation_style'] == "existing"
            srcdb_vpc = @config['source'].kitten.cloud_desc.db_subnet_group.vpc_id
            if srcdb_vpc != @vpc.cloud_id
              MU.log "#{self} is deploying into #{@vpc.cloud_id}, but our source database, #{@config['identifier']}, is in #{srcdb_vpc}", MU::ERR
              raise MuError, "Can't use 'existing' to deploy into a different VPC from the source database; try 'new_snapshot' instead"
            end
          end

          if subnet_ids.empty?
            raise MuError, "Couldn't find subnets in #{@vpc} to add to #{@config["subnet_group_name"]}. Make sure the subnets are valid and publicly_accessible is set correctly"
          else
            # Create subnet group
            resp = MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).create_db_subnet_group(
              db_subnet_group_name: @config["subnet_group_name"],
              db_subnet_group_description: @config["subnet_group_name"],
              subnet_ids: subnet_ids,
              tags: @tags.each_key.map { |k| { :key => k, :value => @tags[k] } }
            )
            @config["subnet_group_name"] = resp.db_subnet_group.db_subnet_group_name

            if @dependencies.has_key?('firewall_rule')
              @config["vpc_security_group_ids"] = []
              @dependencies['firewall_rule'].each_value { |sg|
                @config["vpc_security_group_ids"] << sg.cloud_id
              }
            end
          end

          allowBastionAccess
        end

        # Create a database parameter group.
        def createDBParameterGroup(cluster = false)
          params = {
            db_parameter_group_family: @config["parameter_group_family"],
            description: "Parameter group for #{@mu_name}",
            tags: @tags.each_key.map { |k| { :key => k, :value => @tags[k] } }
          }
          params[cluster ? :db_cluster_parameter_group_name : :db_parameter_group_name] = @config["parameter_group_name"]
          MU.log "Creating a #{cluster ? "cluster" : "database" } parameter group #{@config["parameter_group_name"]}"

          MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).send(cluster ? :create_db_cluster_parameter_group : :create_db_parameter_group, params)
          fieldname = cluster ? "cluster_parameter_group_parameters" : "db_parameter_group_parameters"

          if @config[fieldname] && !@config[fieldname].empty?
            params = []
            @config[fieldname].each { |item|
              params << {parameter_name: item['name'], parameter_value: item['value'], apply_method: item['apply_method']}
            }

            MU.log "Modifiying parameter group #{@config["parameter_group_name"]}"
            if cluster
              MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).modify_db_cluster_parameter_group(
                db_cluster_parameter_group_name: @config["parameter_group_name"],
                parameters: params
              )
            else
              MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).modify_db_parameter_group(
                db_parameter_group_name: @config["parameter_group_name"],
                parameters: params
              )
            end
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          if @config["create_cluster"]
            @config['cluster_node_count'] ||= 1
            if @config['cluster_mode'] == "serverless"
              MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).modify_current_db_cluster_capacity(
                db_cluster_identifier: @cloud_id,
                capacity: @config['cluster_node_count']
              )
            end
          else

            # Run SQL on deploy
            if @config['run_sql_on_deploy']
              run_sql_commands
            end

            # set multi-az on deploy
            if @config['multi_az_on_deploy']
              if !database.multi_az
                MU.log "Setting multi-az on #{@config['identifier']}"
                MU.retrier([Aws::RDS::Errors::InvalidParameterValue, Aws::RDS::Errors::InvalidDBInstanceState], wait: 15, max: 15) {
                  MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).modify_db_instance(
                    db_instance_identifier: @config['identifier'],
                    apply_immediately: true,
                    multi_az: true
                  )
                }
              end
            end
          end

        end

        # Generate database user, database identifier, database name based on engine-specific constraints
        # @return [String]: Name
        def self.getName(basename, type: 'dbname', config: nil)
          if type == 'dbname'
            # Apply engine-specific db name constraints
            if config["engine"] =~ /^oracle/
              (MU.seed.downcase+config["name"])[0..7]
            elsif config["engine"] =~ /^sqlserver/
              nil
            elsif config["engine"] =~ /^mysql/
              basename[0..63]
            elsif config["engine"] =~ /^aurora/
              (MU.seed.downcase+config["name"])[0..7]
            else
              basename
            end
          elsif type == 'dbuser'
            # Apply engine-specific master username constraints
            if config["engine"] =~ /^oracle/
              basename[0..29].gsub(/[^a-z0-9]/i, "")
            elsif config["engine"] =~ /^sqlserver/
              basename[0..127].gsub(/[^a-z0-9]/i, "")
            elsif config["engine"] =~ /^(mysql|maria)/
              basename[0..15].gsub(/[^a-z0-9]/i, "")
            elsif config["engine"] =~ /^aurora/
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
                MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).authorize_db_security_group_ingress(
                    db_security_group_name: rds_sg.db_security_group_name,
                    cidrip: cidr
                )
              rescue Aws::RDS::Errors::AuthorizationAlreadyExists
                MU.log "CIDR #{cidr} already in database instance #{@cloud_id} security group", MU::WARN
              end
            }
          end

          # Otherwise go get our generic EC2 ruleset and punch a hole in it
          if @dependencies.has_key?('firewall_rule')
            @dependencies['firewall_rule'].each_value { |sg|
              sg.addRule([cidr], proto: "tcp", port: cloud_desc.endpoint.port)
              break
            }
          end
        end

        # Return the metadata for this ContainerCluster
        # @return [Hash]
        def notify
          deploy_struct = MU.structToHash(cloud_desc)
          deploy_struct['cloud_id'] = @cloud_id
          deploy_struct["region"] ||= @config['region']
          deploy_struct["db_name"] ||= @config['db_name']
          deploy_struct
        end

        # Generate a snapshot from the database described in this instance.
        # @return [String]: The cloud provider's identifier for the snapshot.
        def createNewSnapshot
          snap_id = @deploy.getResourceName(@config["name"]) + Time.new.strftime("%M%S").to_s
          src_ref = MU::Config::Ref.get(@config["source"])
          src_ref.kitten(@deploy)
          if !src_ref.id
            raise MuError.new "#{@mu_name} failed to get an id from reference for creating a snapshot", details: @config['source']
          end
          params = {
            :tags => @tags.each_key.map { |k| { :key => k, :value => @tags[k] } }
          }
          if @config["create_cluster"]
            params[:db_cluster_snapshot_identifier] = snap_id
            params[:db_cluster_identifier] = src_ref.id
          else
            params[:db_snapshot_identifier] = snap_id
            params[:db_instance_identifier] = src_ref.id
          end

          MU.retrier([Aws::RDS::Errors::InvalidDBInstanceState, Aws::RDS::Errors::InvalidDBClusterStateFault], wait: 60, max: 10) {
            MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).send("create_db_#{@config['create_cluster'] ? "cluster_" : ""}snapshot".to_sym, params)
          }

          loop_if = Proc.new {
            if @config["create_cluster"]
              MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).describe_db_cluster_snapshots(db_cluster_snapshot_identifier: snap_id).db_cluster_snapshots.first.status != "available"
            else
              MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).describe_db_snapshots(db_snapshot_identifier: snap_id).db_snapshots.first.status != "available"
            end
          }

          MU.retrier(wait: 15, loop_if: loop_if) { |retries, _wait|
            MU.log "Waiting for RDS snapshot of #{src_ref.id} to be ready...", MU::NOTICE if retries % 20 == 0
          }

          return snap_id
        end

        # Fetch the latest snapshot of the database described in this instance.
        # @return [String]: The cloud provider's identifier for the snapshot.
        def getExistingSnapshot
          src_ref = MU::Config::Ref.get(@config["source"])
          resp =
            if @config["create_cluster"]
              MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).describe_db_cluster_snapshots(db_cluster_snapshot_identifier: src_ref.id)
            else
              MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).describe_db_snapshots(db_snapshot_identifier: src_ref.id)
            end

          snapshots = @config["create_cluster"] ? resp.db_cluster_snapshots : resp.db_snapshots

          if snapshots.empty?
            nil
          else
            sorted_snapshots = snapshots.sort_by { |snap| snap.snapshot_create_time }
            @config["create_cluster"] ? sorted_snapshots.last.db_cluster_snapshot_identifier : sorted_snapshots.last.db_snapshot_identifier
          end
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
          MU::Cloud::RELEASE
        end

        # @return [Array<Thread>]
        def self.threaded_resource_purge(describe_method, list_method, id_method, arn_type, region, credentials, ignoremaster)
          deletia = []

          resp = MU::Cloud::AWS.rds(credentials: credentials, region: region).send(describe_method)
          resp.send(list_method).each { |resource|
            begin
              arn = MU::Cloud::AWS::Database.getARN(resource.send(id_method), arn_type, "rds", region: region, credentials: credentials)
              tags = MU::Cloud::AWS.rds(credentials: credentials, region: region).list_tags_for_resource(resource_name: arn).tag_list
            rescue Aws::RDS::Errors::InvalidParameterValue
              MU.log "Failed to fetch ARN of type #{arn_type} or tags of resource via #{id_method}", MU::WARN, details: [resource, arn]
              next
            end

            if should_delete?(tags, ignoremaster)
              deletia << resource.send(id_method)
            end
          }

          threads = []
          deletia.each { |id|
            threads << Thread.new(id) { |resource_id|
              yield(resource_id)
            }
          }

          threads
        end

        # Called by {MU::Cleanup}. Locates resources that were created by the
        # currently-loaded deployment, and purges them.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region in which to operate
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, credentials: nil, region: MU.curRegion, flags: {})

          ["instance", "cluster"].each { |type|
            threaded_resource_purge("describe_db_#{type}s".to_sym, "db_#{type}s".to_sym, "db_#{type}_identifier".to_sym, (type == "instance" ? "db" : "cluster"), region, credentials, ignoremaster) { |id|
              terminate_rds_instance(nil, noop: noop, skipsnapshots: flags["skipsnapshots"], region: region, deploy_id: MU.deploy_id, cloud_id: id, mu_name: id.upcase, credentials: credentials, cluster: (type == "cluster"))
  
            }.each { |t|
              t.join
            }
          }

          threads = threaded_resource_purge(:describe_db_subnet_groups, :db_subnet_groups, :db_subnet_group_name, "subgrp", region, credentials, ignoremaster) { |id|
            MU.log "Deleting RDS subnet group #{id}"
            MU.retrier([Aws::RDS::Errors::InvalidDBSubnetGroupStateFault], wait: 30, max: 5, ignoreme: [Aws::RDS::Errors::DBSubnetGroupNotFoundFault]) {
              MU::Cloud::AWS.rds(region: region).delete_db_subnet_group(db_subnet_group_name: id) if !noop
            }
          }

          ["db", "db_cluster"].each { |type|
            threads.concat threaded_resource_purge("describe_#{type}_parameter_groups".to_sym, "#{type}_parameter_groups".to_sym, "#{type}_parameter_group_name".to_sym, (type == "db" ? "pg" : "cluster-pg"), region, credentials, ignoremaster) { |id|
              MU.log "Deleting RDS #{type} parameter group #{id}"
              MU.retrier([Aws::RDS::Errors::InvalidDBParameterGroupState], wait: 30, max: 5, ignoreme: [Aws::RDS::Errors::DBParameterGroupNotFound]) {
                MU::Cloud::AWS.rds(region: region).send("delete_#{type}_parameter_group", { "#{type}_parameter_group_name".to_sym => id }) if !noop
              }
            }
          }

          # Wait for all of the databases subnet/parameter groups to finish cleanup before proceeding
          threads.each { |t|
            t.join
          }
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          rds_parameters_primitive = {
            "type" => "array",
            "minItems" => 1,
            "items" => {
              "description" => "The database parameter group parameter to change and when to apply the change.",
              "type" => "object",
              "title" => "Database Parameter",
              "required" => ["name", "value"],
              "additionalProperties" => false,
              "properties" => {
                "name" => {
                  "type" => "string"
                },
                "value" => {
                  "type" => "string"
                },
                "apply_method" => {
                  "enum" => ["pending-reboot", "immediate"],
                  "default" => "immediate",
                  "type" => "string"
                }
              }
            }
          }


          schema = {
            "db_parameter_group_parameters" => rds_parameters_primitive,
            "cluster_parameter_group_parameters" => rds_parameters_primitive,
            "parameter_group_family" => {
              "type" => "String",
              "description" => "An RDS parameter group family. See also https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithParamGroups.html"
            },
            "cluster_mode" => {
              "type" => "string",
              "description" => "The DB engine mode of the DB cluster",
              "enum" => ["provisioned", "serverless", "parallelquery", "global", "multimaster"],
              "default" => "provisioned"
            },
            "storage_type" => {
              "enum" => ["standard", "gp2", "io1"],
              "type" => "string",
              "default" => "gp2"
            },
            "cloudwatch_logs" => {
              "type" => "array",
              "items" => {
                "type" => "string",
                "enum" => ["audit", "error", "general", "slowquery", "profiler", "postgresql", "alert", "listener", "trace", "upgrade", "agent"]
              }
            },
            "serverless_scaling" => {
              "type" => "object",
              "description" => "Scaling configuration for a +serverless+ Aurora cluster",
              "default" => {
                "auto_pause" => false,
                "min_capacity" => 2,
                "max_capacity" => 2
              },
              "properties" => {
                "auto_pause" => {
                  "type" => "boolean",
                  "description" => "A value that specifies whether to allow or disallow automatic pause for an Aurora DB cluster in serverless DB engine mode",
                  "default" => false
                },
                "min_capacity" => {
                  "type" => "integer",
                  "description" => "The minimum capacity for an Aurora DB cluster in serverless DB engine mode.",
                  "default" => 2,
                  "enum" => [2, 4, 8, 16, 32, 64, 128, 256]
                },
                "max_capacity" => {
                  "type" => "integer",
                  "description" => "The maximum capacity for an Aurora DB cluster in serverless DB engine mode.",
                  "default" => 2,
                  "enum" => [2, 4, 8, 16, 32, 64, 128, 256]
                },
                "seconds_until_auto_pause" => {
                  "type" => "integer",
                  "description" => "A DB cluster can be paused only when it's idle (it has no connections). If a DB cluster is paused for more than seven days, the DB cluster might be backed up with a snapshot. In this case, the DB cluster is restored when there is a request to connect to it.",
                  "default" => 86400
                }
              }
            },
            "license_model" => {
              "type" => "string",
              "enum" => ["license-included", "bring-your-own-license", "general-public-license", "postgresql-license"]
            },
            "ingress_rules" => MU::Cloud.resourceClass("AWS", "FirewallRule").ingressRuleAddtlSchema
          }
          [toplevel_required, schema]
        end

        @@engine_cache= {}
        def self.get_supported_engines(region = MU.myRegion, credentials = nil, engine: nil)
          @@engine_cache ||= {}
          @@engine_cache[credentials] ||= {}
          @@engine_cache[credentials][region] ||= {}

          if !@@engine_cache[credentials][region].empty?
            return engine ? @@engine_cache[credentials][region][engine] : @@engine_cache[credentials][region]
          end

          engines = {}
          marker = nil

          begin
            resp = MU::Cloud::AWS.rds(credentials: credentials, region: region).describe_db_engine_versions(marker: marker)
            marker = resp.marker

            if resp and resp.db_engine_versions
              resp.db_engine_versions.each { |version|
                engines[version.engine] ||= {
                  "versions" => [],
                  "families" => [],
                  "features" => {},
                  "raw" => {}
                }
                engines[version.engine]['versions'] << version.engine_version
                engines[version.engine]['families'] << version.db_parameter_group_family
                engines[version.engine]['raw'][version.engine_version] = version
                [:supports_read_replica, :supports_log_exports_to_cloudwatch_logs].each { |feature|
                  if version.respond_to?(feature) and version.send(feature) == true
                    engines[version.engine]['features'][version.engine_version] ||= []
                    engines[version.engine]['features'][version.engine_version] << feature
                  end
                }

              }
              engines.each_key { |e|
                engines[e]["versions"].uniq!
                engines[e]["versions"].sort! { |a, b| MU.version_sort(a, b) }
                engines[e]["families"].uniq!
              }

            else
              MU.log "Failed to get list of valid RDS engine versions in #{db['region']}, proceeding without proper validation", MU::WARN
            end
          end while !marker.nil?

          @@engine_cache[credentials][region] = engines
          return engine ? @@engine_cache[credentials][region][engine] : @@engine_cache[credentials][region]
        end
        private_class_method :get_supported_engines

        # Make sure any source database/cluster/snapshot we've asked for exists
        # and is valid.
        def self.validate_source_data(db)
          ok = true

          if db['creation_style'] == "existing_snapshot" and
             !db['create_cluster'] and
             db['source'] and db["source"]["id"] and db['source']["id"].match(/:cluster-snapshot:/)
            MU.log "Database #{db['name']}: Existing snapshot #{db["source"]["id"]} looks like a cluster snapshot, but create_cluster is not set. Add 'create_cluster: true' if you're building an RDS cluster.", MU::ERR
            ok = false
          elsif db["creation_style"] == "existing" or db["creation_style"] == "new_snapshot"
            begin
              MU::Cloud::AWS.rds(region: db['region']).describe_db_instances(
                db_instance_identifier: db['source']['id']
              )
            rescue Aws::RDS::Errors::DBInstanceNotFound
              MU.log "Source database was specified for #{db['name']}, but no such database exists in #{db['region']}", MU::ERR, db['source']
              ok = false
            end
          end

          ok
        end
        private_class_method :validate_source_data

        def self.validate_master_password(db)
          maxlen = case db['engine']
            when "mariadb", "mysql"
              41
            when "postgresql"
              41
            when /oracle/
              30
            when /sqlserver/
              128
            else
              return true
          end

          pw = if !db['password'].nil?
            db['password']
          elsif db['auth_vault'] and !db['auth_vault'].empty?
            groomclass = MU::Groomer.loadGroomer(db['groomer'])
            pw = groomclass.getSecret(
              vault: db['auth_vault']['vault'],
              item: db['auth_vault']['item'],
              field: db['auth_vault']['password_field']
            )
            return true if pw.nil?
            pw
          end

          if pw and (pw.length < 8 or pw.match(/[\/\\@\s]/) or pw.length > maxlen)
            MU.log "Database password specified in 'password' or 'auth_vault' doesn't meet RDS requirements. Must be between 8 and #{maxlen} chars and have only ASCII characters other than /, @, \", or [space].", MU::ERR
            return false
          end

          true
        end
        private_class_method :validate_master_password

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::databases}, bare and unvalidated.
        # @param db [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(db, _configurator)
          ok = true

          ok = false if !validate_source_data(db)

          ok = false if !validate_engine(db)

          ok = false if !valid_read_replica?(db)

          ok = false if !valid_cloudwatch_logs?(db)

          db["license_model"] ||=
            if ["postgres", "postgresql", "aurora-postgresql"].include?(db["engine"])
              "postgresql-license"
            elsif ["mysql", "mariadb"].include?(db["engine"])
              "general-public-license"
            else
              "license-included"
            end

          ok = false if !validate_master_password(db)

          if db["multi_az_on_create"] and db["multi_az_on_deploy"]
            MU.log "Both of multi_az_on_create and multi_az_on_deploy cannot be true", MU::ERR
            ok = false
          end

          if (db["db_parameter_group_parameters"] or db["cluster_parameter_group_parameters"]) and db["parameter_group_family"].nil?
            engine = get_supported_engines(db['region'], db['credentials'], engine: db['engine'])
            db["parameter_group_family"] = engine['raw'][db['engine_version']].db_parameter_group_family
          end

          # Adding rules for Database instance storage. This varies depending on storage type and database type. 
          if !db["storage"].nil? and !db["create_cluster"] and !db["add_cluster_node"] and !STORAGE_RANGES[db["storage_type"]][db['engine']].include?(db["storage"])
            MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes from #{STORAGE_RANGES[db["storage_type"]][db['engine']]} GB for #{db["storage_type"]} volumes.", MU::ERR
            ok = false
          end

          ok = false if !validate_network_cfg(db)

          ok
        end

        private

        def genericParams
          params = if @config['create_cluster']
            paramhash = {
              db_cluster_identifier: @cloud_id,
              engine: @config["engine"],
              vpc_security_group_ids: @config["vpc_security_group_ids"],
              tags: @tags.each_key.map { |k| { :key => k, :value => @tags[k] } }
            }
            paramhash[:db_subnet_group_name] = @config["subnet_group_name"].downcase if @vpc
            if @config['cloudwatch_logs']
              paramhash[:enable_cloudwatch_logs_exports ] = @config['cloudwatch_logs']
            end
            if @config['cluster_mode']
              paramhash[:engine_mode] = @config['cluster_mode']
              if @config['cluster_mode'] == "serverless"
                paramhash[:scaling_configuration] = {
                  :auto_pause => @config['serverless_scaling']['auto_pause'],
                  :min_capacity => @config['serverless_scaling']['min_capacity'],
                  :max_capacity => @config['serverless_scaling']['max_capacity'],
                  :seconds_until_auto_pause => @config['serverless_scaling']['seconds_until_auto_pause']
                }
              end
            end
            paramhash
          else
            {
              db_instance_identifier: @cloud_id,
              db_instance_class: @config["size"],
              engine: @config["engine"],
              auto_minor_version_upgrade: @config["auto_minor_version_upgrade"],
              license_model: @config["license_model"],
              db_subnet_group_name: @config["subnet_group_name"],
              publicly_accessible: @config["publicly_accessible"],
              copy_tags_to_snapshot: true,
              tags: @tags.each_key.map { |k| { :key => k, :value => @tags[k] } }
            }
          end

          if %w{existing_snapshot new_snapshot}.include?(@config["creation_style"])
            if @config['create_cluster']
              params[:snapshot_identifier] = @config["snapshot_id"]
            else
              params[:db_snapshot_identifier] = @config["snapshot_id"]
            end
          end

          params
        end


        def self.validate_network_cfg(db)
          ok = true

          if !db['vpc']
            db["vpc"] = MU::Cloud::AWS::VPC.defaultVpc(db['region'], db['credentials'])
            if db['vpc'] and !(db['engine'].match(/sqlserver/) and db['create_read_replica'])
              MU.log "Using default VPC for database '#{db['name']}; this sets 'publicly_accessible' to true.", MU::WARN
              db['publicly_accessible'] = true
            end
          else
            if db["vpc"]["subnet_pref"] == "all_public" and !db['publicly_accessible'] and (db["vpc"]['subnets'].nil? or db["vpc"]['subnets'].empty?)
              MU.log "Setting publicly_accessible to true on database '#{db['name']}', since deploying into public subnets.", MU::WARN
              db['publicly_accessible'] = true
            elsif db["vpc"]["subnet_pref"] == "all_private" and db['publicly_accessible']
              MU.log "Setting publicly_accessible to false on database '#{db['name']}', since deploying into private subnets.", MU::NOTICE
              db['publicly_accessible'] = false
            end
            if db['engine'].match(/sqlserver/) and db['create_read_replica']
              MU.log "SQL Server does not support read replicas in VPC deployments", MU::ERR
              ok = false
            end
          end

          ok
        end
        private_class_method :validate_network_cfg

        def self.valid_read_replica?(db)
          if !db['create_read_replica'] and !db['read_replica_of']
            return true
          end

          engine = get_supported_engines(db['region'], db['credentials'], engine: db['engine'])
          if engine.nil? or !engine['features'] or !engine['features'][db['engine_version']]
            return true # we can't be sure, so let the API sort it out later
          end

          if !engine['features'][db['engine_version']].include?(:supports_read_replica)
            MU.log "Engine #{db['engine']} #{db['engine_version']} does not appear to support read replicas", MU::ERR
            return false
          end
          true
        end
        private_class_method :valid_read_replica?

        def self.valid_cloudwatch_logs?(db)
          return true if !db['cloudwatch_logs']
          engine = get_supported_engines(db['region'], db['credentials'], engine: db['engine'])
          if engine.nil? or !engine['features'] or !engine['features'][db['engine_version']] or !engine['features'][db['engine_version']].include?(:supports_read_replica)
            MU.log "CloudWatch Logs not supported for #{db['engine']} #{db['engine_version']}", MU::ERR
            return false
          end

          ok = true
          db['cloudwatch_logs'].each { |logtype|
            if !engine['raw'][db['engine_version']].exportable_log_types.include?(logtype)
              ok = false
              MU.log "CloudWatch Log type #{logtype} is not valid for #{db['engine']} #{db['engine_version']}. List of valid types:", MU::ERR, details: engine['raw'][db['engine_version']].exportable_log_types
            end
          }

          ok
        end
        private_class_method :valid_cloudwatch_logs?

        def self.validate_engine(db)
          ok = true

          if db['create_cluster'] or db["member_of_cluster"] or db["add_cluster_node"] or (db['engine'] and db['engine'].match(/aurora/))
            case db['engine']
            when "mysql", "aurora", "aurora-mysql"
              if (db['engine_version'] and db["engine_version"].match(/^5\.6/)) or db["cluster_mode"] == "serverless"
                db["engine"] = "aurora"
                db["engine_version"] = "5.6"
                db['publicly_accessible'] = false
              else
                db["engine"] = "aurora-mysql"
              end
            when /postgres/
              db["engine"] = "aurora-postgresql"
            else
              ok = false
              MU.log "#{db['engine']} is not supported for clustering", MU::ERR
            end
            db["create_cluster"] = true if !(db["member_of_cluster"] or db["add_cluster_node"])
          end

          db["engine"] = "oracle-se2" if db["engine"] == "oracle"
          db["engine"] = "sqlserver-ex" if db["engine"] == "sqlserver"

          engine_cfg = get_supported_engines(db['region'], db['credentials'], engine: db['engine'])

          if !engine_cfg or engine_cfg['versions'].empty? or engine_cfg['families'].empty?
            MU.log "RDS engine #{db['engine']} reports no supported versions in #{db['region']}", MU::ERR, details: engines.keys.sort
            return false
          end

          # Resolve or default our engine version to something reasonable
          db['engine_version'] ||= engine_cfg['versions'].last
          if !engine_cfg['versions'].include?(db["engine_version"])
            db['engine_version'] = engine_cfg['versions'].grep(/^#{Regexp.quote(db["engine_version"])}/).last
          end
          if !engine_cfg['versions'].include?(db["engine_version"])
            MU.log "RDS engine '#{db['engine']}' version '#{db['engine_version']}' is not supported in #{db['region']}", MU::ERR, details: { "Known-good versions:" => engine_cfg['versions'].uniq.sort }
            ok = false
          end

          if db["parameter_group_family"] and
             !engine_cfg['families'].include?(db['parameter_group_family'])
            MU.log "RDS engine '#{db['engine']}' parameter group family '#{db['parameter_group_family']}' is not supported.", MU::ERR, details: engine_cfg['families'].uniq.sort
            ok = false
          end

          ok
        end
        private_class_method :validate_engine

        def add_basic

          getPassword
          if @config['source'].nil? or @config['region'] != @config['source'].region
            createSubnetGroup if @vpc
          else
            MU.log "Note: Read Replicas automatically reside in the same subnet group as the source database, if they're both in the same region. This replica may not land in the VPC you intended.", MU::WARN
          end

          if @config.has_key?("parameter_group_family")
            @config["parameter_group_name"] = @mu_name
            createDBParameterGroup
          end

          createDb
        end


        def add_cluster_node
          cluster = MU::Config::Ref.get(@config["member_of_cluster"]).kitten(@deploy, debug: true)
          if cluster.nil? or cluster.cloud_id.nil?
            raise MuError.new "Failed to resolve parent cluster of #{@mu_name}", details: @config["member_of_cluster"].to_h
          end

          @config['cluster_identifier'] = cluster.cloud_id.downcase
          # We're overriding @config["subnet_group_name"] because we need each cluster member to use the cluster's subnet group instead of a unique subnet group
          @config["subnet_group_name"] = @config['cluster_identifier'] if @vpc
          @config["creation_style"] = "new" if @config["creation_style"] != "new"
          if @config.has_key?("parameter_group_family")
            @config["parameter_group_name"] = @mu_name
            createDBParameterGroup
          end

          createDb
        end

        # creation_style = new, existing, new_snapshot, existing_snapshot
        def create_basic
          params = genericParams
          params[:storage_encrypted] = @config["storage_encrypted"]
          params[:master_user_password] = @config['password']
          params[:engine_version] = @config["engine_version"]
          params[:vpc_security_group_ids] = @config["vpc_security_group_ids"]
          params[:preferred_maintenance_window] = @config["preferred_maintenance_window"] if @config["preferred_maintenance_window"]

          if @config['create_cluster']
            params[:database_name] = @config["db_name"]
            params[:db_cluster_parameter_group_name] = @config["parameter_group_name"] if @config["parameter_group_name"]
          else
            params[:db_name] = @config["db_name"] if !@config['add_cluster_node']
            params[:db_parameter_group_name] = @config["parameter_group_name"] if @config["parameter_group_name"]
          end

          if @config['create_cluster'] or @config['add_cluster_node']
            params[:db_cluster_identifier] = @config["cluster_identifier"]
          else
            params[:storage_type] = @config["storage_type"] 
            params[:allocated_storage] = @config["storage"]
            params[:multi_az] = @config['multi_az_on_create']
          end

          if !@config['add_cluster_node']
            params[:backup_retention_period] = @config["backup_retention_period"]
            params[:preferred_backup_window] = @config["preferred_backup_window"]
            params[:master_username] = @config['master_user']
            params[:port] = @config["port"] if @config["port"]
            params[:iops] = @config["iops"] if @config['storage_type'] == "io1"
          end

          noun = @config['create_cluster'] ? "cluster" : "instance"

          MU.retrier([Aws::RDS::Errors::InvalidParameterValue], max: 5, wait: 10) {
            if %w{existing_snapshot new_snapshot}.include?(@config["creation_style"])
              [:storage_encrypted, :master_user_password, :engine_version, :allocated_storage, :backup_retention_period, :preferred_backup_window, :master_username, :db_name, :database_name].each { |p| params.delete(p) }
              MU.log "Creating database #{noun} #{@cloud_id} from snapshot #{@config["snapshot_id"]}"
              MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).send("restore_db_#{noun}_from_#{noun == "instance" ? "db_" : ""}snapshot".to_sym, params)
            else
              MU.log "Creating pristine database #{noun} #{@cloud_id} (#{@config['name']}) in #{@config['region']}"
              MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).send("create_db_#{noun}".to_sym, params)
            end
          }
        end

        # creation_style = point_in_time
        def create_point_in_time
          @config["source"].kitten(@deploy, debug: true)
          if !@config["source"].id
            raise MuError.new "Database '#{@config['name']}' couldn't resolve cloud id for source database", details: @config["source"].to_h
          end

          params = genericParams
          params.delete(:db_instance_identifier)
          if @config['create_cluster']
            params[:source_db_cluster_identifier] = @config["source"].id
            params[:restore_to_time] = @config["restore_time"] unless @config["restore_time"] == "latest"
          else
            params[:source_db_instance_identifier] = @config["source"].id
            params[:target_db_instance_identifier] = @cloud_id
          end
          params[:restore_time] = @config['restore_time'] unless @config["restore_time"] == "latest"
          params[:use_latest_restorable_time] = true if @config['restore_time'] == "latest"


          MU.retrier([Aws::RDS::Errors::InvalidParameterValue], max: 15, wait: 20) {
            MU.log "Creating database #{@config['create_cluster'] ? "cluster" : "instance" } #{@cloud_id} based on point in time backup '#{@config['restore_time']}' of #{@config['source'].id}"
            MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).send("restore_db_#{@config['create_cluster'] ? "cluster" : "instance"}_to_point_in_time".to_sym, params)
          }
        end

        # creation_style = new, existing and read_replica_of is not nil
        def create_read_replica
          @config["source"].kitten(@deploy, debug: true)
          if !@config["source"].id
            raise MuError.new "Database '#{@config['name']}' couldn't resolve cloud id for source database", details: @config["source"].to_h
          end

          params = {
            db_instance_identifier: @cloud_id,
            source_db_instance_identifier: @config["source"].id,
            db_instance_class: @config["size"],
            auto_minor_version_upgrade: @config["auto_minor_version_upgrade"],
            publicly_accessible: @config["publicly_accessible"],
            tags: @tags.each_key.map { |k| { :key => k, :value => @tags[k] } },
            db_subnet_group_name: @config["subnet_group_name"],
            storage_type: @config["storage_type"]
          }
          if @config["source"].region and @config['region'] != @config["source"].region
            params[:source_db_instance_identifier] = MU::Cloud::AWS::Database.getARN(@config["source"].id, "db", "rds", region: @config["source"].region, credentials: @config['credentials'])
          end

          params[:port] = @config["port"] if @config["port"]
          params[:iops] = @config["iops"] if @config['storage_type'] == "io1"

          on_retry = Proc.new { |e|
            if e.class == Aws::RDS::Errors::DBSubnetGroupNotAllowedFault
              MU.log "Being forced to use source database's subnet group: #{e.message}", MU::WARN
              params.delete(:db_subnet_group_name)
            end
          }

          MU.retrier([Aws::RDS::Errors::InvalidDBInstanceState, Aws::RDS::Errors::InvalidParameterValue, Aws::RDS::Errors::DBSubnetGroupNotAllowedFault], max: 10, wait: 30, on_retry: on_retry) {
            MU.log "Creating read replica database instance #{@cloud_id} for #{@config['source'].id}"
            MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).create_db_instance_read_replica(params)
          }
        end

        # Sit on our hands until we show as available
        def wait_until_available
          loop_if = if @config["create_cluster"]
            Proc.new { cloud_desc(use_cache: false).status != "available" }
          else
            Proc.new { cloud_desc(use_cache: false).db_instance_status != "available" }
          end
          MU.retrier(wait: 10, max: 360, loop_if: loop_if) { |retries, _wait|
            if retries > 0 and retries % 20 == 0
              MU.log "Waiting for RDS #{@config['create_cluster'] ? "cluster" : "database" } #{@cloud_id} to be ready...", MU::NOTICE
            end
          }
        end

        def do_naming
          if @config["create_cluster"]
            MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: cloud_desc.db_cluster_identifier, target: "#{cloud_desc.endpoint}.", cloudclass: MU::Cloud::Database, sync_wait: @config['dns_sync_wait'])
            MU.log "Database cluster #{@config['name']} is at #{cloud_desc.endpoint}", MU::SUMMARY
          else
            MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: cloud_desc.db_instance_identifier, target: "#{cloud_desc.endpoint.address}.", cloudclass: MU::Cloud::Database, sync_wait: @config['dns_sync_wait'])
            MU.log "Database #{@config['name']} is at #{cloud_desc.endpoint.address}", MU::SUMMARY
          end
          if @config['auth_vault']
            MU.log "knife vault show #{@config['auth_vault']['vault']} #{@config['auth_vault']['item']} for Database #{@config['name']} credentials", MU::SUMMARY
          end
        end

        # Create a plain database instance or read replica, as described in our
        # +@config+.
        # @return [String]: The cloud provider's identifier for this database instance.
        def createDb

          if @config['creation_style'] == "point_in_time"
            create_point_in_time
          elsif @config['read_replica_of']
            create_read_replica
          else
            create_basic
          end

          wait_until_available
          do_naming

          # If referencing an existing DB, insert this deploy's DB security group so it can access the thing
          if @config["creation_style"] == 'existing'
            mod_config = {}
            mod_config[:db_instance_identifier] = @cloud_id
            mod_config[:vpc_security_group_ids] = cloud_desc.vpc_security_groups.map { |sg| sg.vpc_security_group_id }

            localdeploy_rule =  @deploy.findLitterMate(type: "firewall_rule", name: "database"+@config['name'])
            if localdeploy_rule.nil?
              raise MU::MuError, "Database #{@config['name']} failed to find its generic security group 'database#{@config['name']}'"
            end
            mod_config[:vpc_security_group_ids] << localdeploy_rule.cloud_id

            MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).modify_db_instance(mod_config)
            MU.log "Modified database #{@cloud_id} with new security groups: #{mod_config}", MU::NOTICE
          end

          # When creating from a snapshot or replicating an existing database,
          # some of the create arguments that we'd want to carry over aren't
          # applicable- but we can apply them after the fact with a modify.
          if %w{existing_snapshot new_snapshot point_in_time}.include?(@config["creation_style"]) or @config["read_replica_of"]
            mod_config = {
              db_instance_identifier: @cloud_id,
              apply_immediately: true
            }
            if !@config["read_replica_of"] or @config['region'] == @config['source'].region
              mod_config[:vpc_security_group_ids] = @config["vpc_security_group_ids"]
            end


            if !@config["read_replica_of"]
              mod_config[:preferred_backup_window] = @config["preferred_backup_window"]
              mod_config[:backup_retention_period] = @config["backup_retention_period"]
              mod_config[:engine_version] = @config["engine_version"]
              mod_config[:allow_major_version_upgrade] = @config["allow_major_version_upgrade"] if @config['allow_major_version_upgrade']
              mod_config[:db_parameter_group_name] = @config["parameter_group_name"] if @config["parameter_group_name"]
              mod_config[:master_user_password] = @config['password']
              mod_config[:allocated_storage] = @config["storage"] if @config["storage"]
            end
            if @config["preferred_maintenance_window"]
              mod_config[:preferred_maintenance_window] = @config["preferred_maintenance_window"]
            end

            MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).modify_db_instance(mod_config)
            wait_until_available
          end

          # Maybe wait for DB instance to be in available state. DB should still be writeable at this state
          if @config['allow_major_version_upgrade'] && @config["creation_style"] == "new"
            MU.log "Setting major database version upgrade on #{@cloud_id}'"

            MU::Cloud::AWS.rds(region: @config['region'], credentials: @config['credentials']).modify_db_instance(
              db_instance_identifier: @cloud_id,
              apply_immediately: true,
              allow_major_version_upgrade: true
            )
          end

          MU.log "Database #{@config['name']} (#{@mu_name}) is ready to use"
          @cloud_id
        end

        def run_sql_commands
          MU.log "Running initial SQL commands on #{@config['name']}", details: @config['run_sql_on_deploy']

          port = address = nil

          if !cloud_desc.publicly_accessible and @vpc
            if @config['vpc']['nat_host_name']
              keypairname, _ssh_private_key, _ssh_public_key = @deploy.SSHKey
              begin
                gateway = Net::SSH::Gateway.new(
                  @config['vpc']['nat_host_name'],
                  @config['vpc']['nat_ssh_user'],
                  :keys => [Etc.getpwuid(Process.uid).dir+"/.ssh"+"/"+keypairname],
                  :keys_only => true,
                  :auth_methods => ['publickey']
                )
                port = gateway.open(cloud_desc.endpoint.address, cloud_desc.endpoint.port)
                address = "127.0.0.1"
                MU.log "Tunneling #{@config['engine']} connection through #{@config['vpc']['nat_host_name']} via local port #{port}", MU::DEBUG
              rescue IOError => e
                MU.log "Got #{e.inspect} while connecting to #{@mu_name} through NAT #{@config['vpc']['nat_host_name']}", MU::ERR
                return
              end
            else
              MU.log "Can't run initial SQL commands! Database #{@mu_name} is not publicly accessible, but we have no NAT host for connecting to it", MU::WARN, details: @config['run_sql_on_deploy']
              return
            end
          else
            port = database.endpoint.port
            address = database.endpoint.address
          end

          # Running SQL on deploy
          if @config['engine'] =~ /postgres/
            MU::Cloud::AWS::Database.run_sql_postgres(address, port, @config['master_user'], @config['password'], cloud_desc.db_name, @config['run_sql_on_deploy'], @config['name'])
          elsif @config['engine'] =~ /mysql|maria/
            MU::Cloud::AWS::Database.run_sql_mysql(address, port, @config['master_user'], @config['password'], cloud_desc.db_name, @config['run_sql_on_deploy'], @config['name'])
          end

          # close the SQL on deploy sessions
          if !cloud_desc.publicly_accessible
            begin
              gateway.close(port)
            rescue IOError => e
              MU.log "Failed to close ssh session to NAT after running sql_on_deploy", MU::ERR, details: e.inspect
            end
          end
        end

        def self.run_sql_postgres(address, port, user, password, db, cmds = [], identifier = nil)
          identifier ||= address
          MU.log "Initiating postgres connection to #{address}:#{port} as #{user}"
          autoload :PG, 'pg'
          begin
            conn = PG::Connection.new(
              :host => address,
              :port => port,
              :user => user,
              :password => password,
              :dbname => db
            )
            cmds.each { |cmd|
              MU.log "Running #{cmd} on database #{identifier}"
              conn.exec(cmd)
            }
            conn.finish
          rescue PG::Error => e
            MU.log "Failed to run initial SQL commands on #{identifier} via #{address}:#{port}: #{e.inspect}", MU::WARN, details: conn
          end
        end
        private_class_method :run_sql_postgres

        def self.run_sql_mysql(address, port, user, password, db, cmds = [], identifier = nil)
          identifier ||= address
          autoload :Mysql, 'mysql'
          MU.log "Initiating mysql connection to #{address}:#{port} as #{user}"
          conn = Mysql.new(address, user, password, db, port)
          cmds.each { |cmd|
            MU.log "Running #{cmd} on database #{identifier}"
            conn.query(cmd)
          }
          conn.close
        end
        private_class_method :run_sql_mysql

        def self.should_delete?(tags, ignoremaster = false, deploy_id = MU.deploy_id, master_ip = MU.mu_public_ip)
          found_muid = false
          found_master = false
          tags.each { |tag|
            found_muid = true if tag.key == "MU-ID" && tag.value == deploy_id
            found_master = true if tag.key == "MU-MASTER-IP" && tag.value == master_ip
          }
          delete =
            if ignoremaster && found_muid
              true
            elsif !ignoremaster && found_muid && found_master
              true
            else
              false
            end
          delete
        end
        private_class_method :should_delete?

        # Remove an RDS database and associated artifacts
        # @param db [OpenStruct]: The cloud provider's description of the database artifact
        # @return [void]
        def self.terminate_rds_instance(db, noop: false, skipsnapshots: false, region: MU.curRegion, deploy_id: MU.deploy_id, mu_name: nil, cloud_id: nil, credentials: nil, cluster: false)
          db ||= MU::Cloud::AWS::Database.find(cloud_id: cloud_id, region: region, credentials: credentials, cluster: cluster).values.first if cloud_id
          db_obj ||= MU::MommaCat.findStray(
            "AWS",
            "database",
            region: region,
            deploy_id: deploy_id,
            cloud_id: cloud_id,
            mu_name: mu_name,
            dummy_ok: true
          ).first
          if db_obj
            cloud_id ||= db_obj.cloud_id
            db ||= db_obj.cloud_desc
          end

          raise MuError, "terminate_rds_instance requires a non-nil database descriptor (#{cloud_id})" if db.nil? or cloud_id.nil?

          MU.retrier([], wait: 60, loop_if: Proc.new { %w{creating modifying backing-up}.include?(cluster ? db.status : db.db_instance_status) }) {
            db = MU::Cloud::AWS::Database.find(cloud_id: cloud_id, region: region, credentials: credentials, cluster: cluster).values.first
            return if db.nil?
          }

          MU::Cloud.resourceClass("AWS", "DNSZone").genericMuDNSEntry(name: cloud_id, target: (cluster ? db.endpoint : db.endpoint.address), cloudclass: MU::Cloud::Database, delete: true) if !noop

          if %w{deleting deleted}.include?(cluster ? db.status : db.db_instance_status)
            MU.log "#{cloud_id} has already been terminated", MU::WARN
          else
            params = cluster ? { :db_cluster_identifier => cloud_id } : { :db_instance_identifier => cloud_id }

            if skipsnapshots or (!cluster and (db.db_cluster_identifier or db.read_replica_source_db_instance_identifier))
              MU.log "Terminating #{cluster ? "cluster" : "database" } #{cloud_id} (not saving final snapshot)"
              params[:skip_final_snapshot] = true
            else
              MU.log "Terminating #{cluster ? "cluster" : "database" } #{cloud_id} (final snapshot: #{cloud_id}-mufinal)"
              params[:skip_final_snapshot] = false
              params[:final_db_snapshot_identifier] = "#{cloud_id}-mufinal"
            end

            if !noop
              on_retry = Proc.new { |e|
                if [Aws::RDS::Errors::DBSnapshotAlreadyExists, Aws::RDS::Errors::DBClusterSnapshotAlreadyExistsFault, Aws::RDS::Errors::DBClusterQuotaExceeded].include?(e.class)
                  MU.log e.message, MU::WARN
                  params[:skip_final_snapshot] = true
                  params.delete(:final_db_snapshot_identifier)
                end
              }
              MU.retrier([Aws::RDS::Errors::InvalidDBInstanceState, Aws::RDS::Errors::DBSnapshotAlreadyExists, Aws::RDS::Errors::InvalidDBClusterStateFault], wait: 60, max: 20, on_retry: on_retry) {
                if !noop
                  cluster ? MU::Cloud::AWS.rds(region: region, credentials: credentials).delete_db_cluster(params) : MU::Cloud::AWS.rds(region: region, credentials: credentials).delete_db_instance(params)
                end
              }
              del_db = nil
              MU.retrier([], wait: 10, ignoreme: [Aws::RDS::Errors::DBInstanceNotFound], loop_if: Proc.new { del_db and ((!cluster and del_db.db_instance_status != "deleted") or (cluster and del_db.status != "deleted")) }) {
                del_db = MU::Cloud::AWS::Database.find(cloud_id: cloud_id, region: region, cluster: cluster).values.first
              }
            end
          end

          purge_rds_sgs(cloud_id, region, credentials, noop)

          purge_groomer_artifacts(db_obj, cloud_id, noop)

          MU.log "#{cloud_id} has been terminated" if !noop
        end
        private_class_method :terminate_rds_instance

        def self.purge_groomer_artifacts(db_obj, cloud_id, noop)
          return if !db_obj
          # Cleanup the database vault
          groomer = 
            if db_obj and db_obj.respond_to?(:config) and db_obj.config
              db_obj.config.has_key?("groomer") ? db_obj.config["groomer"] : MU::Config.defaultGroomer
            else
              MU::Config.defaultGroomer
            end

          groomclass = MU::Groomer.loadGroomer(groomer)
          groomclass.deleteSecret(vault: cloud_id.upcase) if !noop
        end
        private_class_method :purge_groomer_artifacts

        def self.purge_rds_sgs(cloud_id, region, credentials, noop)
          rdssecgroups = []
          begin
            secgroup = MU::Cloud::AWS.rds(region: region, credentials: credentials).describe_db_security_groups(db_security_group_name: cloud_id)
            rdssecgroups << cloud_id if !secgroup.nil?
          rescue Aws::RDS::Errors::DBSecurityGroupNotFound
            MU.log "No such RDS security group #{cloud_id} to purge", MU::DEBUG
          end

          # RDS security groups can depend on EC2 security groups, do these last
          rdssecgroups.each { |sg|
            MU.log "Removing RDS Security Group #{sg}"
            begin
              MU::Cloud::AWS.rds(region: region, credentials: credentials).delete_db_security_group(db_security_group_name: sg) if !noop
            rescue Aws::RDS::Errors::DBSecurityGroupNotFound
              MU.log "RDS Security Group #{sg} disappeared before I could remove it", MU::NOTICE
            end
          }
        end
        private_class_method :purge_rds_sgs

      end #class
    end #class
  end
end #module
