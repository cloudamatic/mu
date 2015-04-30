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

	# A database as configured in {MU::Config::BasketofKittens::databases}
	class Database

		# The {MU::Config::BasketofKittens} name for a single resource of this class.
		def self.cfg_name; "database".freeze end
		# The {MU::Config::BasketofKittens} name for a collection of resources of this class.
		def self.cfg_plural; "databases".freeze end
		# Whether {MU::Deploy} should hold creation of other resources which depend on this resource until the latter has been created.
		def self.deps_wait_on_my_creation; true.freeze end
		# Whether {MU::Deploy} should hold creation of this resource until resources on which it depends have been fully created and deployed.
		def self.waits_on_parent_completion; false.freeze end

		@deploy = nil
		@db = nil

		# @param deployer [MU::Deploy]: A {MU::Deploy} object, typically associated with an in-progress deployment.
		# @param db [Hash]: The full {MU::Config} resource declaration as defined in {MU::Config::BasketofKittens::databases}
		def initialize(deployer, db)
			@deploy = deployer
			@db = db
			MU.setVar("curRegion", @db['region']) if !@db['region'].nil?
		end


		# Called automatically by {MU::Deploy#createResources}
		# @return [String]: The cloud provider's identifier for this database instance.
		def create
			if @db["creation_style"] == "existing"
				database = MU::Database.getDatabaseById(@db['identifier'])

				raise "No such database #{@db['identifier']} exists" if database.nil?

				MU::Database.notifyDeploy(@db["name"], @db['identifier'], @db["password"], @db["creation_style"])
				return @db['db_id']
			else
				return createDb
			end
		end

		# Fetch a full description of a database instance.
		# @param name [String]: The MU name of a database.
		# @param db_id [String]: The cloud provider's identifier for this database.
		# @param region [String]: The cloud provider region
		# @return [OpenStruct, nil]: The cloud provider's full description of this database resource, or nil if no such database exists.
		def self.find(name: name, db_id: db_id, region: MU.curRegion)
			# TODO expand to work with name tags like the other resources
			if name and MU::Deploy.deployment and MU::Deploy.deployment['databases']
				MU.log "Looking for database #{name}", MU::DEBUG, details: MU::Deploy.deployment['databases']
				return getDatabaseById(MU::Deploy.deployment['databases'][name]['identifier'], region: region) if MU::Deploy.deployment['databases'][name]
			end
			return nil
		end

		# Construct an Amazon Resource Name for an RDS resource. The RDS API is
		# peculiar, and we often need this identifier in order to do things that
		# the other APIs can do with shorthand.
		# @param resource [String]: The name of the resource
		# @param resource_type [String]: The type of the resource (one of `db, es, og, pg, ri, secgrp, snapshot, subgrp`)
		# @param region [String]: The region in which the resource resides.
		# @param account_number [String]: The account in which the resource resides.
		# @return [String]
		def self.getARN(resource, resource_type, region: MU.curRegion, account_number: MU.account_number)
			return "arn:aws:rds:#{region}:#{account_number}:#{resource_type}:#{resource}"
		end

		# Add our standard tag set to an Amazon RDS resource.
		# @param resource [String]: The name of the resource
		# @param resource_type [String]: The type of the resource (one of `db, es, og, pg, ri, secgrp, snapshot, subgrp`)
		# @param region [String]: The cloud provider region
		def addStandardTags(resource, resource_type, region: MU.curRegion)
			tags = []
			MU::MommaCat.listStandardTags.each_pair { |name, value|
				tags << { key: name, value: value }
			}

			if @db['tags']
				@db['tags'].each { |tag|
					tags << { key: tag['key'], value: tag['value'] }
				}
			end

			MU.log "Adding tags to RDS resource #{resource}: #{tags}"
			MU.rds(region).add_tags_to_resource(
				resource_name: MU::Database.getARN(resource, resource_type, region: region),
				tags: tags
			)
		end		

		# Create the database described in this instance
		# @return [String]: The cloud provider's identifier for this database instance.
		def createDb
			snap_id = getExistingSnapshot if @db["creation_style"] == "existing_snapshot"
			snap_id = createNewSnapshot if @db["creation_style"] == "new_snapshot" or (@db["creation_style"] == "existing_snapshot" and snap_id.nil?)
			@db["snapshot_id"] = snap_id

			db_node_name = MU::MommaCat.getResourceName(@db["name"])

			# RDS is picky, we can't just use our regular node names for things like
			# the default schema or username. And it varies from engine to engine.
			basename = @db["name"]+@deploy.timestamp+MU.seed.downcase
			basename.gsub!(/[^a-z0-9]/i, "")

			# Getting engine specific names
			dbname = getName(basename, type: "dbname")
			@db['master_user'] = getName(basename, type: "dbuser")
			@db['identifier'] = getName(db_node_name, type: "dbidentifier")
			MU.log "Truncated master username for #{@db['identifier']} (db #{dbname}) to #{@db['master_user']}", MU::WARN if @db['master_user'] != @db["name"] and @db["snapshot_id"].nil?

			@db['password'] = Password.pronounceable(10..12) if @db['password'].nil?

			# Database instance config
			config={
				db_instance_identifier: @db['identifier'],
				db_instance_class: @db["size"],
				engine: @db["engine"],
				engine_version: @db["engine_version"],
				auto_minor_version_upgrade: @db["auto_minor_version_upgrade"],
				storage_encrypted: @db["storage_encrypted"],
				multi_az: @db['multi_az_on_create'],
				license_model: @db["license_model"],
				storage_type: @db['storage_type'],
				db_subnet_group_name: db_node_name,
				publicly_accessible: @db["publicly_accessible"],
				tags: []
			}

			MU::MommaCat.listStandardTags.each_pair { |name, value|
				config[:tags] << { key: name, value: value }
			}

			config[:iops] = @db["iops"] if @db['storage_type'] == "io1"
			config[:preferred_maintenance_window] = @db["preferred_maintenance_window"] if @db["preferred_maintenance_window"]

			if @db["snapshot_id"].nil?
				config[:allocated_storage] = @db["storage"]
				config[:db_name] = dbname
				config[:master_username] = @db['master_user']
				config[:master_user_password] = @db['password']
			end
			
			# Lets make sure automatic backups are enabled when DB instance is deployed in Multi-AZ so failover actually works. Maybe default to 1 instead?
			if @db['multi_az_on_create'] or @db['multi_az_on_deploy']
				if @db["backup_retention_period"].nil? or @db["backup_retention_period"] == 0
					@db["backup_retention_period"] = 35
					MU.log "Multi-AZ deployment specified but backup retention period disabled or set to 0. Changing to #{@db["backup_retention_period"]} ", MU::WARN
				end

				if @db["preferred_backup_window"].nil?
					@db["preferred_backup_window"] = "05:00-05:30"
					MU.log "Multi-AZ deployment specified but no backup window specified. Changing to #{@db["preferred_backup_window"]} ", MU::WARN
				end
			end

			config[:preferred_backup_window] = @db["preferred_backup_window"]
			config[:backup_retention_period] = @db["backup_retention_period"]

			db_config = createSubnetGroup(config)

			# Creating DB instance
			MU.log "RDS config: #{db_config}", MU::DEBUG
			attempts = 0
			begin
				if @db["snapshot_id"]
					db_config[:db_snapshot_identifier] = @db["snapshot_id"]
					MU.log "Creating database instance #{@db['identifier']} from snapshot #{@db["snapshot_id"]}", details: db_config
					resp = MU.rds(@db['region']).restore_db_instance_from_db_snapshot(db_config)
				else
					MU.log "Creating database instance #{@db['identifier']}", details: db_config
					resp = MU.rds(@db['region']).create_db_instance(db_config)
				end
			rescue Aws::RDS::Errors::InvalidParameterValue => e
				if attempts < 5
					MU.log "Got #{e.inspect} creating #{@db['identifier']}, will retry a few times in case of transient errors.", MU::WARN
					attempts += 1
					sleep 10
					retry
				else
					MU.log "Exhausted retries trying to create database instance #{@db['identifier']}", MU::ERR, details: e.inspect
				end
			end

			begin
				# this ends in an ensure block that cleans up if we die
				database = MU::Database.getDatabaseById(@db['identifier'], region: @db['region'])
				# Calling this a second time after the DB instance is ready or DNS record creation will fail.
				wait_start_time = Time.now

				MU.rds(@db['region']).wait_until(:db_instance_available, db_instance_identifier: @db['identifier']) do |waiter|
					# Does create_db_instance implement wait_until_available ?
					waiter.max_attempts = nil
					waiter.before_attempt do |attempts|
						MU.log "Waiting for RDS database #{@db['identifier'] } to be ready..", MU::NOTICE if attempts % 10 == 0
					end
					waiter.before_wait do |attempts, resp|
						throw :success if resp.data.db_instances.first.db_instance_status == "available"
						throw :failure if Time.now - wait_start_time > 2400
					end
				end

				database = MU::Database.getDatabaseById(@db['identifier'], region: @db['region'])

				MU::DNSZone.genericDNSEntry(database.db_instance_identifier, "#{database.endpoint.address}.", MU::Database, sync_wait: @db['dns_sync_wait'])
				MU::DNSZone.createRecordsFromConfig(@db['dns_records'], target: database.endpoint.address)

				# When creating from a snapshot, some of the create arguments aren't
				# applicable- but we can apply them after the fact with a modify.
				if @db["snapshot_id"]
					mod_config = Hash.new
					mod_config[:db_instance_identifier] = database.db_instance_identifier
					mod_config[:apply_immediately] = true

					if database.db_subnet_group and database.db_subnet_group.subnets and !database.db_subnet_group.subnets.empty?
						mod_config[:vpc_security_group_ids] = [vpc_db_sg]
						if @db["add_firewall_rules"] and !@db["add_firewall_rules"].empty?
							@db["add_firewall_rules"].each { |acl|
								sg = MU::FirewallRule.find(sg_id: acl["rule_id"], name: acl["rule_name"], region: @db['region'])
								mod_config[:vpc_security_group_ids] << sg.group_id if sg
							}
						end
					# else
						# This doesn't make sense. we don't have a security group by that name, and we should only create this if we're in classic
						# mod_config[:db_security_groups] = [dbname]
					end

					mod_config[:master_user_password] = @db['password']
					MU.rds(@db['region']).modify_db_instance(mod_config)
					
					
					MU.rds(@db['region']).wait_until(:db_instance_available, db_instance_identifier: @db['identifier']) do |waiter|
						# Does create_db_instance implement wait_until_available ?
						waiter.max_attempts = nil
						waiter.before_attempt do |attempts|
							MU.log "Waiting for RDS database #{@db['identifier'] } to be ready..", MU::NOTICE if attempts % 10 == 0
						end
						waiter.before_wait do |attempts, resp|
							throw :success if resp.data.db_instances.first.db_instance_status == "available"
							throw :failure if Time.now - wait_start_time > 2400
						end
					end
				end

				MU::Database.notifyDeploy(@db["name"], @db['identifier'], @db['password'], @db["creation_style"], region: @db['region'])
				MU.log "Database #{@db['identifier']} is ready to use"
				done = true
			ensure
				if !done and database
					MU::Cleanup.terminate_rds_instance(database, region: @db['region'])
				end
			end

			# Maybe wait for DB instance to be in available state. DB should still be writeable at this state
			if @db['allow_major_version_upgrade']
				MU.log "Setting major database version upgrade on #{@db['identifier']}'"
				MU.rds(@db['region']).modify_db_instance(
					db_instance_identifier: @db['identifier'],
					apply_immediately: true,
					allow_major_version_upgrade: true
				)
			end
			
			createReadReplica if @db['read_replica']

			return @db['identifier']
		end

		def createSubnetGroup(config)
			# Finding subnets, creating security groups/adding holes, create subnet group 
			if @db['vpc'] and !@db['vpc'].empty?
				existing_vpc, vpc_name = MU::VPC.find(
					id: @db["vpc"]["vpc_id"],
					name: @db["vpc"]["vpc_name"],
					region: @db['region']
				)

				MU.log "Couldn't find an active VPC from #{@db['vpc']}", MU::ERR, details: @db['vpc'] if existing_vpc.nil? or existing_vpc.vpc_id.nil?

				vpc_id = existing_vpc.vpc_id
				subnet_ids = []

				# Getting subnet IDs
				if !@db["vpc"]["subnets"].empty?
					@db["vpc"]["subnets"].each { |subnet|
						subnet_struct = MU::VPC.findSubnet(
							id: subnet["subnet_id"],
							name: subnet["subnet_name"],
							vpc_id: vpc_id,
							region: @db['region']
						)

						if !subnet_struct
							# should this be subnet_struct.empty?
							MU.log "Couldn't find a live subnet matching #{subnet}", MU::ERR, details: MU::Deploy.deployment['subnets']
							raise "Couldn't find a live subnet matching #{subnet}"
						else
							subnet_ids << subnet_struct.subnet_id
						end
					}
				else
					# This should be changed to only include subnets that will work with publicly_accessible
					subnet_ids = MU::VPC.listSubnets(vpc_id: vpc_id, region: @db['region'])
					MU.log "No subnets specified for #{@db['identifier']}, adding all subnets in #{vpc_id}", MU::DEBUG, details: subnet_ids
				end

				# Create DB subnet group
				if subnet_ids.empty?
					MU.log "Couldn't find subnets in #{vpc_id} to add #{@db['identifier']} to", MU::ERR, details: vpc_id
					raise "Couldn't find subnets in #{vpc_id} to add #{@db['identifier']} to"
				else
					subnet_ids.each { |subnet_id|
						# Make sure we aren't configuring publicly_accessible wrong.
						if MU::VPC.isSubnetPrivate?(subnet_id, region: @db['region']) and @db["publicly_accessible"]
							MU.log "Found a private subnet but publicly_accessible is set to true on #{@db['identifier']}", MU::ERR
							raise "Found a private subnet but publicly_accessible is set to true on #{@db['identifier']}"
						elsif !MU::VPC.isSubnetPrivate?(subnet_id, region: @db['region']) and !@db["publicly_accessible"]
							MU.log "Found a public subnet but publicly_accessible is set to false on #{@db['identifier']}", MU::ERR
							raise "Found a public subnet but publicly_accessible is set to false on #{@db['identifier']}"
						end
					}

					# Create subnet group
					resp = MU.rds(@db['region']).create_db_subnet_group(
						db_subnet_group_name: config[:db_subnet_group_name],
						db_subnet_group_description: config[:db_subnet_group_name],
						subnet_ids: subnet_ids
					)
					addStandardTags(config[:db_subnet_group_name], "subgrp", region: @db['region'])
				end

				# Find NAT and create holes in security groups
				if @db["vpc"]["nat_host_name"] or @db["vpc"]["nat_host_id"]
					nat_instance, mu_name = MU::Server.find(
						id: @db["vpc"]["nat_host_id"],
						name: @db["vpc"]["nat_host_name"],
						region: @db['region']
					)

					if nat_instance.nil?
						MU.log "#{@db['name']} is configured to use #{@db['vpc']} but I can't find a running instance matching nat_host_id or nat_host_name", MU::ERR
					else
						admin_sg = MU::FirewallRule.setAdminSG(
							vpc_id: vpc_id,
							add_admin_ip: nat_instance["private_ip_address"],
							region: @db['region']
						)
					end
				else
					admin_sg = MU::FirewallRule.setAdminSG(vpc_id: vpc_id, region: @db['region'])
				end

				# Create VPC security group and add to config 
				vpc_db_sg = MU::FirewallRule.createEc2SG(@db['name'], nil, description: "Database Security Group for #{@db['name']}", vpc_id: vpc_id, region: @db['region'])
				if @db["snapshot_id"].nil?
					config[:vpc_security_group_ids] = [vpc_db_sg, admin_sg]

					if @db["add_firewall_rules"] and !@db["add_firewall_rules"].empty?
						@db["add_firewall_rules"].each { |acl|
							sg = MU::FirewallRule.find(sg_id: acl["rule_id"], name: acl["rule_name"], region: @db['region'])
							config[:vpc_security_group_ids] << sg.group_id if sg
						}
					end
				end
			else
				# If we didn't specify a VPC, make the distinction between EC2 Classic
				# or having a default VPC, so we can get security groups right.
				vpc_id = default_subnet = nil
				MU.ec2(@db['region']).describe_vpcs.vpcs.each { |vpc|
					if vpc.is_default
						vpc_id = vpc.vpc_id
						default_subnet = MU.ec2(@db['region']).describe_subnets(filters: [{:name => "vpc-id", :values => [vpc_id]}] ).subnets.first.subnet_id
						break
					end
				}
				if default_subnet and vpc_id
					@db['vpc'] = {
						"vpc_id" => vpc_id,
						"subnet_id" => default_subnet
					}
					using_default_vpc = true
				else
					# Creating an RDS secuirty group if no VPC exist. Not sure if this actually works. 
					db_sg_name = @db["name"]+@deploy.timestamp+MU.seed.downcase
					MU.log "Creating RDS security group #{db_sg_name}"
					db_security_group=MU.rds(@db['region']).create_db_security_group(
						{
							db_security_group_name: db_sg_name,
							db_security_group_description: MU.mu_id
						}
					)

					addStandardTags(db_sg_name, "secgrp", region: @db['region'])

					config[:db_security_groups] = [db_sg_name]
				end
			end

			return config
		end

		# Called automatically by {MU::Deploy#createResources}
		def deploy
			database = MU::Database.getDatabaseById(@db['identifier'], region: @db['region'])

			# Run SQL on deploy
			if @db['run_sql_on_deploy']
				MU.log "Running initial SQL commands on #{@db['name']}", details: @db['run_sql_on_deploy']

				# check if DB is private or public
				if !database.publicly_accessible
				# This doesn't necessarily mean what we think it does. publicly_accessible = true means resolve to public address.
				# publicly_accessible can still be set to true even when only private subnets are included in the subnet group. We try to solve this during creation.
					is_private = true
				else
					is_private = false
				end

				# Getting VPC info
				if @db['vpc'] and !@db['vpc'].empty?
					vpc_id, subnet_ids, nat_host_name, nat_ssh_user = MU::VPC.parseVPC(@db['vpc'])
				end

				#Setting up connection params
				ssh_keydir = Etc.getpwuid(Process.uid).dir+"/.ssh"
				keypairname, ssh_private_key, ssh_public_key = @deploy.createEc2SSHKey
				if is_private
					if nat_host_name
						begin
							proxy_cmd = "ssh -o StrictHostKeyChecking=no -W %h:%p #{nat_ssh_user}@#{nat_host_name}"
							gateway = Net::SSH::Gateway.new(
								nat_host_name,
								nat_ssh_user,
								:keys => [ssh_keydir+"/"+keypairname],
								:keys_only => true,
								:auth_methods => ['publickey'],
#								:verbose => :info
							)
							port = gateway.open(database.endpoint.address, database.endpoint.port)
							address = "127.0.0.1"
							MU.log "Tunneling #{@db['engine']} connection through #{nat_host_name} via local port #{port}", MU::DEBUG
						rescue IOError => e
							MU.log "Got #{e.inspect} while connecting to #{@db['identifier']} through NAT #{nat_host_name}", MU::ERR
						end
					else
						MU.log "Can't run initial SQL commands! Database #{@db['identifier']} is not publicly accessible, but we have no NAT host for connecting to it", MU::WARN, details: @db['run_sql_on_deploy']
					end
				else
					port = database.endpoint.port
					address = database.endpoint.address
				end

				# Running SQL on deploy
				if @db['engine'] == "postgres"
					autoload :PG, 'pg'
					begin
						conn = PG::Connection.new(
							:host => address,
							:port => port,
							:user => @db['master_user'],
							:dbname => database.db_name,
							:password => @db['password']
						)
						@db['run_sql_on_deploy'].each { |cmd|
							MU.log "Running #{cmd} on database #{@db['name']}"
							conn.exec(cmd)
						}
						conn.finish
					rescue PG::Error => e
						MU.log "Failed to run initial SQL commands on #{@db['name']} via #{address}:#{port}: #{e.inspect}", MU::WARN, details: conn
					end
				elsif @db['engine'] == "mysql"
					autoload :Mysql, 'mysql'
					MU.log "Initiating mysql connection to #{address}:#{port} as #{@db['master_user']}"
					conn = Mysql.new(address, @db['master_user'], @db['password'], "mysql", port)
					@db['run_sql_on_deploy'].each { |cmd|
						MU.log "Running #{cmd} on database #{@db['name']}"
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
			if @db['multi_az_on_deploy']
				if !database.multi_az
					MU.log "Setting multi-az on #{@db['identifier']}"
					attempts = 0
					begin
						MU.rds(@db['region']).modify_db_instance(
							db_instance_identifier: @db['identifier'],
							apply_immediately: true,
							multi_az: true
						)
					rescue Aws::RDS::Errors::InvalidParameterValue, Aws::RDS::Errors::InvalidDBInstanceState => e
						if attempts < 15
							MU.log "Got #{e.inspect} while setting Multi-AZ on #{@db['identifier']}, retrying."
							attempts += 1
							sleep 15
							retry
						else
							MU.log "Couldn't set Multi-AZ on #{@db['identifier']} after several retries, giving up. #{e.inspect}", MU::ERR
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
				if @db["engine"].match(/^oracle/)
					dbname = (MU.seed.downcase+@db["name"])[0..7]
				elsif @db["engine"].match(/^sqlserver/)
					dbname = nil
				elsif @db["engine"].match(/^mysql/)
					dbname = basename[0..63]
				else
					dbname = basename
				end

				name = dbname
			elsif type == 'dbuser'
				# Apply engine-specific master username constraints
				if @db["engine"].match(/^oracle/)
					dbuser = basename[0..29].gsub(/[^a-z0-9]/i, "")
				elsif @db["engine"].match(/^sqlserver/)
					dbuser = basename[0..127].gsub(/[^a-z0-9]/i, "")
				elsif @db["engine"].match(/^mysql/)
					dbuser = basename[0..15].gsub(/[^a-z0-9]/i, "")
				else
					dbuser = basename.gsub(/[^a-z0-9]/i, "")
				end

				name = dbuser
			elsif type == 'dbidentifier'
				# Apply engine-specific instance name constraints
				if @db["engine"].match(/^oracle/)
					db_identifier = basename.gsub(/^[^a-z]/i, "")[0..62]
				elsif @db["engine"].match(/^sqlserver/)
					db_identifier = basename.gsub(/[^a-z]/i, "")[0..14]
				elsif @db["engine"].match(/^mysql/)
					db_identifier = basename.gsub(/^[^a-z]/i, "")[0..62]
				else
					db_identifier = basename.gsub(/^[^a-z]/i, "")[0..62]
				end

				name = db_identifier.gsub(/(--|-$)/, "").gsub(/(_)/, "-")
			end

			return name
		end

		# Permit a host to connect to the given database instance.
		# @param cidr [String]: The CIDR-formatted IP address or block to allow access.
		# @param db_id [String]: The cloud provider's identifier for this database.
		# @param region [String]: The cloud provider region
		# @return [void]
		def self.allowHost(cidr, db_id, region: MU.curRegion)
			database = MU::Database.getDatabaseById(@db['identifier'], region: @db['region'])
			# resp = MU.rds(region).describe_db_instances(db_instance_identifier: db_id)
			# database = resp.data.db_instances.first

			if !database.db_security_groups.empty?
				database.db_security_groups.each { |rds_sg|
					begin
					MU.rds(region).authorize_db_security_group_ingress(
						db_security_group_name: rds_sg.db_security_group_name,
						cidrip: cidr
					)
					rescue Aws::RDS::Errors::AuthorizationAlreadyExists => e
						MU.log "CIDR #{cidr} already in database instance #{db_id} security group", MU::WARN
					end
				}
			end

			if !database.vpc_security_groups.empty?
				database.vpc_security_groups.each { |vpc_sg|
					MU::FirewallRule.addRule(vpc_sg.vpc_security_group_id, [cidr], region: region)
				}
			end
		end

		# Retrieve the complete cloud provider description of a database instance.
		# @param db_id [String]: The cloud provider's identifier for this database.
		# @param region [String]: The cloud provider region
		# @return [OpenStruct]
		def self.getDatabaseById(db_id, region: MU.curRegion)
			resp = MU.rds(region).describe_db_instances(db_instance_identifier: db_id)
			database = resp.data.db_instances.first
			return database
		end

		# Register a description of this database instance with this deployment's
		# metadata.
		# @param name [String]: The MU resource name of this database instance.
		# @param db_id [String]: The cloud provider's identifier for this database.
		# @param password [String]: The master user's password for this database, when applicable.
		# @param region [String]: The cloud provider region
		# @param create_style [String]: How the database was created. See also {MU::Config::BasketofKittens::databases#creation_style}
		def self.notifyDeploy(name, db_id, password = nil, create_style='new', region: MU.curRegion)
			database = MU::Database.getDatabaseById(db_id, region: region)

			vpc_sg_ids = Array.new
			database.vpc_security_groups.each { |vpc_sg|
				vpc_sg_ids << vpc_sg.vpc_security_group_id 
			}

			rds_sg_ids = Array.new
			database.db_security_groups.each { |rds_sg|
				rds_sg_ids << rds_sg.db_security_group_name 
			}

	  # if database is new then want database name 
			db_deploy_struct = {
				"identifier" => database.db_instance_identifier,
				"region" => region,
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
				"password" => password,
				"create_style" => create_style,
				"db_name" => database.db_name,
				"multi_az" => database.multi_az,
				"publicly_accessible" => database.publicly_accessible,
				"ca_certificate_identifier" => database.ca_certificate_identifier
			}

			if database.db_subnet_group and database.db_subnet_group.subnets
				subnet_ids = Array.new
				database.db_subnet_group.subnets.each { |subnet|
					subnet_ids <<  subnet.subnet_identifier
				}
				db_deploy_struct["subnets"] = subnet_ids
			end

			MU::Deploy.notify("databases", name, db_deploy_struct)
		end

		# Generate a snapshot from the database described in this instance.
		# @return [String]: The cloud provider's identifier for the snapshot.
		def createNewSnapshot
			snap_id = MU::MommaCat.getResourceName(@db["name"]) + Time.new.strftime("%M%S").to_s

			attempts = 0
			begin
				snapshot = MU.rds(@db['region']).create_db_snapshot(
					db_snapshot_identifier: snap_id,
					db_instance_identifier: @db["identifier"]
				)
			rescue Aws::RDS::Errors::InvalidDBInstanceState => e
				raise e if attempts >= 10
				attempts += 1
				sleep 60
				retry
			end

			addStandardTags(snap_id, "snapshot", region: @db['region'])

			
			attempts = 0
			loop do
				MU.log "Waiting for RDS snapshot of #{@db["identifier"];} to be ready...", MU::NOTICE if attempts % 20 == 0
				MU.log "Waiting for RDS snapshot of #{@db["identifier"];} to be ready...", MU::DEBUG
				snapshot_resp = MU.rds(@db['region']).describe_db_snapshots(
					db_snapshot_identifier: snap_id,
				)
				attempts += 1
				sleep 15
				break unless snapshot_resp.db_snapshots.first.status != "available"
			end

			return snap_id
		end

		# Fetch the latest snapshot of the database described in this instance.
		# @return [String]: The cloud provider's identifier for the snapshot.
		def getExistingSnapshot
			resp = MU.rds(@db['region']).describe_db_snapshots(db_snapshot_identifier: @db["identifier"])
			snapshots = resp.db_snapshots
			if snapshots.empty?
				latest_snapshot = nil
			else
				sorted_snapshots = snapshots.sort_by { |snap| snap.snapshot_create_time}
				latest_snapshot = sorted_snapshots.last.db_snapshot_identifier
			end
			
			return latest_snapshot
		end

		# Create Read Replica database instance.
		# @return [String]: The cloud provider's identifier for this read replica database instance.
		def createReadReplica
			db_node_name = MU::MommaCat.getResourceName(@db['read_replica']['name'])
			
			@db['read_replica']['identifier'] = getName(db_node_name, type: "dbidentifier")
			@db['read_replica']['source_identifier'] = @db['identifier'] if !@db['read_replica']['source_identifier']

			replica_config = {
				db_instance_identifier: @db['read_replica']['identifier'],
				source_db_instance_identifier: @db['read_replica']['source_identifier'],
				auto_minor_version_upgrade: @db['read_replica']['auto_minor_version_upgrade'],
				storage_type: @db['read_replica']['storage_type'],
				publicly_accessible: @db['read_replica']['publicly_accessible'],
				port: @db['read_replica']['port'],
				db_instance_class: @db['read_replica']['size'],
				tags: []
			}

			if @db['read_replica']['region'] != @db['region']
				# Need to deal with case where read replica is created in different region than source DB instance.
				# Will have to create db_subnet_group_name in different region.
				# Read replica deployed in the same region as the source DB instance will inherit from source DB instance 
			end

			
			replica_config[:iops] = @db['read_replica']["iops"] if @db['read_replica']['storage_type'] == "io1"

			MU::MommaCat.listStandardTags.each_pair { |name, value|
				replica_config[:tags] << { key: name, value: value }
			}

			attempts = 0
			begin
				MU.log "Read replica RDS config: #{replica_config}", MU::DEBUG
				MU.log "Creating read replica database instance #{@db['read_replica']['identifier']} from #{@db['read_replica']['source_identifier']} database instance", details: replica_config
				resp = MU.rds(@db['read_replica']['region']).create_db_instance_read_replica(replica_config)
			rescue Aws::RDS::Errors::InvalidParameterValue => e
				if attempts < 5
					MU.log "Got #{e.inspect} creating #{@db['read_replica']['identifier']}, will retry a few times in case of transient errors.", MU::WARN
					attempts += 1
					sleep 10
					retry
				else
					MU.log "Exhausted retries to create DB read replica #{@db['read_replica']['identifier']}, giving up", MU::ERR, details: e.inspect
					raise "Exhausted retries to create DB read replica #{@db['read_replica']['identifier']}, giving up"
				end
			end

			begin # this ends in an ensure block that cleans up if we die
				database = MU::Database.getDatabaseById(@db['read_replica']['identifier'], region: @db['region'])
				# Calling this a second time after the DB instance is ready or DNS record creation will fail.
				wait_start_time = Time.now

				MU.rds(@db['region']).wait_until(:db_instance_available, db_instance_identifier: @db['read_replica']['identifier']) do |waiter|
				# Does create_db_instance_read_replica implement wait_until_available ?
					waiter.max_attempts = nil
					waiter.before_attempt do |attempts|
						MU.log "Waiting for Read Replica RDS database #{@db['read_replica']['identifier']} to be ready...", MU::NOTICE if attempts % 10 == 0
					end
					waiter.before_wait do |attempts, resp|
						throw :success if resp.data.db_instances.first.db_instance_status == "available"
						throw :failure if Time.now - wait_start_time > 2400
					end
				end

				database = MU::Database.getDatabaseById(@db['read_replica']['identifier'], region: @db['region'])

				MU::DNSZone.genericDNSEntry(database.db_instance_identifier, "#{database.endpoint.address}.", MU::Database, sync_wait: @db['read_replica']['dns_sync_wait'])
				MU::DNSZone.createRecordsFromConfig(@db['read_replica']['dns_records'], target: database.endpoint.address)

				MU::Database.notifyDeploy(@db['read_replica']['name'], @db['read_replica']['identifier'], @db['password'], "read_replica", region: @db['read_replica']['region'])
				MU.log "Database instance #{@db['read_replica']['identifier']} is ready to use"
				done = true
			ensure
				if !done and database
					MU::Cleanup.terminate_rds_instance(database, region: @db['read_replica']['region'])
				end
			end

			return @db['read_replica']['identifier']
		end
	end #class
end #module
