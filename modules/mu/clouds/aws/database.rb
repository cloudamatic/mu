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
			attr_reader :cloud_desc

			# @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
			# @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::databases}
			def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
				@deploy = mommacat
				@config = kitten_cfg
				@cloud_id ||= cloud_id
				if !mu_name.nil?
					@mu_name = mu_name
				else
					@mu_name = MU::MommaCat.getResourceName(@config["name"])
				end
			end


			# Called automatically by {MU::Deploy#createResources}
			# @return [String]: The cloud provider's identifier for this database instance.
			def create
				if @config["creation_style"] == "existing"
					database = MU::Cloud::AWS::Database.getDatabaseById(@config['identifier'])

					raise MuError, "No such database #{@config['identifier']} exists" if database.nil?
					@cloud_id = @config['db_id']

					return @cloud_id
				else
					@cloud_id = createDb
					return @cloud_id
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
				if !cloud_id.nil?
					db = getDatabaseById(cloud_id, region: region)
					if !db.nil?
						map[cloud_id] = db
						return map
					end
				end
	
				if !tag_value.nil?
					MU::Cloud::AWS.rds(region).describe_db_instances().db_instances.each { |db|
						resp = MU::Cloud::AWS.rds(region).list_tags_for_resource(
							resource_name: MU::Cloud::AWS::Database.getARN(db.db_instance_identifier, "db", region: region)
						)
						if !resp.nil? and !resp.tag_list.nil?
							resp.tag_list { |tag|
								if tag.key == tag_key and tag.value == tag_value
									map[db.db_instance_identifier] = db
								end
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

				if @config['tags']
					@config['tags'].each { |tag|
						tags << { key: tag['key'], value: tag['value'] }
					}
				end

				MU.log "Adding tags to RDS resource #{resource}: #{tags}"
				MU::Cloud::AWS.rds(region).add_tags_to_resource(
					resource_name: MU::Cloud::AWS::Database.getARN(resource, resource_type, region: region),
					tags: tags
				)
			end		

			# Create the database described in this instance
			# @return [String]: The cloud provider's identifier for this database instance.
			def createDb
				snap_id = getExistingSnapshot if @config["creation_style"] == "existing_snapshot"
				snap_id = createNewSnapshot if @config["creation_style"] == "new_snapshot" or (@config["creation_style"] == "existing_snapshot" and snap_id.nil?)
				@config["snapshot_id"] = snap_id

				# RDS is picky, we can't just use our regular node names for things like
				# the default schema or username. And it varies from engine to engine.
				basename = @config["name"]+@deploy.timestamp+MU.seed.downcase
				basename.gsub!(/[^a-z0-9]/i, "")

				# Getting engine specific names
				dbname = getName(basename, type: "dbname")
				@config['master_user'] = getName(basename, type: "dbuser")
				@config['identifier'] = getName(@mu_name, type: "dbidentifier")
				MU.log "Truncated master username for #{@config['identifier']} (db #{dbname}) to #{@config['master_user']}", MU::WARN if @config['master_user'] != @config["name"] and @config["snapshot_id"].nil?

				@config['password'] = Password.pronounceable(10..12) if @config['password'].nil?

				# Database instance config
				config={
					db_instance_identifier: @config['identifier'],
					db_instance_class: @config["size"],
					engine: @config["engine"],
					auto_minor_version_upgrade: @config["auto_minor_version_upgrade"],
					multi_az: @config['multi_az_on_create'],
					license_model: @config["license_model"],
					storage_type: @config['storage_type'],
					db_subnet_group_name: @mu_name,
					publicly_accessible: @config["publicly_accessible"],
					tags: []
				}

				MU::MommaCat.listStandardTags.each_pair { |name, value|
					config[:tags] << { key: name, value: value }
				}

				config[:iops] = @config["iops"] if @config['storage_type'] == "io1"

				# Lets make sure automatic backups are enabled when DB instance is deployed in Multi-AZ so failover actually works. Maybe default to 1 instead?
				if @config['multi_az_on_create'] or @config['multi_az_on_deploy']
					if @config["backup_retention_period"].nil? or @config["backup_retention_period"] == 0
						@config["backup_retention_period"] = 35
						MU.log "Multi-AZ deployment specified but backup retention period disabled or set to 0. Changing to #{@config["backup_retention_period"]} ", MU::WARN
					end

					if @config["preferred_backup_window"].nil?
						@config["preferred_backup_window"] = "05:00-05:30"
						MU.log "Multi-AZ deployment specified but no backup window specified. Changing to #{@config["preferred_backup_window"]} ", MU::WARN
					end
				end

				if @config["snapshot_id"].nil?
					config[:preferred_backup_window] = @config["preferred_backup_window"]
					config[:backup_retention_period] = @config["backup_retention_period"]
					config[:storage_encrypted] = @config["storage_encrypted"]
					config[:engine_version] = @config["engine_version"]
					config[:preferred_maintenance_window] = @config["preferred_maintenance_window"] if @config["preferred_maintenance_window"]
					config[:allocated_storage] = @config["storage"]
					config[:db_name] = dbname
					config[:master_username] = @config['master_user']
					config[:master_user_password] = @config['password']
				end

				db_config = createSubnetGroup(config)

				# Creating DB instance
				MU.log "RDS config: #{db_config}", MU::DEBUG
				attempts = 0
				begin
					if @config["snapshot_id"]
						db_config[:db_snapshot_identifier] = @config["snapshot_id"]
						MU.log "Creating database instance #{@config['identifier']} from snapshot #{@config["snapshot_id"]}", details: db_config
						resp = MU::Cloud::AWS.rds(@config['region']).restore_db_instance_from_db_snapshot(db_config)
					else
						MU.log "Creating database instance #{@config['identifier']}", details: db_config
						resp = MU::Cloud::AWS.rds(@config['region']).create_db_instance(db_config)
					end
				rescue Aws::RDS::Errors::InvalidParameterValue => e
					if attempts < 5
						MU.log "Got #{e.inspect} creating #{@config['identifier']}, will retry a few times in case of transient errors.", MU::WARN
						attempts += 1
						sleep 10
						retry
					else
						MU.log "Exhausted retries trying to create database instance #{@config['identifier']}", MU::ERR, details: e.inspect
					end
				end

				begin
					# this ends in an ensure block that cleans up if we die
					database = MU::Cloud::AWS::Database.getDatabaseById(@config['identifier'], region: @config['region'])
					# Calling this a second time after the DB instance is ready or DNS record creation will fail.
					wait_start_time = Time.now

					MU::Cloud::AWS.rds(@config['region']).wait_until(:db_instance_available, db_instance_identifier: @config['identifier']) do |waiter|
						# Does create_db_instance implement wait_until_available ?
						waiter.max_attempts = nil
						waiter.before_attempt do |attempts|
							MU.log "Waiting for RDS database #{@config['identifier'] } to be ready..", MU::NOTICE if attempts % 10 == 0
						end
						waiter.before_wait do |attempts, resp|
							throw :success if resp.data.db_instances.first.db_instance_status == "available"
							throw :failure if Time.now - wait_start_time > 2400
						end
					end

					database = MU::Cloud::AWS::Database.getDatabaseById(@config['identifier'], region: @config['region'])

					MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: database.db_instance_identifier, target: "#{database.endpoint.address}.", cloudclass: MU::Cloud::Database, sync_wait: @config['dns_sync_wait'])
					if !@config['dns_records'].nil?
						@config['dns_records'].each { |dnsrec|
							dnsrec['name'] = database.db_instance_identifier.downcase if !dnsrec.has_key?('name')
						}
					end
					MU::Cloud::AWS::DNSZone.createRecordsFromConfig(@config['dns_records'], target: database.endpoint.address)

					# When creating from a snapshot, some of the create arguments aren't
					# applicable- but we can apply them after the fact with a modify.
					if @config["snapshot_id"]
						mod_config = Hash.new
						mod_config[:db_instance_identifier] = database.db_instance_identifier
						mod_config[:preferred_backup_window] = @config["preferred_backup_window"]
						mod_config[:backup_retention_period] = @config["backup_retention_period"]
						mod_config[:preferred_maintenance_window] = @config["preferred_maintenance_window"] if @config["preferred_maintenance_window"]
						mod_config[:engine_version] = @config["engine_version"]
						mod_config[:allow_major_version_upgrade] = @config["allow_major_version_upgrade"] if @config['allow_major_version_upgrade']
						mod_config[:apply_immediately] = true

						if database.db_subnet_group and database.db_subnet_group.subnets and !database.db_subnet_group.subnets.empty?
							if !db_config.nil? and db_config.has_key?(:vpc_security_group_ids)
								mod_config[:vpc_security_group_ids] = db_config[:vpc_security_group_ids]
							end

							if @dependencies.has_key?('firewall_ruleset')
								if !mod_config.has_key?(:vpc_security_group_ids)
									mod_config[:vpc_security_group_ids] = []
								end
								@dependencies['firewall_ruleset'].each { |sg|
									mod_config[:vpc_security_group_ids] << sg.cloud_id
								}
							end
						# else
							# This doesn't make sense. we don't have a security group by that name, and we should only create this if we're in classic
							# mod_config[:db_security_groups] = [dbname]
						end

						mod_config[:master_user_password] = @config['password']
						MU::Cloud::AWS.rds(@config['region']).modify_db_instance(mod_config)
						
						
						MU::Cloud::AWS.rds(@config['region']).wait_until(:db_instance_available, db_instance_identifier: @config['identifier']) do |waiter|
							# Does create_db_instance implement wait_until_available ?
							waiter.max_attempts = nil
							waiter.before_attempt do |attempts|
								MU.log "Waiting for RDS database #{@config['identifier'] } to be ready..", MU::NOTICE if attempts % 10 == 0
							end
							waiter.before_wait do |attempts, resp|
								throw :success if resp.data.db_instances.first.db_instance_status == "available"
								throw :failure if Time.now - wait_start_time > 2400
							end
						end
					end

					MU.log "Database #{@config['identifier']} is ready to use"
					done = true
				ensure
					if !done and database
						MU::Cloud::AWS::Database.terminate_rds_instance(database, region: @config['region'])
					end
				end

				# Maybe wait for DB instance to be in available state. DB should still be writeable at this state
				if @config['allow_major_version_upgrade']
					MU.log "Setting major database version upgrade on #{@config['identifier']}'"
					MU::Cloud::AWS.rds(@config['region']).modify_db_instance(
						db_instance_identifier: @config['identifier'],
						apply_immediately: true,
						allow_major_version_upgrade: true
					)
				end
				
				createReadReplica if @config['read_replica']

				return @config['identifier']
			end

			# Create a subnet group for a database with the given config.
			# @param config [Hash]: The cloud provider configuration options.
			# @return [Hash]: The modified cloud provider configuration options Hash.
			def createSubnetGroup(config)
				# Finding subnets, creating security groups/adding holes, create subnet group 
				if @config['vpc'] and !@config['vpc'].empty?
					raise MuError, "Didn't find the VPC specified in #{@config['vpc']}" if @vpc.nil?

					vpc_id = @vpc.cloud_id
					subnets = []

					# Getting subnet IDs
					if !@config["vpc"]["subnets"].empty?
						@config["vpc"]["subnets"].each { |subnet|
							subnet_obj = @vpc.getSubnet(cloud_id: subnet["subnet_id"], name: subnet["subnet_name"])

							if subnet_obj.nil?
								raise MuError, "Couldn't find a live subnet matching #{subnet} in #{@vpc} (#{@vpc.subnets})"
							else
								subnets << subnet_obj
							end
						}
					else
						# This should be changed to only include subnets that will work with publicly_accessible
						@vpc.subnets.each { |subnet|
							subnets << subnet
						}
						MU.log "No subnets specified for #{@config['identifier']}, adding all subnets in #{@vpc}", MU::DEBUG, details: subnets
					end

					# Create DB subnet group
					if subnets.empty?
						raise MuError, "Couldn't find subnets in #{@vpc} to add #{@config['identifier']} to"
					else
						subnet_ids = []
						subnets.each { |subnet|
							# Make sure we aren't configuring publicly_accessible wrong.
							if subnet.private? and @config["publicly_accessible"]
								raise MuError, "Found a private subnet but publicly_accessible is set to true on #{@config['identifier']}"
							elsif !subnet.private? and !@config["publicly_accessible"]
								raise MuError, "Found a public subnet but publicly_accessible is set to false on #{@config['identifier']}"
							end
							subnet_ids << subnet.cloud_id
						}
						# Create subnet group
						resp = MU::Cloud::AWS.rds(@config['region']).create_db_subnet_group(
							db_subnet_group_name: config[:db_subnet_group_name],
							db_subnet_group_description: config[:db_subnet_group_name],
							subnet_ids: subnet_ids
						)
						addStandardTags(config[:db_subnet_group_name], "subgrp", region: @config['region'])
					end

					admin_sg = nil
# XXX this sucks, make #dependencies get this for us instead
					@deploy.kittens['firewall_rules'].each_pair { |name, acl|
						if acl.config["admin"]
							admin_sg = acl
							break
						end
					}

					# Find NAT and create holes in security groups
					if @config["vpc"]["nat_host_name"] or @config["vpc"]["nat_host_id"] or @config["vpc"]["nat_host_tag"] or @config["vpc"]["nat_host_ip"]
						nat_tag_key, nat_tag_value = @config['vpc']['nat_host_tag'].split(/=/, 2)
						nat_instance = @vpc.findBastion(
							nat_name: @config["vpc"]["nat_host_name"],
							nat_cloud_id: @config["vpc"]["nat_host_id"],
							nat_tag_key: nat_tag_key,
							nat_tag_value: nat_tag_value,
							nat_ip: @config['vpc']['nat_host_ip']
						)

						if nat_instance.nil?
							MU.log "#{node} (#{MU.deploy_id}) is configured to use #{@config['vpc']} but I can't find a matching NAT instance", MU::ERR
						end
						nat_name, nat_conf, nat_deploydata, nat_descriptor = @nat.describe
						admin_sg.addRule([nat_deploydata["private_ip_address"]], proto: "tcp")
						admin_sg.addRule([nat_deploydata["private_ip_address"]], proto: "udp")
					end

					if @config["snapshot_id"].nil?
						if @dependencies.has_key?('firewall_rule')
							if !config.has_key?(:vpc_security_group_ids)
								config[:vpc_security_group_ids] = []
							end
							@dependencies['firewall_rule'].values.each { |sg|
								config[:vpc_security_group_ids] << sg.cloud_id
							}
						end
					end
				else
					# If we didn't specify a VPC, make the distinction between EC2 Classic
					# or having a default VPC, so we can get security groups right.
					vpc_id = default_subnet = nil
					MU::Cloud::AWS.ec2(@config['region']).describe_vpcs.vpcs.each { |vpc|
						if vpc.is_default
							vpc_id = vpc.vpc_id
							default_subnet = MU::Cloud::AWS.ec2(@config['region']).describe_subnets(filters: [{:name => "vpc-id", :values => [vpc_id]}] ).subnets.first.subnet_id
							break
						end
					}
					if default_subnet and vpc_id
						@config['vpc'] = {
							"vpc_id" => vpc_id,
							"subnet_id" => default_subnet
						}
						using_default_vpc = true
					else
						# Creating an RDS secuirty group if no VPC exist. Not sure if this actually works. 
						db_sg_name = @config["name"]+@deploy.timestamp+MU.seed.downcase
						MU.log "Creating RDS security group #{db_sg_name}"
						db_security_group=MU::Cloud::AWS.rds(@config['region']).create_db_security_group(
							{
								db_security_group_name: db_sg_name,
								db_security_group_description: MU.deploy_id
							}
						)

						addStandardTags(db_sg_name, "secgrp", region: @config['region'])

						config[:db_security_groups] = [db_sg_name]
					end
				end

				return config
			end

			# Called automatically by {MU::Deploy#createResources}
			def groom
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

			# Generate database user, database identifier, database name based on engine-specific constraints
			# @return [String]: Name
			def getName(basename, type: 'dbname')
				if type == 'dbname'
					# Apply engine-specific db name constraints
					if @config["engine"].match(/^oracle/)
						dbname = (MU.seed.downcase+@config["name"])[0..7]
					elsif @config["engine"].match(/^sqlserver/)
						dbname = nil
					elsif @config["engine"].match(/^mysql/)
						dbname = basename[0..63]
					else
						dbname = basename
					end

					name = dbname
				elsif type == 'dbuser'
					# Apply engine-specific master username constraints
					if @config["engine"].match(/^oracle/)
						dbuser = basename[0..29].gsub(/[^a-z0-9]/i, "")
					elsif @config["engine"].match(/^sqlserver/)
						dbuser = basename[0..127].gsub(/[^a-z0-9]/i, "")
					elsif @config["engine"].match(/^mysql/)
						dbuser = basename[0..15].gsub(/[^a-z0-9]/i, "")
					else
						dbuser = basename.gsub(/[^a-z0-9]/i, "")
					end

					name = dbuser
				elsif type == 'dbidentifier'
					# Apply engine-specific instance name constraints
					if @config["engine"].match(/^oracle/)
						db_identifier = basename.gsub(/^[^a-z]/i, "")[0..62]
					elsif @config["engine"].match(/^sqlserver/)
						db_identifier = basename.gsub(/[^a-z]/i, "")[0..14]
					elsif @config["engine"].match(/^mysql/)
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
			# @return [void]
			def allowHost(cidr)
				mu_name, config, deploydata, cloud_desc = describe
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
						sg.addRule([cidr], proto: "tcp")
						break
					}
				end
			end

			# Retrieve the complete cloud provider description of a database instance.
			# @param db_id [String]: The cloud provider's identifier for this database.
			# @param region [String]: The cloud provider region
			# @return [OpenStruct]
			def self.getDatabaseById(db_id, region: MU.curRegion)
				resp = MU::Cloud::AWS.rds(region).describe_db_instances(db_instance_identifier: db_id)
				database = resp.data.db_instances.first
				return database
			end

			# Register a description of this database instance with this deployment's
			# metadata. Register read replicas as separate instances, while we're
			# at it.
			def notify
				my_dbs = [@config]
				if !@config['read_replica'].nil?
					@config['read_replica']['create_style'] = "read_replica"
					@config['read_replica']['password'] = @config["password"]
					my_dbs << @config['read_replica']
				end
# XXX databases probably need to be has_multiples aware if we're treating read_replicas as first-class resources
				my_dbs.each { |db|
					database = MU::Cloud::AWS::Database.getDatabaseById(db["identifier"], region: db['region'])
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
						"password" => db['password'],
						"create_style" => db['create_style'],
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

					return db_deploy_struct
				}
			end

			# Generate a snapshot from the database described in this instance.
			# @return [String]: The cloud provider's identifier for the snapshot.
			def createNewSnapshot
				snap_id = MU::MommaCat.getResourceName(@config["name"]) + Time.new.strftime("%M%S").to_s

				attempts = 0
				begin
					snapshot = MU::Cloud::AWS.rds(@config['region']).create_db_snapshot(
						db_snapshot_identifier: snap_id,
						db_instance_identifier: @config["identifier"]
					)
				rescue Aws::RDS::Errors::InvalidDBInstanceState => e
					raise MuError, e.inspect if attempts >= 10
					attempts += 1
					sleep 60
					retry
				end

				addStandardTags(snap_id, "snapshot", region: @config['region'])

				
				attempts = 0
				loop do
					MU.log "Waiting for RDS snapshot of #{@config["identifier"];} to be ready...", MU::NOTICE if attempts % 20 == 0
					MU.log "Waiting for RDS snapshot of #{@config["identifier"];} to be ready...", MU::DEBUG
					snapshot_resp = MU::Cloud::AWS.rds(@config['region']).describe_db_snapshots(
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
				resp = MU::Cloud::AWS.rds(@config['region']).describe_db_snapshots(db_snapshot_identifier: @config["identifier"])
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
				rr_name = MU::MommaCat.getResourceName(@config['read_replica']['name'])
				
				@config['read_replica']['identifier'] = getName(rr_name, type: "dbidentifier")
				@config['read_replica']['source_identifier'] = @config['identifier'] if !@config['read_replica']['source_identifier']

				replica_config = {
					db_instance_identifier: @config['read_replica']['identifier'],
					source_db_instance_identifier: @config['read_replica']['source_identifier'],
					auto_minor_version_upgrade: @config['read_replica']['auto_minor_version_upgrade'],
					storage_type: @config['read_replica']['storage_type'],
					publicly_accessible: @config['read_replica']['publicly_accessible'],
					port: @config['read_replica']['port'],
					db_instance_class: @config['read_replica']['size'],
					tags: []
				}

				if @config['read_replica']['region'] != @config['region']
					# Need to deal with case where read replica is created in different region than source DB instance.
					# Will have to create db_subnet_group_name in different region.
					# Read replica deployed in the same region as the source DB instance will inherit from source DB instance 
				end

				
				replica_config[:iops] = @config['read_replica']["iops"] if @config['read_replica']['storage_type'] == "io1"

				MU::MommaCat.listStandardTags.each_pair { |name, value|
					replica_config[:tags] << { key: name, value: value }
				}

				attempts = 0
				begin
					MU.log "Read replica RDS config: #{replica_config}", MU::DEBUG
					MU.log "Creating read replica database instance #{@config['read_replica']['identifier']} from #{@config['read_replica']['source_identifier']} database instance", details: replica_config
					resp = MU::Cloud::AWS.rds(@config['read_replica']['region']).create_db_instance_read_replica(replica_config)
				rescue Aws::RDS::Errors::InvalidParameterValue => e
					if attempts < 5
						MU.log "Got #{e.inspect} creating #{@config['read_replica']['identifier']}, will retry a few times in case of transient errors.", MU::WARN
						attempts += 1
						sleep 10
						retry
					else
						MU.log "Exhausted retries to create DB read replica #{@config['read_replica']['identifier']}, giving up", MU::ERR, details: e.inspect
						raise MuError, "Exhausted retries to create DB read replica #{@config['read_replica']['identifier']}, giving up"
					end
				end

				begin # this ends in an ensure block that cleans up if we die
					database = MU::Cloud::AWS::Database.getDatabaseById(@config['read_replica']['identifier'], region: @config['region'])
					# Calling this a second time after the DB instance is ready or DNS record creation will fail.
					wait_start_time = Time.now

					MU::Cloud::AWS.rds(@config['region']).wait_until(:db_instance_available, db_instance_identifier: @config['read_replica']['identifier']) do |waiter|
					# Does create_db_instance_read_replica implement wait_until_available ?
						waiter.max_attempts = nil
						waiter.before_attempt do |attempts|
							MU.log "Waiting for Read Replica RDS database #{@config['read_replica']['identifier']} to be ready...", MU::NOTICE if attempts % 10 == 0
						end
						waiter.before_wait do |attempts, resp|
							throw :success if resp.data.db_instances.first.db_instance_status == "available"
							throw :failure if Time.now - wait_start_time > 2400
						end
					end

					database = MU::Cloud::AWS::Database.getDatabaseById(@config['read_replica']['identifier'], region: @config['region'])

					MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: @config['read_replica']['identifier'], target: "#{database.endpoint.address}.", cloudclass: MU::Cloud::Database, sync_wait: @config['read_replica']['dns_sync_wait'])
					if !@config['read_replica']['dns_records'].nil?
						@config['read_replica']['dns_records'].each { |dnsrec|
							dnsrec['name'] = @config['read_replica']['identifier'].downcase if !dnsrec.has_key?('name')
						}
					end
					MU::Cloud::AWS::DNSZone.createRecordsFromConfig(@config['read_replica']['dns_records'], target: database.endpoint.address)

					MU.log "Database instance #{@config['read_replica']['identifier']} is ready to use"
					done = true
				ensure
					if !done and database
						MU::Cloud::AWS::Database.terminate_rds_instance(database, region: @config['read_replica']['region'])
					end
				end

				return @config['read_replica']['identifier']
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
				resp.data.db_instances.each { |db|
					db_id = db.db_instance_identifier 

					# XXX this smells
					az = db.availability_zone
					if az.nil?
						MU.log "Couldn't retrieve availability zone of RDS instance #{db_id}", MU::ERR
						MU.log "Going to try a wild guess about its region", MU::ERR
# XXX maybe we load the deployment record with Momma and use the region listed in there?  Beats a WAG.
						region = "us-east-1"
					else
						region = az.sub(/[a-z]$/, "")
					end

					db_arn = MU::Cloud::AWS::Database.getARN(db.db_instance_identifier, "db", region: region)

					begin
						db_tags = MU::Cloud::AWS.rds(region).list_tags_for_resource(resource_name: db_arn).data
					rescue Aws::RDS::Errors::DBInstanceNotFound
						next
					end
					
					found_muid = false
					found_master = false
					db_tags[:tag_list].each { |tag|
						if (tag[:key] == "MU-ID" or tag[:key] == "CAP-ID") and tag[:value] == MU.deploy_id
							found_muid = true
						end
						if (tag[:key] == "MU-MASTER-IP" or tag[:key] == "CAP-MASTER-IP") and tag[:value] == MU.mu_public_ip
							found_master = true
						end
					}
					next if !found_muid

					parent_thread_id = Thread.current.object_id
					if found_muid and (found_master or ignoremaster)
						threads << Thread.new(db) { |mydb|
							MU.dupGlobals(parent_thread_id)
							Thread.abort_on_exception = true
							MU::Cloud::AWS::Database.terminate_rds_instance(mydb, noop, skipsnapshots, region: region)
						} # thread
					end # if found_muid and found_master
				} # resp.data.db_instances.each { |db|

				# Wait for all of the databases to finish cleanup before proceeding
				threads.each { |t|
					t.join
				}
			end

			private

			# Remove an RDS database and associated artifacts
			# @param db [OpenStruct]: The cloud provider's description of the database artifact
			# @return [void]
			def self.terminate_rds_instance(db, noop = false, skipsnapshots = false, region: MU.curRegion)
				raise MuError, "terminate_rds_instance requires a non-nil database descriptor" if db.nil?

				retries = 0
				begin
					db_id = db.db_instance_identifier 
				rescue NoMethodError => e
					if retries < 30
						retries = retries + 1
						sleep 30
					else
						raise e
					end
				end
				if db_id.nil?
					MU.log "Couldn't get db_instance_identifier from '#{db}'", MU::WARN, details: caller
					return
				end

				subnet_group = nil
				begin
					if !db.db_subnet_group.nil?
						subnet_group = db.db_subnet_group.db_subnet_group_name 
					end
				rescue NoMethodError
					# ignorable for non-VPC databases
				end

				rdssecgroups = Array.new
				begin
					secgroup = MU::Cloud::AWS.rds(region).describe_db_security_groups(
						{
							:db_security_group_name => db_id
						}
					)
				rescue Aws::RDS::Errors::DBSecurityGroupNotFound
					# this is normal in VPC world
				end

				rdssecgroups << db_id if !secgroup.nil?
				db = MU::Cloud::AWS.rds(region).describe_db_instances(db_instance_identifier: db_id).data.db_instances.first

				while !noop and (db.nil? or db.db_instance_status == "creating" or db.db_instance_status == "modifying" or db.db_instance_status == "backing-up")
					MU.log "Waiting for #{db_id} to be in a removable state...", MU::NOTICE
					sleep 60
					db = MU::Cloud::AWS.rds(region).describe_db_instances(db_instance_identifier: db_id).data.db_instances.first
				end

				MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: db_id, target: db.endpoint.address, cloudclass: MU::Cloud::Database, delete: true)

				if db.db_instance_status == "deleting" or db.db_instance_status == "deleted" then
					MU.log "#{db_id} has already been terminated", MU::WARN
				else
					if !skipsnapshots
						MU.log "Terminating #{db_id} (final snapshot: #{db_id}MUfinal)"
					else
						MU.log "Terminating #{db_id} (not saving final snapshot)"
					end

					if !noop
						retries = 0
						begin
							if !skipsnapshots
								MU::Cloud::AWS.rds(region).delete_db_instance(db_instance_identifier: db_id,
																				final_db_snapshot_identifier: "#{db_id}MUfinal",
																				skip_final_snapshot: false)
							else
								MU::Cloud::AWS.rds(region).delete_db_instance(db_instance_identifier: db_id,
																				skip_final_snapshot: true)
							end
						rescue Aws::RDS::Errors::InvalidDBInstanceState => e
							MU.log "#{db_id} is not in a removable state", MU::WARN
							if retries < 5
								retries = retries + 1
								sleep 30
								retry
							else
								MU.log "#{db_id} is not in a removable state after several retries, giving up. #{e.inspect}", MU::ERR
								return
							end
						rescue Aws::RDS::Errors::DBSnapshotAlreadyExists
							MU::Cloud::AWS.rds(region).delete_db_instance(db_instance_identifier: db_id,
																			skip_final_snapshot: true)
							MU.log "Snapshot of #{db_id} already exists", MU::WARN
						rescue Aws::RDS::Errors::SnapshotQuotaExceeded
							MU::Cloud::AWS.rds(region).delete_db_instance(db_instance_identifier: db_id,
																			skip_final_snapshot: true)
							MU.log "Snapshot quota exceeded while deleting #{db_id}", MU::ERR
						end
					end
				end

				begin
					del_db = MU::Cloud::AWS.rds(region).describe_db_instances(db_instance_identifier: db_id).data.db_instances.first
					while !del_db.nil? and del_db.db_instance_status != "deleted" and !noop
						MU.log "Waiting for #{db_id} termination to complete", MU::NOTICE
						sleep 60
						del_db = MU::Cloud::AWS.rds(region).describe_db_instances(db_instance_identifier: db_id).data.db_instances.first
					end
				rescue Aws::RDS::Errors::DBInstanceNotFound
					# we are ok with this
				end

				retries = 0
				if !subnet_group.nil?
					MU.log "Deleting DB subnet group #{subnet_group}"
					begin
						MU::Cloud::AWS.rds(region).delete_db_subnet_group(db_subnet_group_name: subnet_group)
					rescue Aws::RDS::Errors::DBSubnetGroupNotFoundFault => e
						MU.log "DB subnet group #{subnet_group} disappeared before we could remove it", MU::WARN
					rescue Aws::RDS::Errors::InvalidDBSubnetGroupStateFault => e
						MU.log "DB subnet group #{subnet_group} is not in a removable state, retrying", MU::WARN
						if retries < 5
							retries = retries + 1
							sleep 30
							retry
						else
							MU.log "#{subnet_group} is not in a removable state after several retries, giving up. #{e.inspect}", MU::ERR
							return
						end				
					end
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
			end

		end #class
	end #class
	end
end #module
