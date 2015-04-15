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
				if database.nil?
					raise "No such database #{@db['identifier']} exists"
				end

				MU::Database.notifyDeploy(@db["name"], @db['identifier'], @db["password"],@db["creation_style"])
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
			if !name.nil? and !MU::Deploy.deployment.nil? and !MU::Deploy.deployment['databases'].nil?
				MU.log "Looking for database #{name}", MU::DEBUG, details: MU::Deploy.deployment['databases']
				if !MU::Deploy.deployment['databases'][name].nil?
					return getDatabaseById(MU::Deploy.deployment['databases'][name]['identifier'], region: region)
				end
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
			if !@db['tags'].nil?
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
			if @db["creation_style"] == "existing_snapshot"
				snap_id = getExistingSnapshot
			end
			if @db["creation_style"] == "new_snapshot" or (@db["creation_style"] == "existing_snapshot" and snap_id == nil)
				snap_id = createNewSnapshot
			end

		  node = MU::MommaCat.getResourceName(@db["name"])

			# RDS is picky, we can't just use our regular node names for things like
			# the default schema or username. And it varies from engine to engine.
			basename = @db["name"]+@deploy.timestamp+MU.seed.downcase
			basename.gsub!(/[^a-z0-9]/i, "")
		  dbsgname = basename

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


			# Apply engine-specific instance and schema/db name constraints
			if @db["engine"].match(/^oracle/)
				dbidentifier = node.gsub(/^[^a-z]/i, "")[0..62]
			  dbname = (MU.seed.downcase+@db["name"])[0..7]
				if dbname != @db["name"]
					MU.log "Truncated dbname to #{dbname} for Oracle", MU::WARN
				end
			elsif @db["engine"].match(/^sqlserver/)
				dbidentifier = node.gsub(/[^a-z]/i, "")[0..14]
				dbname = nil
			elsif @db["engine"].match(/^mysql/)
				dbidentifier = node.gsub(/^[^a-z]/i, "")[0..62]
				dbname = basename[0..63]
			else
				dbidentifier = node.gsub(/^[^a-z]/i, "")[0..62]
				dbname = basename
			end
			dbidentifier = dbidentifier.gsub(/(--|-$)/, "")

			if dbuser != @db["name"] and snap_id.nil?
				MU.log "Truncated master username for #{dbidentifier} (db #{dbname}) to #{dbuser}", MU::WARN
			end
			@db['master_user'] = dbuser

			dbpassword = @db['password']
			if !dbpassword
			  dbpassword = @db['password'] = Password.pronounceable(10..12)
			end

			# If we didn't specify a VPC, make the distinction between EC2 Classic
			# or having a default VPC, so we can get security groups right.
			if @db['vpc'].nil?
				vpc_id = default_subnet = nil
				MU.ec2(@db['region']).describe_vpcs.vpcs.each { |vpc|
					if vpc.is_default
						vpc_id = vpc.vpc_id
						default_subnet = MU.ec2(@db['region']).describe_subnets(filters: [{:name => "vpc-id", :values => [vpc_id]}] ).subnets.first.subnet_id
						break
					end
				}
				if !default_subnet.nil? and !vpc_id.nil?
					@db['vpc'] = {
						"vpc_id" => vpc_id,
						"subnet_id" => default_subnet
					}
					using_default_vpc = true
				end
			end

			# Ok, if we're in EC2 Classic, use an old-style DB security group
			if @db['vpc'].nil?
				MU.log("Creating RDS security group #{dbsgname}")
			  db_security_group=MU.rds(@db['region']).create_db_security_group(
					{
						:db_security_group_name=>"#{dbsgname}",
						:db_security_group_description=>MU.mu_id
					}
				)
			end

		  config={
		    :db_instance_identifier => dbidentifier,
		    :db_instance_class => @db["size"],
		    :engine => @db["engine"],
		    :engine_version => @db["engine_version"],
		    :multi_az => @db['multi_az_on_create'],
		    :publicly_accessible => @db['publicly_accessible'],
		    :license_model => @db["license_model"],
		    :storage_type => @db['storage_type'],
		    :tags => []
		  }
			MU::MommaCat.listStandardTags.each_pair { |name, value|
				config[:tags] << { key: name, value: value }
			}
			if !@db['tags'].nil?
				@db['tags'].each { |tag|
					config[:tags] << { key: tag['key'], value: tag['value'] }
				}
			end
			if snap_id == nil
		    config[:allocated_storage] = @db["storage"]
		    config[:db_name] = dbname
		    config[:master_username] = dbuser
		    config[:master_user_password] = dbpassword
			end

	    config[:license_model] = @db["license_model"]


			if !@db['vpc'].nil?
				existing_vpc, vpc_name = MU::VPC.find(
					id: @db["vpc"]["vpc_id"],
					name: @db["vpc"]["vpc_name"],
					region: @db['region']
				)
				raise "Couldn't find an active VPC from #{@db['vpc']}" if existing_vpc.nil? or existing_vpc.vpc_id.nil? or existing_vpc.vpc_id.empty?
				vpc_id = existing_vpc.vpc_id
				if !@db["vpc"]["subnets"].nil?
					subnet_ids = Array.new
					@db["vpc"]["subnets"].each { |subnet|
						subnet_struct = MU::VPC.findSubnet(
							id: subnet["subnet_id"],
							name: subnet["subnet_name"],
							vpc_id: vpc_id,
							region: @db['region']
						)
						if subnet_struct.nil?
							MU.log "Couldn't find a live subnet matching #{subnet}", MU::ERR, details: MU::Deploy.deployment['subnets']
							raise "Couldn't find a live subnet matching #{subnet}"
						end
						id = subnet_struct.subnet_id
						subnet_ids << id if !id.nil?
					}
				else
					subnet_ids = MU::VPC.listSubnets(vpc_id: vpc_id, region: @db['region'])

					MU.log "No subnets specified for #{dbname}, adding to all in #{vpc_id}", MU::DEBUG, details: subnet_ids
				end
				if subnet_ids == nil or subnet_ids.size < 1
					raise "Couldn't find subnets in #{vpc_id} to add #{dbname} to"
				end

				resp = MU.rds(@db['region']).create_db_subnet_group(
					db_subnet_group_name: node,
					db_subnet_group_description: node,
					subnet_ids: subnet_ids
				)
				addStandardTags(node, "subgrp", region: @db['region'])

				config[:db_subnet_group_name] = node

				if !@db["vpc"]["nat_host_name"].nil? or !@db["vpc"]["nat_host_id"].nil?
					nat_instance, mu_name = MU::Server.find(
						id: @db["vpc"]["nat_host_id"],
						name: @db["vpc"]["nat_host_name"],
						region: @db['region']
					)
					if nat_instance.nil?
						MU.log "#{@db['name']} is configured to use #{@db['vpc']} but I can't find a running instance matching nat_host_id or nat_host_name", MU::ERR
						raise "#{@db['name']} is configured to use #{@db['vpc']} but I can't find a running instance matching nat_host_id or nat_host_name"
					end
				end
				if nat_instance.nil? 
					admin_sg = MU::FirewallRule.setAdminSG(vpc_id: vpc_id, region: @db['region'])
				else
					admin_sg = MU::FirewallRule.setAdminSG(
						vpc_id: vpc_id,
						add_admin_ip: nat_instance["private_ip_address"],
						region: @db['region']
					)
				end
				vpc_db_sg = MU::FirewallRule.createEc2SG(@db['name'], nil, description: "Database Security Group for #{dbname}", vpc_id: vpc_id, region: @db['region'])
				if snap_id == nil
					config[:vpc_security_group_ids] = [vpc_db_sg, admin_sg]
					if !@db["add_firewall_rules"].nil?
						@db["add_firewall_rules"].each { |acl|
							sg = MU::FirewallRule.find(sg_id: acl["rule_id"], name: acl["rule_name"], region: @db['region'])
							if !sg.nil?
								config[:vpc_security_group_ids] << sg.group_id
							end
						}
					end
				end
			elsif snap_id == nil
		    config[:db_security_groups] = [dbsgname]
			end

			if @db["publicly_accessible"] != nil and @db["publicly_accessible"] == true
				config[:publicly_accessible] = true
			end

		
			retries = 0
			begin
				MU.log "RDS config: #{config}", MU::DEBUG
				if snap_id != nil
					config[:db_snapshot_identifier] = snap_id
					MU.log "Creating database instance #{dbidentifier} (default db #{dbname}) from snapshot #{snap_id}"
					resp = MU.rds(@db['region']).restore_db_instance_from_db_snapshot(config)
				else
					MU.log "Creating database instance #{dbidentifier} (default db #{dbname})", details: config
				  resp = MU.rds(@db['region']).create_db_instance(config)
				end
			rescue Aws::RDS::Errors::InvalidParameterValue => e
				if retries < 5
					MU.log "Got #{e.inspect} creating #{dbidentifier}, will retry a few times in case of transient errors.", MU::WARN
					sleep 10
					retry
				else
					MU.log e.inspect, MU::ERR, details: config
					raise e
				end
			end

			begin # this ends in an ensure block that cleans up if we die
				@db['identifier'] = resp.db_instance.db_instance_identifier

				attempts = 0
				begin
					# Don't make *too* much noise to console waiting, unless asked
					if attempts % 5 == 0
						MU.log("Waiting for RDS database #{dbidentifier} to be ready...", MU::NOTICE)
					else
						MU.log("Waiting for RDS database #{dbidentifier} to be ready...", MU::DEBUG)
					end
					database = MU.rds(@db['region']).describe_db_instances(db_instance_identifier: @db['identifier'])
					attempts = attempts + 1
					sleep 60
				end while database.db_instances.first.db_instance_status != "available"
				database = database.db_instances.first

				MU::DNSZone.genericDNSEntry(database.db_instance_identifier, "#{database.endpoint.address}.", MU::Database)
				MU::DNSZone.createRecordsFromConfig(@db['dns_records'], target: database.endpoint.address)

				# When creating from a snapshot, some of the create arguments aren't
				# applicable- but we can apply them after the fact with a modify.
				if snap_id != nil
					mod_config = Hash.new
					mod_config[:db_instance_identifier] = database.db_instance_identifier
					mod_config[:apply_immediately] = true

					if database.db_subnet_group != nil and database.db_subnet_group.subnets != nil
						mod_config[:vpc_security_group_ids] = [vpc_db_sg]
						if !@db["add_firewall_rules"].nil?
							@db["add_firewall_rules"].each { |acl|
								sg = MU::FirewallRule.find(sg_id: acl["rule_id"], name: acl["rule_name"], region: @db['region'])
								if !sg.nil?
									mod_config[:vpc_security_group_ids] << sg.group_id
								end
							}
						end
					else
						mod_config[:db_security_groups] = [dbname]
					end
					if @db['password'] != nil
						mod_config[:master_user_password] = @db['password']
					end

					MU.rds(@db['region']).modify_db_instance(mod_config)
					begin
						resp = MU.rds(@db['region']).describe_db_instances(db_instance_identifier: @db['identifier'])
						mod_db = resp.data.db_instances.first
						if !mod_db.nil?
							ok = true
							if !mod_db.pending_modified_values.nil?
								mod_db.pending_modified_values.each { |val|
									ok = false if val != nil
								}
							end
							mod_db.vpc_security_groups.each { |sg|
								ok = false if sg.status != "active"
							}
						end
						if !ok
							MU.log "Modifications for #{dbidentifier} pending, waiting...", MU::DEBUG
							sleep 60
						end
					end while !ok
				end

				if vpc_id == nil
					addStandardTags(dbsgname, "secgrp", region: @db['region'])
				end

				MU::Database.notifyDeploy(@db["name"], @db['identifier'], dbpassword, @db["creation_style"], region: @db['region'])
			  MU.log("Database #{dbname} is ready to use")
				done = true
			ensure
				if !done and !database.nil?
					MU::Cleanup.terminate_rds_instance(@db['identifier'])
				end
			end

			return @db['identifier']
		end

		# Called automatically by {MU::Deploy#createResources}
		def deploy
			resp = MU.rds(@db['region']).describe_db_instances(db_instance_identifier: @db['identifier'])
			database = resp.data.db_instances.first

			if @db['run_sql_on_deploy']
				MU.log "Running initial SQL commands on #{@db['name']}", details: @db['run_sql_on_deploy']
				is_private = false
				if !database.publicly_accessible
# XXX does this actually mean what I think at the network level? verify
					is_private = true
				end
				database.db_subnet_group.subnets.each { |subnet|
					if MU::VPC.isSubnetPrivate?(subnet.subnet_identifier, region: @db['region'])
						is_private = true
					end
				}
				if @db['vpc']
					vpc_id, subnet_ids, nat_host_name, nat_ssh_user = MU::VPC.parseVPC(@db['vpc'])
				end
				ssh_keydir = Etc.getpwuid(Process.uid).dir+"/.ssh"
				keypairname, ssh_private_key, ssh_public_key = @deploy.createEc2SSHKey
				if !is_private
					port = database.endpoint.port
					address = database.endpoint.address
				else
					if !nat_host_name.nil?
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
							MU.log e.inspect, MU::ERR
							raise e
						end
					else
						MU.log "Database is in a private subnet, but we have no NAT host for connecting to it, so I can't run initial SQL commands!", MU::WARN, details: @db['run_sql_on_deploy']
						raise "Database is in a private subnet, but we have no NAT host for connecting to it, so I can't run initial SQL commands!"
					end
				end
				if @db['engine'] == "postgres"
					autoload :PG, 'pg'
					begin
						conn = PG::Connection.new(:host => address,
																			:port => port,
																			:user => @db['master_user'],
																			:dbname => "template1",
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
CAP.log "Initiating mysql connection to #{address}:#{port} as #{@db['master_user']}"
					conn = Mysql.new(address, @db['master_user'], @db['password'], "mysql", port)
					@db['run_sql_on_deploy'].each { |cmd|
						MU.log "Running #{cmd} on database #{@db['name']}"
						conn.query(cmd)
					}
					conn.close
				end
				if is_private
					begin
						gateway.close(port)
					rescue IOError => e
						MU.log e.inspect, MU::ERR
					end
				end
			end

			if @db['multi_az_on_deploy']
				if !database.multi_az
					MU.log "Setting multi-az on '#{@db['identifier']}'"
					MU.rds(@db['region']).modify_db_instance(
						db_instance_identifier: @db['identifier'],
						apply_immediately: true,
						multi_az: true
					)
				end
			end
		end


		# Permit a host to connect to the given database instance.
		# @param cidr [String]: The CIDR-formatted IP address or block to allow access.
		# @param db_id [String]: The cloud provider's identifier for this database.
		# @param region [String]: The cloud provider region
		# @return [void]
		def self.allowHost(cidr, db_id, region: MU.curRegion)
			resp = MU.rds(region).describe_db_instances(db_instance_identifier: db_id)
			database = resp.data.db_instances.first

			if database.db_security_groups != nil
				database.db_security_groups.each { |rds_sg|
					begin
					MU.rds(region).authorize_db_security_group_ingress(
						db_security_group_name: rds_sg.db_security_group_name,
						cidrip: cidr
					)
					rescue Aws::RDS::Errors::AuthorizationAlreadyExists => e
						MU.log "Got #{e.inspect} adding #{cidr} to #{db_id}", MU::WARN
					end
				}
			end

			if database.vpc_security_groups != nil
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
				"endpoint" => database.endpoint.address,
				"port" => database.endpoint.port,
				"username" => database.master_username,
				"rds_sgs" => rds_sg_ids,
				"vpc_sgs" => vpc_sg_ids,
				"az" => database.availability_zone,
				"password" => password,
				"create_style" => create_style,
				"db_name" => database.db_name
			}
			if database.db_subnet_group != nil and database.db_subnet_group.subnets != nil
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
			db_id = @db["identifier"];
			snap_id = MU::MommaCat.getResourceName(@db["name"]) + Time.new.strftime("%M%S").to_s

			retries = 0
			begin
				snapshot = MU.rds(@db['region']).create_db_snapshot(
					:db_snapshot_identifier => snap_id,
					:db_instance_identifier => db_id
				)
			rescue Aws::RDS::Errors::InvalidDBInstanceState => e
				raise e if retries >= 10
				retries = retries +1
				sleep 60
				retry
			end

			addStandardTags(snap_id, "snapshot", region: @db['region'])

			attempts = 0
			begin
				snapshot_resp = MU.rds(@db['region']).describe_db_snapshots(
					:db_snapshot_identifier => snap_id,
				)
				if attempts % 5 == 0
					MU.log("Waiting for RDS snapshot of #{db_id} to be ready...", MU::NOTICE)
				else
					MU.log("Waiting for RDS snapshot of #{db_id} to be ready...", MU::DEBUG)
				end
				sleep 60
			end while snapshot_resp.db_snapshots.first.status != "available"

			return snap_id
		end

		# Fetch the latest snapshot of the database described in this instance.
		# @return [String]: The cloud provider's identifier for the snapshot.
		def getExistingSnapshot
			resp = MU.rds(@db['region']).describe_db_snapshots(db_snapshot_identifier: @db["identifier"])
			snapshots = resp.db_snapshots
			return nil if snapshots.size == 0
			sorted_snapshots = snapshots.sort_by { |snap| snap.snapshot_create_time}
			return sorted_snapshots.last.db_snapshot_identifier
		end  
	end #class
end #module
