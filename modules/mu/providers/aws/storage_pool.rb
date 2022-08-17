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
      # A storage pool as configured in {MU::Config::BasketofKittens::storage_pools}
      class StoragePool < MU::Cloud::StoragePool

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config['name'])
        end

        # Called automatically by {MU::Deploy#createResources}
        # @return [String]: The cloud provider's identifier for this storage pool.
        def create
          MU.log "Creating storage pool #{@mu_name}"
          resp = MU::Cloud::AWS.efs(region: @region, credentials: @credentials).create_file_system(
            creation_token: @mu_name,
            performance_mode: @config['storage_type'],
            encrypted: @config['encrypt']
          )

          attempts = 0
          loop do
            MU.log "Waiting for #{@mu_name}: #{resp.file_system_id} to become available" if attempts % 5 == 0
            storage_pool = MU::Cloud::AWS.efs(region: @region, credentials: @credentials).describe_file_systems(
              creation_token: @mu_name
            ).file_systems.first
            break if storage_pool.life_cycle_state == "available"
            raise MuError, "Failed to create storage pool #{@mu_name}" if %w{deleting deleted}.include? storage_pool.life_cycle_state
            sleep 10
            attempts += 1
            raise MuError, "timed out waiting for #{resp.mount_target_id }" if attempts >= 20
          end

          addStandardTags(cloud_id: resp.file_system_id, region: @region, credentials: @credentials)
          @cloud_id = resp.file_system_id

          if @config['mount_points'] && !@config['mount_points'].empty?
            mp_threads = []
            parent_thread_id = Thread.current.object_id
            @config['mount_points'].each { |target|
              sgs = []
              if target['add_firewall_rules']
                target['add_firewall_rules'].each { |mount_sg|
                  sg = @deploy.findLitterMate(type: "firewall_rule", name: mount_sg['name'])
                  sgs << sg.cloud_id if sg
                }
              end

              if target.has_key?("vpc") and target['vpc'].has_key?("vpc_name")
                vpc = @dependencies["vpc"][target['vpc']["vpc_name"]]
                if target['vpc']["subnet_name"]
                  subnet_obj = vpc.getSubnet(name: target['vpc']["subnet_name"])
                  if subnet_obj.nil?
                    raise MuError, "Failed to locate subnet from #{target['vpc']["subnet_name"]} in StoragePool #{@config['name']}:#{target['name']}"
                  end
                  target['vpc']['subnet_id'] = subnet_obj.cloud_id
                end
              elsif target['vpc']["subnets"] and !target['vpc']["subnets"].empty?
                target['vpc']['subnet_id'] = target['vpc']["subnets"].first["subnet_id"]
              end

              mp_threads << Thread.new {
                MU.dupGlobals(parent_thread_id)
                mount_target = MU::Cloud::AWS::StoragePool.create_mount_target(
                  cloud_id: @cloud_id,
                  ip_address: target['ip_address'],
                  subnet_id: target['vpc']['subnet_id'],
                  security_groups: sgs,
                  credentials: @credentials,
                  region: @region
                )
                target['cloud_id'] = mount_target.mount_target_id
              }
            }

            mp_threads.each { |t|
              t.join
            }
          end

          return @cloud_id
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          "arn:"+(MU::Cloud::AWS.isGovCloud?(@region) ? "aws-us-gov" : "aws")+":elasticfilesystem:"+@region+":"+MU::Cloud::AWS.credToAcct(@credentials)+":file-system/"+@cloud_id
        end

        # Locate an existing storage pool and return an array containing matching AWS resource descriptors for those that match.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching storage pool
        def self.find(**args)
          found = {}

          if args[:cloud_id]
            resp = MU::Cloud::AWS.efs(region: args[:region], credentials: args[:credentials]).describe_file_systems(
              file_system_id: args[:cloud_id]
            ).file_systems.first
            found[args[:cloud_id]] = resp if resp
          elsif args[:tag_value]
            storage_pools = MU::Cloud::AWS.efs(region: args[:region], credentials: args[:credentials]).describe_file_systems.file_systems
          
            if !storage_pools.empty?
              storage_pools.each{ |pool|
                tags = MU::Cloud::AWS.efs(region: args[:region], credentials: args[:credentials]).describe_tags(
                  file_system_id: pool.file_system_id
                ).tags

                value = nil
                tags.each{ |tag|
                  if tag.key == args[:tag_key]
                    value = tag.value
                    break
                  end
                }
                
                if value == args[:tag_value]
                  found[pool.file_system_id] = pool
                  break
                end
              }
            end
          else
            resp = MU::Cloud::AWS.efs(region: args[:region], credentials: args[:credentials]).describe_file_systems
            if resp and resp.file_systems
              resp.file_systems.each { |fs|
                found[fs.file_system_id] = fs
              }
            end
          end

          return found
        end

        # Add our standard tag set to an Amazon EFS File System.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        def addStandardTags(cloud_id: nil, region: MU.curRegion, credentials: nil)
          if cloud_id
            tags = []
            MU::MommaCat.listStandardTags.each_pair { |name, value|
              tags << {key: name, value: value}
            }

            name_tag = false
            if @config['tags']
              @config['tags'].each { |tag|
                tags << {key: tag['key'], value: tag['value']}
                name_tag = true if tag['key'] == "Name"
              }
            end

            if @config['optional_tags']
              MU::MommaCat.listOptionalTags.each_pair { |name, value|
                tags << {key: name, value: value}
              }
            end

            tags << {key: "Name", value: @mu_name} unless name_tag

            MU::Cloud::AWS.efs(region: region, credentials: credentials).create_tags(
              file_system_id: cloud_id,
              tags: tags
            )
          else
            MU.log "cloud_id not provided, not tagging resources", MU::WARN
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          #Nothing to do
        end

        # Create a mount point for an existing storage pool and attach it to a given subnet
        # @param cloud_id [String]: The cloud provider's identifier of the storage pool.
        # @param ip_address [String]: A private IP address that will be associated with mount point's network interface
        # @param subnet_id [String]: The subnet_id to associate the mount point with
        # @param security_groups [Array]: A list of security groups to associate with the mount point.
        # @param region [String]: The cloud provider region
        def self.create_mount_target(cloud_id: nil, ip_address: nil, subnet_id: nil, security_groups: [], region: MU.curRegion, credentials: nil)
          MU.log "Creating mount target for filesystem #{cloud_id}"

          resp = MU::Cloud::AWS.efs(region: region, credentials: credentials).create_mount_target(
            file_system_id: cloud_id,
            subnet_id: subnet_id,
            ip_address: ip_address,
            security_groups: security_groups
          )

          attempts = 0
          retries = 0
          loop do
            MU.log "Waiting for #{resp.mount_target_id} to become available", MU::NOTICE if attempts % 10 == 0
            begin
              mount_target = MU::Cloud::AWS.efs(region: region, credentials: credentials).describe_mount_targets(
                mount_target_id: resp.mount_target_id 
              ).mount_targets.first
            rescue Aws::EFS::Errors::MountTargetNotFound
              if retries <= 3
                sleep 10
                retry
              else
                return nil
              end
            end

            break if mount_target.life_cycle_state == "available"
            raise MuError, "Failed to create mount target #{resp.mount_target_id }" if %w{deleting deleted}.include? mount_target.life_cycle_state
            sleep 10
            attempts += 1
            raise MuError, "timed out waiting for #{resp.mount_target_id }" if attempts >= 40
          end

          return resp
        end

        # Modify the security groups associated with an existing mount point 
        # @param cloud_id [String]: The cloud provider's identifier of the mount point.
        # @param replace [TrueClass, FalseClass]: If the provided security groups will replace or be added to the existing ones
        # @param security_groups [Array]: A list of security groups to associate with the mount point.
        # @param region [String]: The cloud provider region
        def self.modify_security_groups(cloud_id: nil, replace: false , security_groups: [], region: MU.curRegion)
          unless replace
            extisting_sgs = MU::Cloud::AWS.efs(region: region).describe_mount_target_security_groups(
              mount_target_id: cloud_id
            ).security_groups

            security_groups.concat extisting_sgs
          end

          security_groups.uniq!
          MU::Cloud::AWS.efs(region: region).modify_mount_target_security_groups(
            mount_target_id: cloud_id,
            security_groups: security_groups
          )
        end

        # Register a description of this storage pool with this deployment's metadata.
        def notify
          storage_pool = MU::Cloud::AWS.efs(region: @region, credentials: @credentials).describe_file_systems(
            creation_token: @mu_name
          ).file_systems.first

          targets = {}

          if @config['mount_points'] && !@config['mount_points'].empty?
            mount_targets = MU::Cloud::AWS.efs(region: @region, credentials: @credentials).describe_mount_targets(
              file_system_id: storage_pool.file_system_id
            ).mount_targets

            @config['mount_points'].each { |mp|
              subnet = nil
              dependencies
              mp_vpc = MU::Config::Ref.get(mp['vpc']).kitten


              subnet_obj = mp_vpc.subnets.select { |s|
                s.name == mp["vpc"]["subnet_name"] or s.cloud_id == mp["vpc"]["subnet_id"]
              }.first
              if !subnet_obj
                MU.log "Failed to find live subnet matching configured mount_point", MU::WARN, details: mp["vpc"]
                next
              end
              mount_target = nil
              mount_targets.each { |t|
                subnet_cidr_obj = NetAddr::IPv4Net.parse(subnet_obj.ip_block)
                if subnet_cidr_obj.contains(NetAddr::IPv4.parse(t.ip_address))
                  mount_target = t
                  subnet = subnet_obj.cloud_desc
                  break
                end
              }
              if !mount_target
                MU.log "Failed to find live mount_target corresponding to configured mount_point", MU::WARN, details: mp
                next
              end

              targets[mp["name"]] = {
                "owner_id" => mount_target.owner_id,
                "cloud_id" => mount_target.mount_target_id,
                "file_system_id" => mount_target.file_system_id,
                "mount_directory" => mp["directory"],
                "subnet_id" => mount_target.subnet_id,
                "vpc_id" => mp_vpc.cloud_id,
                "availability_zone" => subnet.availability_zone,
                "state" => mount_target.life_cycle_state,
                "ip_address" => mount_target.ip_address,
                "endpoint" => "#{subnet.availability_zone}.#{mount_target.file_system_id}.efs.#{@region}.amazonaws.com",
                "network_interface_id" => mount_target.network_interface_id
              }
            }
          end

          deploy_struct = {
            "owner_id" => storage_pool.owner_id,
            "creation_token" => storage_pool.creation_token,
            "identifier" => storage_pool.file_system_id,
            "creation_time" => storage_pool.creation_time,
            "number_of_mount_targets" => storage_pool.number_of_mount_targets,
            "size_in_bytes" => storage_pool.size_in_bytes.value,
            "type" => storage_pool.performance_mode,
            "mount_targets" => targets
          }

          return deploy_struct
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

        # Called by {MU::Cleanup}. Locates resources that were created by the
        # currently-loaded deployment, and purges them.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region in which to operate
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU.log "AWS::StoragePool.cleanup: need to support flags['known']", MU::DEBUG, details: flags

          supported_regions = %w{us-west-2 us-east-1 eu-west-1}
          if supported_regions.include?(region)
            begin 
              resp = MU::Cloud::AWS.efs(credentials: credentials, region: region).describe_file_systems
              return if resp.nil? or resp.file_systems.nil?
              storage_pools = resp.file_systems
            rescue Aws::EFS::Errors::AccessDeniedException
              MU.log "Storage Pools not supported in this account", MU::NOTICE
              return nil
            end

            our_pools = []

            if !storage_pools.empty?
              storage_pools.each{ |pool|
                tags = MU::Cloud::AWS.efs(credentials: credentials, region: region).describe_tags(
                  file_system_id: pool.file_system_id
                ).tags

                found_muid = false
                found_master = false
                tags.each { |tag|
                  found_muid = true if tag.key == "MU-ID" && tag.value == deploy_id
                  found_master = true if tag.key == "MU-MASTER-IP" && tag.value == MU.mu_public_ip
                }
                next if !found_muid

                if ignoremaster
                  our_pools << pool if found_muid
                else
                  our_pools << pool if found_muid && found_master
                end
              }
            end

            # How to identify mount points in a reliable way? Mount points are not tagged, which means we can only reliably identify mount points based on a filesystem ID. We can you our deployment metadata, but it isn’t necessarily reliable
            # begin
              # resp = MU::Cloud::AWS.efs(credentials: credentials, region: region).delete_mount_target(
                # mount_target_id: "MountTargetId"
              # )
              # MU.log "Deleted mount target"
            # rescue Aws::EFS::Errors::BadRequest => e
              # MU.log "Mount target already deleted", MU::NOTICE if e.to_s.start_with?("invalid mount target ID")
            # end

            if !our_pools.empty?
              our_pools.each{ |pool|
                mount_targets = MU::Cloud::AWS.efs(credentials: credentials, region: region).describe_mount_targets(
                  file_system_id: pool.file_system_id
                ).mount_targets

                if !mount_targets.empty?
                  mount_targets.each{ |mp|
                    MU.log "Deleting mount target #{mp.mount_target_id} for filesystem #{pool.name}: #{pool.file_system_id}"
                    unless noop
                      begin
                        resp = MU::Cloud::AWS.efs(credentials: credentials, region: region).delete_mount_target(
                          mount_target_id: mp.mount_target_id
                          )
                      rescue Aws::EFS::Errors::BadRequest => e
                        MU.log "Mount target #{mp.mount_target_id} already deleted", MU::NOTICE if e.to_s.start_with?("invalid mount target ID")
                      end
                    end
                  }
                end

                MU.log "Deleting filesystem #{pool.name}: #{pool.file_system_id}"
                unless noop
                  attempts = 0
                  begin
                    resp = MU::Cloud::AWS.efs(credentials: credentials, region: region).delete_file_system(
                      file_system_id: pool.file_system_id
                    )
                  rescue Aws::EFS::Errors::BadRequest => e
                    MU.log "Filesystem #{pool.name}: #{pool.file_system_id} already deleted", MU::NOTICE if e.to_s.start_with?("invalid file system ID")
                  rescue Aws::EFS::Errors::FileSystemInUse
                    MU.log "Filesystem #{pool.name}: #{pool.file_system_id} is still in use, retrying", MU::NOTICE
                    sleep 10
                    attempts += 1
                    raise MuError, "Failed to delete filesystem #{pool.name}: #{pool.file_system_id}, still in use." if attempts >= 6
                    retry
                  end
                end
              }
            end
          end
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "encrypt" => {
              "type" => "boolean",
              "description" => "Encrypt EFS data at rest",
              "default" => true
            },
            "ingress_rules" => {
              "type" => "array",
              "description" => "Firewall rules to apply to our mountpoints",
              "items" => {
                "type" => "object",
                "description" => "Firewall rules to apply to our mountpoints",
                "properties" => {
                  "sgs" => {
                    "type" => "array",
                    "items" => {
                      "description" => "Other AWS Security Groups; resources that are associated with this group will have this rule applied to their traffic",
                      "type" => "string"
                    }
                  },
                  "lbs" => {
                    "type" => "array",
                    "items" => {
                      "description" => "AWS Load Balancers which will have this rule applied to their traffic",
                      "type" => "string"
                    }
                  }
                }
              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::storage_pools}, bare and unvalidated.
        # @param pool [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(pool, configurator)
          ok = true
          supported_regions = %w{us-west-2 us-east-1 us-east-2 eu-west-1}

          if !supported_regions.include?(pool['region'])
            MU.log "Region #{pool['region']} not supported. Only #{supported_regions.join(',  ')} are supported", MU::ERR
            ok = false
          end

          if pool['mount_points'] && !pool['mount_points'].empty?
            pool['mount_points'].each{ |mp|
              if mp['vpc'] and mp['vpc']['name']
                MU::Config.addDependency(pool, mp['vpc']['name'], "vpc")
              end
              if mp['ingress_rules']
                fwname = "storage-#{mp['name']}"
                acl = {
                  "name" => fwname,
                  "rules" => mp['ingress_rules'],
                  "region" => pool['region'],
                  "credentials" => pool['credentials'],
                  "optional_tags" => pool['optional_tags']
                }
                acl["tags"] = pool['tags'] if pool['tags'] && !pool['tags'].empty?
                acl["vpc"] = mp['vpc'].dup if mp['vpc']
                ok = false if !configurator.insertKitten(acl, "firewall_rules")
                mp["add_firewall_rules"] = [] if mp["add_firewall_rules"].nil?
                mp["add_firewall_rules"] << {"name" => fwname}
              end
  
            }
          end

          ok
        end

      end #class
    end #class
  end
end #module
