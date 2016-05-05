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
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :cloud_id
        attr_reader :config

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::storage_pools}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config['name'])
        end

        # Called automatically by {MU::Deploy#createResources}
        # @return [String]: The cloud provider's identifier for this storage pool.
        def create            
          MU.log "Creating storage pool #{@mu_name}"
          resp = MU::Cloud::AWS.efs(@config['region']).create_file_system(
            creation_token: @mu_name
          )

          attempts = 0
          loop do
            MU.log "Waiting for #{@mu_name}: #{resp.file_system_id} to become available" if attempts % 5 == 0
            storage_pool = MU::Cloud::AWS.efs(@config['region']).describe_file_systems(
              creation_token: @mu_name
            ).file_systems.first
            break if storage_pool.life_cycle_state == "available"
            raise MuError, "Failed to create storage pool #{@mu_name}" if %w{deleting deleted}.include? storage_pool.life_cycle_state
            sleep 10
            attempts += 1
            raise MuError, "timed out waiting for #{resp.mount_target_id }" if attempts >= 20
          end

          addStandardTags(cloud_id: resp.file_system_id, region: @config['region'])
          @cloud_id = resp.file_system_id

          if @config['mount_points'] && !@config['mount_points'].empty?
            mp_threads = []
            parent_thread_id = Thread.current.object_id
            @config['mount_points'].each { |target|
              sgs = []
              if @dependencies.has_key?("firewall_rule")
                @dependencies['firewall_rule'].values.each { |sg|
                  target['add_firewall_rules'].each { |mount_sg|
                    sgs << sg.cloud_id if sg.config['name'] == mount_sg['rule_name']
                  }
                }
              end

              mp_threads << Thread.new {
                MU.dupGlobals(parent_thread_id)
                MU::Cloud::AWS::StoragePool.create_mount_target(
                  cloud_id: @cloud_id,
                  ip_address: target['ip_address'],
                  subnet_id: target['vpc']['subnet_id'],
                  security_groups: sgs,
                  region: @config['region']
                )
              }
            }

            mp_threads.each { |t|
              t.join
            }
          end

          return @cloud_id
        end

        # Locate an existing storage pool and return an array containing matching AWS resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching storage pool
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil)
          map = {}
          if cloud_id
            storge_pool = MU::Cloud::AWS.efs(region).describe_file_systems(
              file_system_id: cloud_id
            ).file_systems.first
            
            map[cloud_id] = storge_pool if storge_pool
          end

          if tag_value
            storage_pools = MU::Cloud::AWS.efs(region).describe_file_systems.file_systems
          
            if !storage_pools.empty?
              storage_pools.each{ |pool|
                tags = MU::Cloud::AWS.efs(region).describe_tags(
                  file_system_id: pool.file_system_id
                ).tags

                value = nil
                tags.each{ |tag|
                  if tag.key == tag_key
                    value = tag.value
                    break
                  end
                }
                
                if value == tag_value
                  map[pool.file_system_id] = pool
                  break
                end
              }
            end
          end

          return map
        end

        # Add our standard tag set to an Amazon EFS File System.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        def addStandardTags(cloud_id: nil, region: MU.curRegion)
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

            tags << {key: "Name", value: @mu_name} unless name_tag

            MU::Cloud::AWS.efs(region).create_tags(
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
        def self.create_mount_target(cloud_id: nil, ip_address: nil, subnet_id: nil, security_groups: [], region: MU.curRegion)
          MU.log "Creating mount target for filesystem #{cloud_id}"
          resp = MU::Cloud::AWS.efs(region).create_mount_target(
            file_system_id: cloud_id,
            subnet_id: subnet_id,
            ip_address: ip_address,
            security_groups: security_groups
          )

          attempts = 0
          loop do
            MU.log "Waiting for #{resp.mount_target_id} to become available", MU::NOTICE if attempts % 10 == 0
            mount_target = MU::Cloud::AWS.efs(region).describe_mount_targets(
              mount_target_id: resp.mount_target_id 
            ).mount_targets.first

            break if mount_target.life_cycle_state == "available"
            raise MuError, "Failed to create mount target #{resp.mount_target_id }" if %w{deleting deleted}.include? mount_target.life_cycle_state
            sleep 10
            attempts += 1
            raise MuError, "timed out waiting for #{resp.mount_target_id }" if attempts >= 40
          end
        end

        # Modify the security groups associated with an existing mount point 
        # @param cloud_id [String]: The cloud provider's identifier of the mount point.
        # @param replace [TrueClass, FalseClass]: If the provided security groups will replace or be added to the existing ones
        # @param security_groups [Array]: A list of security groups to associate with the mount point.
        # @param region [String]: The cloud provider region
        def self.modify_security_groups(cloud_id: nil, replace: false , security_groups: [], region: MU.curRegion)
          unless replace
            extisting_sgs = MU::Cloud::AWS.efs(region).describe_mount_target_security_groups(
              mount_target_id: cloud_id
            ).security_groups

            security_groups.concat extisting_sgs
          end

          security_groups.uniq!
          resp = MU::Cloud::AWS.efs(region).modify_mount_target_security_groups(
            mount_target_id: cloud_id,
            security_groups: security_groups
          )
        end

        # Register a description of this storage pool with this deployment's metadata.
        def notify
          deploy_struct = {}
          storage_pool = MU::Cloud::AWS.efs(@config['region']).describe_file_systems(
            creation_token: @mu_name
          ).file_systems.first

          mount_targets = MU::Cloud::AWS.efs(@config['region']).describe_mount_targets(
            file_system_id: storage_pool.file_system_id
          ).mount_targets

          targets = {}
          if !mount_targets.empty?

            mount_targets.each{ |mp|
              subnet = MU::Cloud::AWS.ec2(@config['region']).describe_subnets(
                subnet_ids: [mp.subnet_id]
              ).subnets.first

              targets[mp.mount_target_id] = {
                "owner_id" => mp.owner_id,
                "cloud_id" => mp.mount_target_id,
                "file_system_id" => mp.file_system_id,
                "subnet_id" => mp.subnet_id,
                "vpc_id" => subnet.vpc_id,
                "availability_zone" => subnet.availability_zone,
                "state" => mp.life_cycle_state,
                "ip_address" => mp.ip_address,
                "dns_name" => "#{subnet.availability_zone}.#{storage_pool.file_system_id}.efs.#{@config['region']}.amazonaws.com",
                "network_interface_id" => mp.network_interface_id
              }
            }
          end

          deploy_struct = {
            "owner_id" => storage_pool.owner_id,
            "creation_token" => storage_pool.creation_token,
            "identifier" => storage_pool.file_system_id,
            "creation_time" => storage_pool.creation_time,
            "name" => storage_pool.name,
            "number_of_mount_targets" => storage_pool.number_of_mount_targets,
            "size_in_bytes" => storage_pool.size_in_bytes.value,
            "mount_targets" => targets
          }

          return deploy_struct
        end

        # Called by {MU::Cleanup}. Locates resources that were created by the
        # currently-loaded deployment, and purges them.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region in which to operate
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          if region == "us-west-2"
            begin 
              storage_pools = MU::Cloud::AWS.efs(region).describe_file_systems.file_systems
            rescue Aws::EFS::Errors::AccessDeniedException
              MU.log "Storage Pools not supported in this account", MU::NOTICE
              return nil
            end

            our_pools = []
            our_replication_group_ids = []

            if !storage_pools.empty?
              storage_pools.each{ |pool|
                tags = MU::Cloud::AWS.efs(region).describe_tags(
                  file_system_id: pool.file_system_id
                ).tags

                found_muid = false
                found_master = false
                tags.each { |tag|
                  found_muid = true if tag.key == "MU-ID" && tag.value == MU.deploy_id
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
              # resp = MU::Cloud::AWS.efs(region).delete_mount_target(
                # mount_target_id: "MountTargetId"
              # )
              # MU.log "Deleted mount target"
            # rescue Aws::EFS::Errors::BadRequest => e
              # MU.log "Mount target already deleted", MU::NOTICE if e.to_s.start_with?("invalid mount target ID")
            # end

            if !our_pools.empty?
              our_pools.each{ |pool|
                mount_targets = MU::Cloud::AWS.efs(region).describe_mount_targets(
                  file_system_id: pool.file_system_id
                ).mount_targets

                if !mount_targets.empty?
                  mount_targets.each{ |mp|
                    MU.log "Deleting mount target #{mp.mount_target_id} for filesystem #{pool.name}: #{pool.file_system_id}"
                    unless noop
                      begin
                        resp = MU::Cloud::AWS.efs(region).delete_mount_target(
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
                    resp = MU::Cloud::AWS.efs(region).delete_file_system(
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

        private
      end #class
    end #class
  end
end #module
