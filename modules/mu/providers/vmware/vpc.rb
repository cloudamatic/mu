# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
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
    class VMWare

      # Creation of Virtual Private Clouds and associated artifacts (routes, subnets, etc).
      class VPC < MU::Cloud::VPC
        attr_reader :cloud_desc_cache
        attr_reader :routes

        class VSphereIDUnresolved < MU::MuError
        end

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          @subnets ||= []
          @subnetcachesemaphore = Mutex.new

          loadSubnets if @cloud_id

          @mu_name ||= @config['scrub_mu_isms'] ? @config['name'] : @deploy.getResourceName(@config['name'])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          MU::Cloud::VMWare.nsx(credentials: @credentials, habitat: @habitat).createUpdateSegment(
            {
              "connectivity_path" => "/infra/tier-1s/cgw",
              "id" => @mu_name,
              "description" => @deploy.deploy_id,
              "display_name" => @mu_name, # thing we'll use to find it in vSphere
              "subnets" => @config['subnets'].map { |s|
                cidr_obj = NetAddr::IPv4Net.parse(s['ip_block'])

                {
                  "gateway_address" => cidr_obj.nth(1).to_s+cidr_obj.netmask.to_s,
                  "dhcp_ranges" => [cidr_obj.nth(2).to_s+"-"+cidr_obj.nth(cidr_obj.len-1).to_s],
#                  "dhcp_config" => {
#                    "resource_type" => "SegmentDhcpV4Config",
#                    "server_address" => "40.1.0.1/32" # does this create a DHCP server somewhere? What?
#                  }
                }
              },
              "tags" => @tags.keys.map { |k| { "scope" => k, "tag" => @tags[k] } }
            }
          )
          @cloud_id = @mu_name

          # Don't declare us done until we've shown up on vSphere's side
          MU.retrier([VSphereIDUnresolved], loop_if: Proc.new { vSphereID.nil? or vSphereID.empty? }, max: 10, wait: 30)
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
        end

        # Given an NSX network identifier, attempt to locate a single vSphere
        # network artifact that should be the same network presented in vSphere.
        # vSphere provides only the +display_name+ field to go on, meaning that
        # this task may not be possible if there are duplicate names. Gross.
        # @param cloud_id [String]
        # @param credentials [String]
        # @param habitat [String]
        # @return [String]
        def self.vSphereID(cloud_id, credentials: nil, habitat: nil, quiet: false)
          my_desc = MU::Cloud::VMWare::VPC.find(credentials: credentials, habitat: habitat, cloud_id: cloud_id).values.first

          return nil if !my_desc or my_desc.empty?
          vsphere_descs = MU::Cloud::VMWare.network().list
          found = vsphere_descs.value.select { |n| n.name == my_desc["display_name"] }
          if found.size != 1
            raise VSphereIDUnresolved.new "Unable to narrow down the vSphere identity of my NSX network (id #{cloud_id}, display_name #{my_desc['display_name']}) to a single vSphere artifact", details: found
          end
          found.first.network
        end

        # Instance method shortcut to {MU::Cloud::VMWare::VPC.vSphereID}
        # @return [String]
        def vSphereID(quiet = false)
          MU::Cloud::VMWare::VPC.vSphereID(@cloud_id, credentials: @credentials, habitat: @habitat, quiet: quiet)
        end

        # Locate and return cloud provider descriptors of this resource type
        # which match the provided parameters, or all visible resources if no
        # filters are specified. At minimum, implementations of +find+ must
        # honor +credentials+ and +cloud_id+ arguments. We may optionally
        # support other search methods, such as +tag_key+ and +tag_value+, or
        # cloud-specific arguments like +project+. See also {MU::MommaCat.findStray}.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching resources
        def self.find(**args)
          found = {}
          resp = MU::Cloud::VMWare.nsx(credentials: args[:credentials], habitat: args[:habitat]).listNetworks

          if resp
            resp.each { |n|
              found[n["id"]] = n
            }
            if args[:cloud_id]
              found.reject! { |k, _v| k != args[:cloud_id] }
            end
          end
          
          found
        end

        # Return an array of MU::Cloud::VMWare::VPC::Subnet objects describe the
        # member subnets of this VPC.
        #
        # @return [Array<MU::Cloud::VMWare::VPC::Subnet>]
        def subnets
          if @subnets.nil? or @subnets.size == 0
            return loadSubnets
          end
          return @subnets
        end

        # Describe subnets associated with this VPC. We'll compose identifying
        # information similar to what MU::Cloud.describe builds for first-class
        # resources.
        # @param use_cache [Boolean]: If available, use saved deployment metadata to describe subnets, instead of querying the cloud API
        # @return [Array<Hash>]: A list of cloud provider identifiers of subnets associated with this VPC.
        def loadSubnets(use_cache: true)
          @subnetcachesemaphore.synchronize {
            return @subnets if use_cache and @subnets and @subnets.size > 0
          }

          return @subnets
        end

        # Given some search criteria try locating a NAT Gaateway in this VPC.
        # @param nat_cloud_id [String]: The cloud provider's identifier for this NAT.
        # @param nat_filter_key [String]: A cloud provider filter to help identify the resource, used in conjunction with nat_filter_value.
        # @param nat_filter_value [String]: A cloud provider filter to help identify the resource, used in conjunction with nat_filter_key.
        # @param region [String]: The cloud provider region of the target instance.
        def findNat(nat_cloud_id: nil, nat_filter_key: nil, nat_filter_value: nil, region: MU.curRegion)
        end

        # Given some search criteria for a {MU::Cloud::Server}, see if we can
        # locate a NAT host in this VPC.
        # @param nat_name [String]: The name of the resource as defined in its 'name' Basket of Kittens field, typically used in conjunction with deploy_id.
        # @param nat_cloud_id [String]: The cloud provider's identifier for this NAT.
        # @param nat_tag_key [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_value.
        # @param nat_tag_value [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_key.
        # @param nat_ip [String]: An IP address associated with the NAT instance.
        def findBastion(nat_name: nil, nat_cloud_id: nil, nat_tag_key: nil, nat_tag_value: nil, nat_ip: nil)

          nil
        end

        # Check for a subnet in this VPC matching one or more of the specified
        # criteria, and return it if found.
        def getSubnet(cloud_id: nil, name: nil, tag_key: nil, tag_value: nil, ip_block: nil, region: nil)
          nil
        end

        # Get the subnets associated with an instance.
        # @param instance_id [String]: The cloud identifier of the instance
        # @param instance [String]: A cloud descriptor for the instance, to save us an API call if we already have it
        # @param region [String]: The cloud provider region of the target instance
        # @return [Array<String>]
        def self.getInstanceSubnets(instance_id: nil, instance: nil, region: MU.curRegion)
        end

        @route_cache = {}
        @rtb_cache = {}
        @rtb_cache_semaphore = Mutex.new
        # Check whether we (the Mu Master) have a direct route to a particular
        # instance. Useful for skipping hops through bastion hosts to get
        # directly at child nodes in peered VPCs, the public internet, and the
        # like.
        # @param target_instance [OpenStruct]: The cloud descriptor of the instance to check.
        # @return [Boolean]
        def self.haveRouteToInstance?(target_instance, credentials: nil)
          false
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          true
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::ALPHA
        end

        # Remove all VPC resources associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, credentials: nil, flags: {})
          resp = find(credentials: credentials)#, habitat: habitat)
          resp.each_pair { |cloud_id, segment|
            if segment["tags"] and segment["tags"].include?({ "scope" => "MU-ID", "tag" => MU.deploy_id})
              MU.log "Deleting NSX network segment #{segment["id"]}"
              if !noop
              MU.retrier([MU::Cloud::VMWare::NSX::NSXError], max: 10, wait: 30) {
                MU::Cloud::VMWare.nsx.deleteSegment(segment["id"])
              }
              end
            end
          }
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config = nil)
          toplevel_required = []
          schema = {
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::vpcs}, bare and unvalidated.
        # @param vpc [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(vpc, configurator)
          ok = true

          has_public_route = Proc.new { |rtb|
            found_one = false
            if rtb['routes']
              rtb['routes'].each { |route|
                found_one = true if route["gateway"] == "#INTERNET"
              }
            end
            found_one
          }

          if (!vpc['subnets'] or vpc['subnets'].empty?) and vpc['create_standard_subnets']
            subnets = configurator.divideNetwork(vpc['ip_block'], vpc['route_tables'].size, 28)

            ok = false if subnets.nil?
            vpc['subnets'] = []

#            if vpc['create_nat_gateway'] and !nat_gateway_added and public_rtbs.size > 0
#              addnat = true
#              nat_gateway_added = true
#            end
            vpc['route_tables'].each { |rtb|
              vpc['subnets'] << {
                "name" => "Subnet#{rtb['name'].capitalize}",
                "ip_block" => subnets.shift,
                "route_table" => rtb['name'],
                
#                "map_public_ips" => (public_rtbs and public_rtbs.include?(rtb['name'])),
                "is_public" => has_public_route.call(rtb)
#                "create_nat_gateway" => (addnat and public_rtbs and public_rtbs.include?(rtb['name']))
              }
            }
          end

          if vpc['route_tables'].size > 1
            if !MU::Config::VPC.splitVPC(vpc, configurator)
              ok = false
            end
          elsif vpc['subnets'].size > 1
            MU.log "VMWare VPCs cannot have more than one subnet", MU::ERR, details: vpc['subnets']
            ok = false
          end

          ok
        end

        # @param route [Hash]: A route description, per the Basket of Kittens schema
        # @param server [MU::Cloud::VMWare::Server]: Instance to which this route will apply
        def createRouteForInstance(route, server)
          createRoute(route, network: @url, tags: [MU::Cloud::VMWare.nameStr(server.mu_name)])
        end

        private

        # Subnets are almost a first-class resource. So let's kinda sorta treat
        # them like one. This should only be invoked on objects that already
        # exists in the cloud layer.
        class Subnet < MU::Cloud::VMWare::VPC

          attr_reader :cloud_id
          attr_reader :ip_block
          attr_reader :mu_name
          attr_reader :name
          attr_reader :cloud_desc_cache
          attr_reader :az

          # @param parent [MU::Cloud::VMWare::VPC]: The parent VPC of this subnet.
          # @param config [Hash<String>]:
          def initialize(parent, config, precache_description: true)
            @parent = parent
            @config = MU::Config.manxify(config)
            @cloud_id = config['cloud_id']
            @url = config['url']
            @mu_name = config['mu_name']
            @name = config['name']
            @deploydata = config # This is a dummy for the sake of describe()
            @az = config['az']
            @ip_block = config['ip_block']
            @cloud_desc_cache = nil
            cloud_desc if precache_description
          end

          # Return the cloud identifier for the default route of this subnet.
          def defaultRoute
          end

          # Describe this VPC Subnet
          # @return [Hash]
          def notify
            MU.structToHash(cloud_desc, stringify_keys: true)
          end

          @cloud_desc_cache = nil
          # Describe this VPC Subnet from the cloud platform's perspective
          # @return [VMWare::Apis::Core::Hashable]
          def cloud_desc(use_cache: true)
            return @cloud_desc_cache if @cloud_desc_cache and use_cache

            @cloud_desc_cache
          end

          # Is this subnet privately-routable only, or public?
          # @return [Boolean]
          def private?
            return true
          end
        end

      end #class
    end #class
  end
end #module
