# Copyright:: Copyright (c) 2019 eGlobalTech, Inc., all rights reserved
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
    class Azure

      # Creation of Virtual Private Clouds and associated artifacts (routes, subnets, etc).
      class VPC < MU::Cloud::VPC
        attr_reader :cloud_desc_cache
        attr_reader :resource_group

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @subnets = []
          @subnetcachesemaphore = Mutex.new

          if !mu_name.nil?
            @mu_name = mu_name
            if @cloud_id
              cloud_desc
              @cloud_id = Id.new(cloud_desc.id)
              @resource_group = @cloud_id.resource_group if @cloud_id.resource_group
              loadSubnets(use_cache: true)
            end
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name = @deploy.getResourceName(@config['name'])
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          create_update
        end


        # Called automatically by {MU::Deploy#createResources}
        def groom

          if @config['peers']
            @config['peers'].each { |peer|
              if peer['vpc']['name']
                peer_obj = @deploy.findLitterMate(name: peer['vpc']['name'], type: "vpcs", habitat: peer['vpc']['project'])
                next if peer_obj.mu_name < @mu_name # both of us would try to create this peering, otherwise, so don't step on each other
              else
                tag_key, tag_value = peer['vpc']['tag'].split(/=/, 2) if !peer['vpc']['tag'].nil?
                if peer['vpc']['deploy_id'].nil? and peer['vpc']['id'].nil? and tag_key.nil?
                  peer['vpc']['deploy_id'] = @deploy.deploy_id
                end

                peer_obj = MU::MommaCat.findStray(
                  "Azure",
                  "vpcs",
                  deploy_id: peer['vpc']['deploy_id'],
                  cloud_id: peer['vpc']['id'],
                  name: peer['vpc']['name'],
                  tag_key: tag_key,
                  tag_value: tag_value,
                  dummy_ok: true
                ).first
              end

              raise MuError, "No result looking for #{@mu_name}'s peer VPCs (#{peer['vpc']})" if peer_obj.nil?
          
              ext_peerings = MU::Cloud::Azure.network(credentials: @credentials).virtual_network_peerings.list(@resource_group, @cloud_id)
              peer_name = @mu_name+"-"+@config['name'].upcase+"-"+peer_obj.config['name'].upcase
              peer_params = MU::Cloud::Azure.network(:VirtualNetworkPeering).new
              peer_params.remote_virtual_network = peer_obj.cloud_desc
              peer['allow_forwarded_traffic'] ||= false
              peer_params.allow_forwarded_traffic = peer['allow_forwarded_traffic']
              peer['allow_gateway_traffic'] ||= false
              peer_params.allow_gateway_transit = peer['allow_gateway_traffic']

              need_update = true
              exists = false
              ext_peerings.each { |ext_peering|
                if ext_peering.remote_virtual_network.id == peer_obj.cloud_desc.id
                  exists = true
                  need_update = (ext_peering.allow_forwarded_traffic != peer_params.allow_forwarded_traffic or ext_peering.allow_gateway_transit != peer_params.allow_gateway_transit)
                end
              }

              if need_update
                if !exists
                  MU.log "Creating peering connection from #{@mu_name} to #{peer_obj.mu_name}", details: peer_params
                else
                  MU.log "Updating peering connection from #{@mu_name} to #{peer_obj.mu_name}", MU::NOTICE, details: peer_params
                end
                MU::Cloud::Azure.network(credentials: @credentials).virtual_network_peerings.create_or_update(@resource_group, @cloud_id, peer_name, peer_params)
              end
            }
          end

          create_update
        end

        # Describe this VPC
        # @return [Hash]
        def notify
          base = MU.structToHash(cloud_desc)
          base["cloud_id"] = @cloud_id.name
          base.merge!(@config.to_h)
          base
        end

        # Describe this VPC from the cloud platform's perspective
        # @return [Hash]
        def cloud_desc(use_cache: true)
          if @cloud_desc_cache and use_cache
            return @cloud_desc_cache
          end
          @cloud_desc_cache = MU::Cloud::Azure::VPC.find(cloud_id: @cloud_id, resource_group: @resource_group).values.first

          @cloud_id ||= Id.new(@cloud_desc_cache.id)
          @cloud_desc_cache
        end

        # List the CIDR blocks to which this VPC has routes. Exclude obvious
        # things like +0.0.0.0/0+.
        # @param subnets [Array<String>]: Only return the routes relevant to these subnet ids
        def routes(subnets: [])
          cloud_desc
          routes = cloud_desc.address_space.address_prefixes
          subnet_ids = @subnets.map { |s| s.cloud_desc.id }

          rtbs = MU::Cloud::Azure.network(credentials: @credentials).route_tables.list(@resource_group)
          rtbs.each { |rtb|
            next if !rtb.subnets or !rtb.routes
            rtb.subnets.each { |s|
              if subnet_ids.include?(s.id)
                rtb.routes.each { |r|
                  next if r.address_prefix == "0.0.0.0/0"
                  routes << r.address_prefix
                }
                break
              end
            }
          }
          MU.log @cloud_id, MU::NOTICE, details: routes.uniq

          routes.uniq
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

          # Azure resources are namedspaced by resource group. If we weren't
          # told one, we may have to search all the ones we can see.
          resource_groups = if args[:resource_group]
            [args[:resource_group]]
          elsif args[:cloud_id] and args[:cloud_id].is_a?(MU::Cloud::Azure::Id)
            [args[:cloud_id].resource_group]
          else
            MU::Cloud::Azure.resources(credentials: args[:credentials]).resource_groups.list.map { |rg| rg.name }
          end

          if args[:cloud_id]
            id_str = args[:cloud_id].is_a?(MU::Cloud::Azure::Id) ? args[:cloud_id].name : args[:cloud_id]
            resource_groups.each { |rg|
              resp = MU::Cloud::Azure.network(credentials: args[:credentials]).virtual_networks.get(rg, id_str)
              found[Id.new(resp.id)] = resp if resp
            }
          else
            if args[:resource_group]
              MU::Cloud::Azure.network(credentials: args[:credentials]).virtual_networks.list(args[:resource_group]).each { |net|
                found[Id.new(net.id)] = net
              }
            else
              MU::Cloud::Azure.network(credentials: args[:credentials]).virtual_networks.list_all.each { |net|
                found[Id.new(net.id)] = net
              }
            end
          end

          if args[:region]
            found.reject!{ |k, v| v.location != args[:region] }
          end

          found
        end

        # Return an array of MU::Cloud::Azure::VPC::Subnet objects describe the
        # member subnets of this VPC.
        #
        # @return [Array<MU::Cloud::Azure::VPC::Subnet>]
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
        def loadSubnets(use_cache: false)
          @subnets = []

          MU::Cloud::Azure.network(credentials: @credentials).subnets.list(@resource_group, cloud_desc(use_cache: use_cache).name).each { |subnet|
            subnet_cfg = {
              "cloud_id" => subnet.name,
              "mu_name" => subnet.name,
              "credentials" => @config['credentials'],
              "region" => @config['region'],
              "ip_block" => subnet.address_prefix
            }
            if @config['subnets']
              @config['subnets'].each { |s|
                if s['ip_block'] == subnet_cfg['ip_block']
                  subnet_cfg['name'] = s['name']
                  break
                end
              }
            end
            subnet_cfg['name'] ||= subnet.name
            @subnets << MU::Cloud::Azure::VPC::Subnet.new(self, subnet_cfg)
          }
          @subnets
        end

        # Given some search criteria try locating a NAT Gaateway in this VPC.
        # @param nat_cloud_id [String]: The cloud provider's identifier for this NAT.
        # @param nat_filter_key [String]: A cloud provider filter to help identify the resource, used in conjunction with nat_filter_value.
        # @param nat_filter_value [String]: A cloud provider filter to help identify the resource, used in conjunction with nat_filter_key.
        # @param region [String]: The cloud provider region of the target instance.
        def findNat(nat_cloud_id: nil, nat_filter_key: nil, nat_filter_value: nil, region: MU.curRegion)
          nil
        end

        # Given some search criteria for a {MU::Cloud::Server}, see if we can
        # locate a NAT host in this VPC.
        # @param nat_name [String]: The name of the resource as defined in its 'name' Basket of Kittens field, typically used in conjunction with deploy_id.
        # @param nat_cloud_id [String]: The cloud provider's identifier for this NAT.
        # @param nat_tag_key [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_value.
        # @param nat_tag_value [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_key.
        # @param nat_ip [String]: An IP address associated with the NAT instance.
        def findBastion(nat_name: nil, nat_cloud_id: nil, nat_tag_key: nil, nat_tag_value: nil, nat_ip: nil)
          [:nat_name, :nat_cloud_id, :nat_tag_key, :nat_tag_value, :nat_ip].each { |var|
            if binding.local_variable_get(var) != nil
              binding.local_variable_set(var, var.to_s)
            end

            # If we're searching by name, assume it's part of this here deploy.
            if nat_cloud_id.nil? and !@deploy.nil?
              deploy_id = @deploy.deploy_id
            end
            found = MU::MommaCat.findStray(
              "Azure",
              "server",
              name: nat_name,
              cloud_id: nat_cloud_id,
              deploy_id: deploy_id,
              tag_key: nat_tag_key,
              tag_value: nat_tag_value,
              allow_multi: true,
              dummy_ok: true,
              calling_deploy: @deploy
            )

            return nil if found.nil? || found.empty?
            if found.size == 1
              return found.first
            end

          }
          nil
        end

        # Check for a subnet in this VPC matching one or more of the specified
        # criteria, and return it if found.
        def getSubnet(cloud_id: nil, name: nil, tag_key: nil, tag_value: nil, ip_block: nil)
          loadSubnets
          if !cloud_id.nil? and cloud_id.match(/^https:\/\//)
            cloud_id.gsub!(/.*?\//, "")
          end
          MU.log "getSubnet(cloud_id: #{cloud_id}, name: #{name}, tag_key: #{tag_key}, tag_value: #{tag_value}, ip_block: #{ip_block})", MU::DEBUG, details: caller[0]

          @subnets.each { |subnet|
            if !cloud_id.nil? and !subnet.cloud_id.nil? and subnet.cloud_id.to_s == cloud_id.to_s
              return subnet
            elsif !name.nil? and !subnet.name.nil? and subnet.name.to_s == name.to_s
              return subnet
            end
          }
          return nil
        end
        @route_cache = {}
        @rtb_cache = {}
        @rtb_cache_semaphore = Mutex.new
        # Check whether we (the Mu Master) have a direct route to a particular
        # instance. Useful for skipping hops through bastion hosts to get
        # directly at child nodes in peered VPCs, the public internet, and the
        # like.
        # @param target_instance [OpenStruct]: The cloud descriptor of the instance to check.
        # @param region [String]: The cloud provider region of the target subnet.
        # @return [Boolean]
        def self.haveRouteToInstance?(target_instance, region: MU.curRegion, credentials: nil)

#          target_instance.network_profile.network_interfaces.each { |iface|
#            iface_id = Id.new(iface.is_a?(Hash) ? iface['id'] : iface.id)
#            iface_desc = MU::Cloud::Azure.network(credentials: credentials).network_interfaces.get(iface_id.resource_group, iface_id.to_s)
#            iface_desc.ip_configurations.each { |ipcfg|
#              if ipcfg.respond_to?(:public_ipaddress) and ipcfg.public_ipaddress
#                return true # XXX invalid if Mu can't talk to the internet
#              end
#            }
#          }

          return false if MU.myCloud != "Azure"
# XXX if we're in Azure, see if this is in our VPC or if we're peered to its VPC
          false
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
          MU::Cloud::BETA
        end

        # Stub method. Azure resources are cleaned up by removing the parent
        # resource group.
        # @return [void]
        def self.cleanup(**args)
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        # XXX add flag to return the diff between @config and live cloud
        def toKitten(**_args)
          return nil if cloud_desc.name == "default" # parent project builds these
          bok = {
            "cloud" => "Azure",
            "name" => cloud_desc.name,
            "project" => @config['project'],
            "credentials" => @config['credentials'],
            "cloud_id" => @cloud_id.to_s
          }

          bok
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config = nil)
          toplevel_required = []
          schema = {
            "peers" => {
              "items" => {
                "properties" => {
                  "allow_forwarded_traffic" => {
                    "type" => "boolean",
                    "default" => false,
                    "description" => "Allow traffic originating from outside peered networks"
                  },
                  "allow_gateway_traffic" => {
                    "type" => "boolean",
                    "default" => false,
                    "description" => "Permit peered networks to use each others' VPN gateways"
                  }
                }
              }
            }
          }
          [toplevel_required, schema]
        end


        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::vpcs}, bare and unvalidated.
        # @param vpc [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(vpc, configurator)
          ok = true
          vpc['region'] ||= MU::Cloud::Azure.myRegion(vpc['credentials'])

          if vpc['subnets']
            vpc['subnets'].each { |subnet|
              subnet_routes[subnet['route_table']] = Array.new if subnet_routes[subnet['route_table']].nil?
              subnet_routes[subnet['route_table']] << subnet['name']
            }
          end

          if (!vpc['subnets'] or vpc['subnets'].empty?) and vpc['create_standard_subnets']
            subnets = configurator.divideNetwork(vpc['ip_block'], vpc['route_tables'].size, 28)
            vpc['subnets'] ||= []
            vpc['route_tables'].each { |rtb|
              is_public = false
              rtb['routes'].each { |route|
                if route['gateway'] == "#INTERNET"
                  is_public = true
                  break
                end
              }
              vpc['subnets'] << {
                "name" => "Subnet#{rtb['name'].capitalize}",
                "is_public" => is_public,
                "ip_block" => subnets.shift,
                "route_table" => rtb['name']
              }
            }
          end

          vpc['route_tables'].each { |rtb|
            rtb['routes'] ||= []
            rtb['routes'] << { "destination_network" => vpc['ip_block'] }
            rtb['routes'].uniq!
          }

          default_acl = {
            "name" => vpc['name']+"-defaultfw",
            "cloud" => "Azure",
            "region" => vpc['region'],
            "credentials" => vpc['credentials'],
            "rules" => [
              {
                "ingress" => true, "proto" => "all", "hosts" => [vpc['ip_block']]
              },
              {
                "egress" => true, "proto" => "all", "hosts" => [vpc['ip_block']]
              }
            ]
          }
          MU::Config.addDependency(vpc, vpc['name']+"-defaultfw", "firewall_rule")

          if !configurator.insertKitten(default_acl, "firewall_rules", true)
            ok = false
          end

          ok
        end

        # @param route [Hash]: A route description, per the Basket of Kittens schema
        # @param server [MU::Cloud::Azure::Server]: Instance to which this route will apply
        def createRouteForInstance(route, server)
          createRoute(route, network: @url, tags: [MU::Cloud::Azure.nameStr(server.mu_name)])
        end

        private

        def create_update
          @config = MU::Config.manxify(@config)
          @config['region'] ||= MU::Cloud::Azure.myRegion(@config['credentials'])
          tags = {}
          if !@config['scrub_mu_isms']
            tags = MU::MommaCat.listStandardTags
          end
          if @config['tags']
            @config['tags'].each { |tag|
              tags[tag['key']] = tag['value']
            }
          end

          vpc_obj =  MU::Cloud::Azure.network(:VirtualNetwork).new
          addr_space_obj = MU::Cloud::Azure.network(:AddressSpace).new
          addr_space_obj.address_prefixes = [
            @config['ip_block']
          ]
          vpc_obj.address_space = addr_space_obj
          vpc_obj.location = @config['region']
          vpc_obj.tags = tags

          my_fw = deploy.findLitterMate(type: "firewall_rule", name: @config['name']+"-defaultfw")

          @resource_group = @deploy.deploy_id+"-"+@config['region'].upcase

          need_apply = false
          ext_vpc = nil
          begin
            ext_vpc = MU::Cloud::Azure.network(credentials: @config['credentials']).virtual_networks.get(
              @resource_group,
              @mu_name
            )
          rescue ::MU::Cloud::Azure::APIError => e
            if e.message.match(/: ResourceNotFound:/)
              need_apply = true
            else
              raise e
            end
          end
# XXX raw update seems to destroy child resources; if we just need to update
# tags, do that with .update_tags
          if !ext_vpc
            MU.log "Creating VPC #{@mu_name} (#{@config['ip_block']}) in #{@config['region']}", details: vpc_obj
            need_apply = true
          elsif ext_vpc.location != vpc_obj.location or
#                ext_vpc.tags != vpc_obj.tags or
#                XXX updating tags is a different API call
                ext_vpc.address_space.address_prefixes != vpc_obj.address_space.address_prefixes
            MU.log "Updating VPC #{@mu_name} (#{@config['ip_block']}) in #{@config['region']}", MU::NOTICE, details: vpc_obj
MU.structToHash(ext_vpc).diff(MU.structToHash(vpc_obj))
            need_apply = true
          end

          if need_apply
            begin
              resp = MU::Cloud::Azure.network(credentials: @config['credentials']).virtual_networks.create_or_update(
                @resource_group,
                @mu_name,
                vpc_obj
              )
              @cloud_id = Id.new(resp.id)
            rescue ::MU::Cloud::Azure::APIError => e
              if e.message.match(/InUseSubnetCannotBeDeleted: /)
                MU.log "Cannot delete an in-use Azure subnet", MU::WARN
              else
                raise e
              end
            end
          end

          # this is slow, so maybe thread it
          rtb_map = {}
          routethreads = []
          @config['route_tables'].each { |rtb_cfg|
            routethreads << Thread.new(rtb_cfg) { |rtb|
              rtb_name = @mu_name+"-"+rtb['name'].upcase
              rtb_obj = MU::Cloud::Azure.network(:RouteTable).new
              rtb_obj.location = @config['region']

              rtb_obj.tags = tags
              rtb_ref_obj = MU::Cloud::Azure.network(:RouteTable).new
              rtb_ref_obj.name = rtb_name
              rtb_map[rtb['name']] = rtb_ref_obj

              need_apply = false
              ext_rtb = nil
              begin
                ext_rtb = MU::Cloud::Azure.network(credentials: @config['credentials']).route_tables.get(
                  @resource_group,
                  rtb_name
                )
                rtb_map[rtb['name']] = ext_rtb
              rescue MU::Cloud::Azure::APIError => e
                if e.message.match(/: ResourceNotFound:/)
                  need_apply = true
                else
                  raise e
                end
              end

              if !ext_rtb
                MU.log "Creating route table #{rtb_name} in VPC #{@mu_name}", details: rtb_obj
                need_apply = true
              elsif ext_rtb.location != rtb_obj.location or
                    ext_rtb.tags != rtb_obj.tags
                need_apply = true
                MU.log "Updating route table #{rtb_name} in VPC #{@mu_name}", MU::NOTICE, details: rtb_obj
              end

              if need_apply
                rtb_map[rtb['name']] = MU::Cloud::Azure.network(credentials: @config['credentials']).route_tables.create_or_update(
                  @resource_group,
                  rtb_name,
                  rtb_obj
                )
              end

              rtb['routes'].each { |route|
                route_obj = MU::Cloud::Azure.network(:Route).new
                route_obj.address_prefix = route['destination_network']
                routename = rtb_name+"-"+route['destination_network'].gsub(/[^a-z0-9]/i, "_")
                route_obj.next_hop_type = if route['gateway'] == "#NAT" and @config['bastion']
                  routename = rtb_name+"-NAT"
                  if @config['bastion'].is_a?(Hash) and !@config['bastion']['id'] and !@config['bastion']['deploy_id']
                    @config['bastion']['deploy_id'] = @deploy.deploy_id
                  end
                  bastion_ref = MU::Config::Ref.get(@config['bastion'])
                  if bastion_ref.kitten and bastion_ref.kitten.cloud_desc
                    iface_id = Id.new(bastion_ref.kitten.cloud_desc.network_profile.network_interfaces.first.id)
                    iface_desc = MU::Cloud::Azure.network(credentials: @credentials).network_interfaces.get(@resource_group, iface_id.name)
                    if iface_desc and iface_desc.ip_configurations and iface_desc.ip_configurations.size > 0
                      route_obj.next_hop_ip_address = iface_desc.ip_configurations.first.private_ipaddress
                      "VirtualAppliance"
                    else
                      "VnetLocal"
                    end
                  else
                    "VnetLocal"
                  end
#                  create_nat_gateway = true
                elsif route['gateway'] == "#INTERNET"
                  routename = rtb_name+"-INTERNET"
                  "Internet"
                else
                  routename = rtb_name+"-LOCAL"
                  "VnetLocal"
                end
#next_hop_type 'VirtualNetworkGateway' is for VPNs I think

                need_apply = false
                ext_route = nil
                begin
                  ext_route = MU::Cloud::Azure.network(credentials: @config['credentials']).routes.get(
                    @resource_group,
                    rtb_name,
                    routename
                  )
                rescue MU::Cloud::Azure::APIError => e
                  if e.message.match(/\bNotFound\b/)
                    need_apply = true
                  else
                    raise e
                  end
                end

                if !ext_route
                  MU.log "Creating route #{routename} for #{route['destination_network']} in route table #{rtb_name}", details: rtb_obj
                  need_apply = true
                elsif ext_route.next_hop_type != route_obj.next_hop_type or
                      ext_route.address_prefix != route_obj.address_prefix
                  MU.log "Updating route #{routename} for #{route['destination_network']} in route table #{rtb_name}", MU::NOTICE, details: [route_obj, ext_route]
                  need_apply = true
                end

                if need_apply
                  MU::Cloud::Azure.network(credentials: @config['credentials']).routes.create_or_update(
                    @resource_group,
                    rtb_name,
                    routename,
                    route_obj
                  )
                end
              }
            }
          }

          routethreads.each { |t|
            t.join
          }

# TODO this is only available in westus as of 2019-09-29
#          if create_nat_gateway
#            nat_obj = MU::Cloud::Azure.network(:NatGateway).new
#            nat_obj.location = @config['region']
#            nat_obj.tags = tags
#            MU.log "Creating NAT Gateway #{@mu_name}-NAT", details: nat_obj
#            MU::Cloud::Azure.network(credentials: @config['credentials']).nat_gateways.create_or_update(
#              @resource_group,
#              @mu_name+"-NAT",
#              nat_obj
#            )
#          end

          if @config['subnets']
            subnetthreads = []
            @config['subnets'].each { |subnet_cfg|
              subnetthreads << Thread.new(subnet_cfg) { |subnet|
                subnet_obj = MU::Cloud::Azure.network(:Subnet).new
                subnet_name = @mu_name+"-"+subnet['name'].upcase
                subnet_obj.address_prefix = subnet['ip_block']
                subnet_obj.route_table = rtb_map[subnet['route_table']]
                if my_fw and my_fw.cloud_desc
                  subnet_obj.network_security_group = my_fw.cloud_desc
                end

                need_apply = false
                ext_subnet = nil
                begin
                  ext_subnet = MU::Cloud::Azure.network(credentials: @config['credentials']).subnets.get(
                    @resource_group,
                    @cloud_id.to_s,
                    subnet_name
                  )
                rescue APIError => e
                  if e.message.match(/\bNotFound\b/)
                    need_apply = true
                  else
#                raise e
                  end
                end

                if !ext_subnet
                  MU.log "Creating Subnet #{subnet_name} in VPC #{@mu_name}", details: subnet_obj
                  need_apply = true
                elsif (!ext_subnet.route_table.nil? and !subnet_obj.route_table.nil? and ext_subnet.route_table.id != subnet_obj.route_table.id) or
                      ext_subnet.address_prefix != subnet_obj.address_prefix or
                      ext_subnet.network_security_group.nil? and !subnet_obj.network_security_group.nil? or
                      (!ext_subnet.network_security_group.nil? and !subnet_obj.network_security_group.nil? and ext_subnet.network_security_group.id != subnet_obj.network_security_group.id)
                  MU.log "Updating Subnet #{subnet_name} in VPC #{@mu_name}", MU::NOTICE, details: subnet_obj
MU.structToHash(ext_subnet).diff(MU.structToHash(subnet_obj))
                  need_apply = true

                end

                if need_apply
                  begin
                    MU::Cloud::Azure.network(credentials: @config['credentials']).subnets.create_or_update(
                      @resource_group,
                      @cloud_id.to_s,
                      subnet_name,
                      subnet_obj
                    )
                  rescue ::MU::Cloud::Azure::APIError => e
                    if e.message.match(/InUseSubnetCannotBeUpdated: /)
                      MU.log "Cannot alter an in-use Azure subnet", MU::WARN
                    else
                      raise e
                    end
                  end
                end
              }
            }

            subnetthreads.each { |t|
              t.join
            }
          end

          loadSubnets
        end

        # Subnets are almost a first-class resource. So let's kinda sorta treat
        # them like one. This should only be invoked on objects that already
        # exists in the cloud layer.
        class Subnet < MU::Cloud::Azure::VPC

          attr_reader :cloud_id
          attr_reader :id
          attr_reader :ip_block
          attr_reader :mu_name
          attr_reader :name
          attr_reader :cloud_desc_cache
          attr_reader :resource_group
          attr_reader :az

          # @param parent [MU::Cloud::Azure::VPC]: The parent VPC of this subnet.
          # @param config [Hash<String>]:
          def initialize(parent, config, precache_description: true)
            @parent = parent
            @deploy = parent.deploy
            @config = MU::Config.manxify(config)
            @cloud_id = config['cloud_id']
            @mu_name = config['mu_name']
            @name = config['name']
            @deploydata = config # This is a dummy for the sake of describe()
            @ip_block = config['ip_block']
            @cloud_desc_cache = nil
            @az = parent.config['region']
            cloud_desc if precache_description
          end

          # Return the cloud identifier for the default route of this subnet.
          def defaultRoute
            if cloud_desc and cloud_desc.route_table
              rtb_id = MU::Cloud::Azure::Id.new(cloud_desc.route_table.id)
              routes = MU::Cloud::Azure.network(credentials: @config['credentials']).routes.list(
                rtb_id.resource_group,
                rtb_id.name
              )
              routes.each { |route|
                return route if route.address_prefix == "0.0.0.0/0"
              }
            end
            nil
          end

          # Describe this VPC Subnet
          # @return [Hash]
          def notify
            MU.structToHash(cloud_desc)
          end

          # Describe this VPC Subnet from the cloud platform's perspective
          def cloud_desc(use_cache: true)
            return @cloud_desc_cache if @cloud_desc_cache and use_cache
            @cloud_desc_cache = MU::Cloud::Azure.network(credentials: @parent.credentials).subnets.get(@parent.resource_group, @parent.cloud_desc.name, @cloud_id.to_s)
            @cloud_desc_cache
          end

          # Is this subnet privately-routable only, or public?
          # @return [Boolean]
          def private?
            if cloud_desc and cloud_desc.route_table
              rtb_id = MU::Cloud::Azure::Id.new(cloud_desc.route_table.id)
              routes = MU::Cloud::Azure.network(credentials: @config['credentials']).routes.list(
                rtb_id.resource_group,
                rtb_id.name
              )
              routes.each { |route|
                return false if route.next_hop_type == "Internet"
              }
              true
            end
          end
        end

      end #class
    end #class
  end
end #module
