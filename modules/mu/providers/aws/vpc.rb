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

module MU
  class Cloud
    class AWS

      # Creation of Virtual Private Clouds and associated artifacts (routes, subnets, etc).
      class VPC < MU::Cloud::VPC
        require 'mu/providers/aws/vpc_subnet'

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @subnets = []
          @subnetcachesemaphore = Mutex.new

          loadSubnets if !@cloud_id.nil?

          @mu_name ||= @deploy.getResourceName(@config['name'])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          MU.log "Creating VPC #{@mu_name}", details: @config
          resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_vpc(cidr_block: @config['ip_block']).vpc
          @cloud_id = resp.vpc_id
          @config['vpc_id'] = @cloud_id

          tag_me

          if resp.state != "available"
            begin
              MU.log "Waiting for VPC #{@mu_name} (#{@cloud_id}) to be available", MU::NOTICE
              sleep 5
              resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_vpcs(vpc_ids: [@cloud_id]).vpcs.first
            end while resp.state != "available"
            # There's a default route table that comes with. Let's tag it.
            resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_route_tables(
              filters: [
                {
                  name: "vpc-id",
                  values: [@cloud_id]
                }
              ]
            )
            resp.route_tables.each { |rtb|
              tag_me(rtb.route_table_id, @mu_name+"-#DEFAULTPRIV")
            }
          end

          if @config['create_internet_gateway']
            MU.log "Creating Internet Gateway #{@mu_name}"
            resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_internet_gateway
            internet_gateway_id = resp.internet_gateway.internet_gateway_id
            sleep 5

            tag_me(internet_gateway_id)

            MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).attach_internet_gateway(vpc_id: @cloud_id, internet_gateway_id: internet_gateway_id)
            @config['internet_gateway_id'] = internet_gateway_id
          end

          route_table_ids = [] 
          if !@config['route_tables'].nil?
            @config['route_tables'].each { |rtb|
              rtb = createRouteTable(rtb)
              route_table_ids << rtb['route_table_id']
            }
          end
          
          if @config['endpoint']
            config = {
              :vpc_id => @cloud_id,
              :service_name => @config['endpoint'],
              :route_table_ids => route_table_ids
            }

            if @config['endpoint_policy'] && !@config['endpoint_policy'].empty?
              statement = {:Statement => @config['endpoint_policy']}
              config[:policy_document] = statement.to_json
            end

            resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_vpc_endpoint(config).vpc_endpoint
            endpoint_id = resp.vpc_endpoint_id
            MU.log "Creating VPC endpoint #{endpoint_id}"
            attempts = 0

            while resp.state == "pending"
              MU.log "Waiting for VPC endpoint #{endpoint_id} to become available" if attempts % 5 == 0
              sleep 10
              begin
                resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_vpc_endpoints(vpc_endpoint_ids: [endpoint_id]).vpc_endpoints.first
              rescue Aws::EmptyStructure, NoMethodError
                sleep 5
                retry
              end
              raise MuError, "Timed out while waiting for VPC endpoint #{endpoint_id}: #{resp}" if attempts > 30
              attempts += 1
            end

            raise MuError, "VPC endpoint failed #{endpoint_id}: #{resp}" if resp.state == "failed"
          end

          if @config["enable_traffic_logging"]
            loggroup = @deploy.findLitterMate(name: @config['name']+"loggroup", type: "logs")
            logrole = @deploy.findLitterMate(name: @config['name']+"logrole", type: "roles")

            MU.log "Enabling traffic logging on VPC #{@mu_name} to log group #{loggroup.mu_name}"
            MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_flow_logs(
              resource_ids: [@cloud_id],
              resource_type: "VPC",
              traffic_type: "ALL",
              log_group_name: loggroup.mu_name,
              deliver_logs_permission_arn: logrole.cloudobj.arn
            )
          end

          nat_gateways = create_subnets

          notify

          if !nat_gateways.empty?
            nat_gateways.each { |gateway|
              @config['subnets'].each { |subnet|
                next if subnet['is_public'] != false or subnet['availability_zone'] != gateway['availability_zone']

                @config['route_tables'].each { |rtb|
                  next if rtb['name'] != subnet['route_table']
                  rtb['routes'].each { |route|
                    next if route['gateway'] != '#NAT'
                    route_config = {
                      :route_table_id => rtb['route_table_id'],
                      :destination_cidr_block => route['destination_network'],
                      :nat_gateway_id => gateway['id']
                    }

                    MU.log "Creating route for #{route['destination_network']} through NAT gatway #{gateway['id']}", details: route_config
                    MU.retrier([Aws::EC2::Errors::InvalidNatGatewayIDNotFound], wait: 10, max: 5) {
                      begin
                        resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_route(route_config)
                      rescue Aws::EC2::Errors::RouteAlreadyExists
                        MU.log "Attempt to create duplicate route to #{route['destination_network']} for #{gateway['id']} in #{rtb['route_table_id']}", MU::WARN
                      end
                    }
                  }
                }
              }
            }
          end

          if @config['enable_dns_support']
            MU.log "Enabling DNS support in #{@mu_name}"
            MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).modify_vpc_attribute(
                vpc_id: @cloud_id,
                enable_dns_support: {value: @config['enable_dns_support']}
            )
          end
          if @config['enable_dns_hostnames']
            MU.log "Enabling DNS hostnames in #{@mu_name}"
            MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).modify_vpc_attribute(
                vpc_id: @cloud_id,
                enable_dns_hostnames: {value: @config['enable_dns_hostnames']}
            )
          end

          if @config['dhcp']
            MU.log "Setting custom DHCP options in #{@mu_name}", details: @config['dhcp']
            dhcpopts = []

            if @config['dhcp']['netbios_type']
              dhcpopts << {key: "netbios-node-type", values: [@config['dhcp']['netbios_type'].to_s]}
            end
            if @config['dhcp']['domains']
              dhcpopts << {key: "domain-name", values: @config['dhcp']['domains']}
            end
            if @config['dhcp']['dns_servers']
              dhcpopts << {key: "domain-name-servers", values: @config['dhcp']['dns_servers']}
            end
            if @config['dhcp']['ntp_servers']
              dhcpopts << {key: "ntp-servers", values: @config['dhcp']['ntp_servers']}
            end
            if @config['dhcp']['netbios_servers']
              dhcpopts << {key: "netbios-name-servers", values: @config['dhcp']['netbios_servers']}
            end

            resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_dhcp_options(
                dhcp_configurations: dhcpopts
            )
            dhcpopt_id = resp.dhcp_options.dhcp_options_id
            tag_me(dhcpopt_id)

            MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).associate_dhcp_options(dhcp_options_id: dhcpopt_id, vpc_id: @cloud_id)
          end
          notify

          if !MU::Cloud::AWS.isGovCloud?(@region)
            mu_zone = MU::Cloud::DNSZone.find(cloud_id: "platform-mu", credentials: @credentials).values.first
            if !mu_zone.nil?
              MU::Cloud.resourceClass("AWS", "DNSZone").toggleVPCAccess(id: mu_zone.id, vpc_id: @cloud_id, region: @region, credentials: @credentials)
            end
          end
					loadSubnets

          MU.log "VPC #{@mu_name} created", details: @config
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          "arn:"+(MU::Cloud::AWS.isGovCloud?(@region) ? "aws-us-gov" : "aws")+":ec2:"+@region+":"+MU::Cloud::AWS.credToAcct(@credentials)+":vpc/"+@cloud_id
        end

        # Describe this VPC
        # @return [Hash]
        def notify
          @config
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          vpc_name = @deploy.getResourceName(@config['name'])

          # Generate peering connections
          if !@config['peers'].nil? and @config['peers'].size > 0
            @config['peers'].each { |peer|
              peerWith(peer)
            }
          end

          # Add any routes that reference instances, which would've been created
          # in Server objects' create phases.
          if !@config['route_tables'].nil?
            @config['route_tables'].each { |rtb|
              route_table_id = rtb['route_table_id']

              rtb['routes'].each { |route|
                if !route['nat_host_id'].nil? or !route['nat_host_name'].nil?
                  route_config = {
                    :route_table_id => route_table_id,
                    :destination_cidr_block => route['destination_network']
                  }

                  nat_instance = findBastion(
                    nat_name: route["nat_host_name"],
                    nat_cloud_id: route["nat_host_id"]
                  )
                  if nat_instance.nil?
                    raise MuError, "VPC #{vpc_name} is configured to use #{route} as a route, but I can't find a matching bastion host!"
                  end
                  route_config[:instance_id] = nat_instance.cloud_id

                  MU.log "Creating route for #{route['destination_network']} through NAT host #{nat_instance.cloud_id}", details: route_config
                  MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_route(route_config)
                end
              }

            }
          end

        end

        # Locate an existing VPC or VPCs and return an array containing matching AWS resource descriptors for those that match.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching VPCs
        def self.find(**args)
          args[:region] ||= MU.curRegion
          args[:tag_key] ||= "Name"

          retries = 0
          map = {}
          begin
            sleep 5 if retries < 0

            if !args[:tag_value].nil?
              MU.log "Searching for VPC by tag:#{args[:tag_key]}=#{args[:tag_value]}", MU::DEBUG
              resp = MU::Cloud::AWS.ec2(region: args[:region], credentials: args[:credentials]).describe_vpcs(
                filters: [
                  {name: "tag:#{args[:tag_key]}", values: [args[:tag_value]]}
                ]
              )
              if resp.data.vpcs.nil? or resp.data.vpcs.size == 0
                return nil
              elsif resp.data.vpcs.size >= 1
                resp.data.vpcs.each { |vpc|
                  map[vpc.vpc_id] = vpc
                }
                return map
              end
            elsif !args[:cloud_id].nil?
              MU.log "Searching for VPC id '#{args[:cloud_id]}' in #{args[:region]}", MU::DEBUG
              begin
                resp = MU::Cloud::AWS.ec2(region: args[:region], credentials: args[:credentials]).describe_vpcs(vpc_ids: [args[:cloud_id].to_s])
                resp.vpcs.each { |vpc|
                  map[vpc.vpc_id] = vpc
                }
                return map
              rescue Aws::EC2::Errors::InvalidVpcIDNotFound
              end
            else
              resp = MU::Cloud::AWS.ec2(region: args[:region], credentials: args[:credentials]).describe_vpcs
              resp.vpcs.each { |vpc|
                map[vpc.vpc_id] = vpc
              }
            end

            retries = retries + 1
          end while retries < 5

          return map
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**_args)
          bok = {
            "cloud" => "AWS",
            "credentials" => @credentials,
            "cloud_id" => @cloud_id,
            "region" => @region
          }

          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end

          return nil if cloud_desc.is_default

          bok['name'] = @cloud_id.sub(/^vpc-/, '') # blech
          bok['ip_block'] = cloud_desc.cidr_block

          if cloud_desc.tags and !cloud_desc.tags.empty?
            bok['tags'] = MU.structToHash(cloud_desc.tags, stringify_keys: true)
            realname = MU::Adoption.tagsToName(bok['tags'])
            bok['name'] = realname if realname
          end

# XXX dhcpopts

          bok['create_bastion'] = false # XXX figure out a way to detect this

          logs = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_flow_logs(filter: [{ "name" => "resource-id", "values" => [@cloud_id] }])
          if logs and logs.flow_logs and !logs.flow_logs.empty?
            bok['enable_traffic_logging'] = true
            bok['traffic_type_to_log'] = logs.flow_logs.first.traffic_type.downcase
            log_group_name = logs.flow_logs.first.log_group_name
            if !log_group_name.match(/^[A-Z0-9\-]+-[A-Z0-9\-]+-\d{10}-[A-Z]{2}-/)
              bok['log_group_name'] = log_group_name
            end
          end

          nats = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_nat_gateways(filter: [{ "name" => "vpc-id", "values" => [@cloud_id] }])
          if nats and nats.nat_gateways and !nats.nat_gateways.empty?
            bok['create_nat_gateway'] = true
            bok['nat_gateway_multi_az'] = true if nats.nat_gateways.size > 1
          end

          rtbs = MU::Cloud::AWS::VPC.get_route_tables(vpc_ids: [@cloud_id], region: @region, credentials: @credentials)

          associations = {}
          if rtbs and !rtbs.empty?
            bok['route_tables'] = []
            rtbs.each { |rtb_desc|
              rtb = { "name" => rtb_desc.route_table_id.sub(/^rtb-/, '') }
              if rtb_desc.tags and !rtb_desc.tags.empty?
                rtb_desc.tags.each { |tag|
                  if tag.key == "Name"
                    rtb['name'] = tag.value
                    break
                  elsif tag.key == "aws:cloudformation:logical-id"
                    rtb['name'] = tag.value
                  end
                }
              end
              if rtb_desc.associations
                rtb_desc.associations.each { |assoc|
                  if assoc.subnet_id
                    associations[assoc.subnet_id] = rtb['name']
                  elsif assoc.gateway_id
                    MU.log " Saw a route table association I don't know how to adopt in #{@cloud_id}", MU::WARN, details: rtb_desc
                  end
                }
              end
              if rtb_desc.routes
                rtb['routes'] = []
                rtb_desc.routes.each { |r|
                  route = {
                    "destination_network" => r.destination_cidr_block,
                  }
                  if r.nat_gateway_id
                    route["gateway"] = "#NAT"
                  elsif r.gateway_id and r.gateway_id != "local"
                    route["gateway"] = "#INTERNET"
                  elsif r.vpc_peering_connection_id
                    route["peer_id"] = r.vpc_peering_connection_id
                  elsif r.instance_id
                    route["nat_host_id"] = r.instance_id
                  end
                  rtb['routes'] << route
                }
              end
              bok['route_tables'] << rtb
            }
          end

          if !@subnets.empty?
            bok['subnets'] = []
            @subnets.each { |s|
              subnet = {
                "ip_block" => s.cloud_desc.cidr_block,
                "availability_zone" => s.cloud_desc.availability_zone,
                "map_public_ips" => s.cloud_desc.map_public_ip_on_launch,
                "name" => s.name
              }
              if associations[s.cloud_id]
                subnet["route_table"] = associations[s.cloud_id]
              end
              bok['subnets'] << subnet
            }
          end
          bok['name'].gsub!(/[^a-zA-Z0-9_\-]+/, '_')

          bok
        end

        # Return an array of MU::Cloud::AWS::VPC::Subnet objects describe the
        # member subnets of this VPC.
        #
        # @return [Array<MU::Cloud::AWS::VPC::Subnet>]
        def subnets
          if @subnets.nil? or @subnets.size == 0
            return loadSubnets
          end
          return @subnets
        end

        # Describe subnets associated with this VPC. We'll compose identifying
        # information similar to what MU::Cloud.describe builds for first-class
        # resources.
        # @return [Array<MU::Cloud::AWS::VPC::Subnet>]
        def loadSubnets
          return [] if !@cloud_id

          resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_subnets(
            filters: [
              { name: "vpc-id", values: [@cloud_id] }
            ]
          )
          if resp.nil? or resp.subnets.nil? or resp.subnets.empty?
            MU.log "Got empty results when trying to list subnets in #{@cloud_id} (#{@region})", MU::WARN
            return []
          end

          @subnetcachesemaphore.synchronize {
            @subnets ||= []
            ext_ids = @subnets.each.collect { |s| s.cloud_id }

            # If we're a plain old Mu resource, load our config and deployment
            # metadata. Like ya do.
            if !@config.nil? and @config.has_key?("subnets")
              @config['subnets'].each { |subnet|
                subnet['mu_name'] ||= @mu_name+"-"+subnet['name']
                subnet['region'] = @region
                subnet['credentials'] = @credentials
                resp.subnets.each { |desc|
                  if desc.cidr_block == subnet["ip_block"]
                    subnet["tags"] = MU.structToHash(desc.tags)
                    subnet["cloud_id"] = desc.subnet_id
                    break
                  end
                }

                if subnet["cloud_id"] and !ext_ids.include?(subnet["cloud_id"])
                  @subnets << MU::Cloud::AWS::VPC::Subnet.new(self, subnet)
                elsif !subnet["cloud_id"]
                  resp.subnets.each { |desc|
                    if desc.cidr_block == subnet["ip_block"]
                      subnet['cloud_id'] = desc.subnet_id
                      @subnets << MU::Cloud::AWS::VPC::Subnet.new(self, subnet)
                    end
                  }
                end

              }
            end

            # Of course we might be loading up a dummy subnet object from a
            # foreign or non-Mu-created VPC and subnet. So make something up.
            if @subnets.empty?
              resp.subnets.each { |desc|
                subnet = {
                  "ip_block" => desc.cidr_block,
                  "tags" => MU.structToHash(desc.tags),
                  "cloud_id" => desc.subnet_id,
                  'region' => @region,
                  'credentials' => @credentials,
                }
                subnet['name'] = subnet["ip_block"].gsub(/[\.\/]/, "_")
                subnet['mu_name'] = @mu_name+"-"+subnet['name']
                @subnets << MU::Cloud::AWS::VPC::Subnet.new(self, subnet)
              }
            end

            return @subnets
          }
        end

        # Given some search criteria try locating a NAT Gaateway in this VPC.
        # @param nat_cloud_id [String]: The cloud provider's identifier for this NAT.
        # @param nat_filter_key [String]: A cloud provider filter to help identify the resource, used in conjunction with nat_filter_value.
        # @param nat_filter_value [String]: A cloud provider filter to help identify the resource, used in conjunction with nat_filter_key.
        # @param region [String]: The cloud provider region of the target instance.
        def findNat(nat_cloud_id: nil, nat_filter_key: nil, nat_filter_value: nil, region: MU.curRegion, credentials: nil)
          # Discard the nat_cloud_id if it's an AWS instance ID
          nat_cloud_id = nil if nat_cloud_id && nat_cloud_id.start_with?("i-")
          credentials ||= @credentials

          if @gateways.nil?
            @gateways = 
              if nat_cloud_id
                MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_nat_gateways(nat_gateway_ids: [nat_cloud_id])
              elsif nat_filter_key && nat_filter_value
                MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_nat_gateways(
                  filter: [
                    {
                      name: nat_filter_key,
                      values: [nat_filter_value]
                    }
                  ]
                ).nat_gateways
              end
            end
            
            @gateways ? @gateways.first : nil
        end

        # Given some search criteria for a {MU::Cloud::Server}, see if we can
        # locate a NAT host in this VPC.
        # @param nat_name [String]: The name of the resource as defined in its 'name' Basket of Kittens field, typically used in conjunction with deploy_id.
        # @param nat_cloud_id [String]: The cloud provider's identifier for this NAT.
        # @param nat_tag_key [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_value.
        # @param nat_tag_value [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_key.
        # @param nat_ip [String]: An IP address associated with the NAT instance.
        def findBastion(nat_name: nil, nat_cloud_id: nil, nat_tag_key: nil, nat_tag_value: nil, nat_ip: nil)

          deploy_id = nil
          nat_name = nat_name.to_s if !nat_name.nil? and nat_name.class.to_s == "MU::Config::Tail"
          nat_cloud_id = nat_cloud_id.to_s if !nat_cloud_id.nil? and nat_cloud_id.class.to_s == "MU::Config::Tail"
          nat_ip = nat_ip.to_s if !nat_ip.nil? and nat_ip.class.to_s == "MU::Config::Tail"
          nat_tag_key = nat_tag_key.to_s if !nat_tag_key.nil? and nat_tag_key.class.to_s == "MU::Config::Tail"
          nat_tag_value = nat_tag_value.to_s if !nat_tag_value.nil? and nat_tag_value.class.to_s == "MU::Config::Tail"

          # If we're searching by name, assume it's part of this here deploy.
          if nat_cloud_id.nil? and !@deploy.nil?
            deploy_id = @deploy.deploy_id
          end
          found = MU::MommaCat.findStray(
              @config['cloud'],
              "server",
              name: nat_name,
              region: @region,
              cloud_id: nat_cloud_id,
              deploy_id: deploy_id,
              tag_key: nat_tag_key,
              tag_value: nat_tag_value,
              allow_multi: true,
              dummy_ok: true,
              calling_deploy: @deploy
          )

          return nil if found.nil? || found.empty?
          if found.size > 1
            found.each { |nat|
              # Try some AWS-specific criteria
              cloud_desc = nat.cloud_desc
              if !nat_ip.nil? and
                  (cloud_desc.private_ip_address == nat_ip or cloud_desc.public_ip_address == nat_ip)
                return nat
              elsif cloud_desc.vpc_id == @cloud_id
                # XXX Strictly speaking we could have different NATs in different
                # subnets, so this can be wrong in corner cases. Why you'd
                # architect something that obnoxiously, I have no idea.
                return nat
              end
            }
          elsif found.size == 1
            return found.first
          end
          return nil
        end

        # Check for a subnet in this VPC matching one or more of the specified
        # criteria, and return it if found.
        def getSubnet(cloud_id: nil, name: nil, tag_key: nil, tag_value: nil, ip_block: nil)
          if !cloud_id and !name and !tag_key and !tag_value and !ip_block
            raise MuError, "getSubnet called with no non-nil arguments"
          end
          subnets

          @subnets.each { |subnet|
            if !cloud_id.nil? and !subnet.cloud_id.nil? and subnet.cloud_id.to_s == cloud_id.to_s
              return subnet
            elsif !name.nil? and !subnet.name.nil? and subnet.name.to_s == name.to_s
              return subnet
            elsif !ip_block.nil? and !subnet.ip_block.nil? and subnet.ip_block.to_s == ip_block.to_s
              return subnet
            end
          }
          return nil
        end

        # Get the subnets associated with an instance.
        # @param instance_id [String]: The cloud identifier of the instance
        # @param instance [String]: A cloud descriptor for the instance, to save us an API call if we already have it
        # @param region [String]: The cloud provider region of the target instance
        # @return [Array<String>]
        def self.getInstanceSubnets(instance_id: nil, instance: nil, region: MU.curRegion, credentials: nil)
          return [] if instance_id.nil? and instance.nil?
          my_subnets = []

          if instance.nil?
            begin
              instance = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_instances(instance_ids: [instance_id]).reservations.first.instances.first
            rescue NoMethodError, Aws::EC2::Errors::InvalidInstanceIDNotFound
              MU.log "Failed to identify instance #{instance_id} in MU::Cloud::AWS::VPC.getInstanceSubnets", MU::WARN
              return []
            end
          end
          my_subnets << instance.subnet_id if !instance.subnet_id.nil?
          if !instance.network_interfaces.nil?
            instance.network_interfaces.each { |iface|
              my_subnets << iface.subnet_id if !iface.subnet_id.nil?
            }
          end
          return my_subnets.uniq.sort
        end

        @route_cache = {}
        @rtb_cache = {}
        @rtb_cache_semaphore = Mutex.new
        # Check whether we (the Mu Master) have a direct route to a particular
        # subnet. Useful for skipping hops through bastion hosts to get directly
        # at child nodes in peered VPCs and the like.
        # @param target_instance [OpenStruct]: The cloud descriptor of the instance to check.
        # @param region [String]: The cloud provider region of the target subnet.
        # @return [Boolean]
        def self.haveRouteToInstance?(target_instance, region: MU.curRegion, credentials: nil)
          return false if target_instance.nil?
          return false if MU.myCloud != "AWS"
          instance_id = target_instance.instance_id
# XXX check if I'm even in AWS before all this bullshit
          target_vpc_id = target_instance.vpc_id
          my_vpc_id = MU.myCloudDescriptor.vpc_id
          if (target_vpc_id && !target_vpc_id.empty?) && (my_vpc_id && !my_vpc_id.empty?)
            # If the master and the node are in the same vpc then more likely than not there is a route...
            if target_vpc_id == my_vpc_id
              MU.log "I share a VPC with #{instance_id}, I can route to it directly", MU::DEBUG
              @route_cache[instance_id] = true
              return true
            end
          end

          return @route_cache[instance_id] if @route_cache.has_key?(instance_id) && @route_cache[instance_id]
          my_subnets = MU::Cloud::AWS::VPC.getInstanceSubnets(instance: MU.myCloudDescriptor)
          target_subnets = MU::Cloud::AWS::VPC.getInstanceSubnets(instance: target_instance, region: region, credentials: credentials)

          my_subnets_key = my_subnets.join(",")
          target_subnets_key = target_subnets.join(",")
          MU::Cloud::AWS::VPC.update_route_tables_cache(my_subnets_key, region: MU.myRegion)
          MU::Cloud::AWS::VPC.update_route_tables_cache(target_subnets_key, region: region, credentials: credentials)

          if MU::Cloud::AWS::VPC.can_route_to_master_peer?(my_subnets_key, target_subnets_key, instance_id)
            return true
          else
            # The cache can be out of date at times, check again without it
            MU::Cloud::AWS::VPC.update_route_tables_cache(my_subnets_key, use_cache: false, region: MU.myRegion)
            MU::Cloud::AWS::VPC.update_route_tables_cache(target_subnets_key, use_cache: false, region: region, credentials: credentials)

            return MU::Cloud::AWS::VPC.can_route_to_master_peer?(my_subnets_key, target_subnets_key, instance_id)
          end

        end

        # updates the route table cache (@rtb_cache).
        # @param subnet_key [String]: The subnet/subnets route tables will be extracted from.
        # @param use_cache [Boolean]: If to use the existing cache and add records to cache only if missing, or to also replace exising records in cache.
        # @param region [String]: The cloud provider region of the target subnet.
        def self.update_route_tables_cache(subnet_key, use_cache: true, region: MU.curRegion, credentials: nil)
          @rtb_cache_semaphore.synchronize {
            update = 
              if !use_cache
                true
              elsif use_cache && !@rtb_cache.has_key?(subnet_key)
                true
              else
                false
              end

            if update
              route_tables = MU::Cloud::AWS::VPC.get_route_tables(subnet_ids: subnet_key.split(","), region: region, credentials: credentials)

              if route_tables.empty? && !subnet_key.empty?
                vpc_id = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_subnets(subnet_ids: subnet_key.split(",")).subnets.first.vpc_id
                MU.log "No route table associations found for #{subnet_key}, falling back to the default table for #{vpc_id}", MU::NOTICE
                route_tables = MU::Cloud::AWS::VPC.get_route_tables(vpc_ids: [vpc_id], region: region, credentials: credentials)
              end

              @rtb_cache[subnet_key] = route_tables
            end
          }
        end

        # Checks if the MU master has a route to a subnet in a peered VPC. Can be used on any subnets
        # @param source_subnets_key [String]: The subnet/subnets on one side of the peered VPC.
        # @param target_subnets_key [String]: The subnet/subnets on the other side of the peered VPC.
        # @param instance_id [String]: The instance ID in the target subnet/subnets.
        # @return [Boolean]
        def self.can_route_to_master_peer?(source_subnets_key, target_subnets_key, instance_id)
          my_routes = []
          vpc_peer_mapping = {}

          @rtb_cache[source_subnets_key].each { |route_table|
            route_table.routes.each { |route|
              if route.destination_cidr_block != "0.0.0.0/0" and !route.destination_cidr_block.nil?
                my_routes << NetAddr::IPv4Net.parse(route.destination_cidr_block)
                if !route.vpc_peering_connection_id.nil?
                  if route.state == "blackhole"
                    MU.log "Ignoring blackhole route to #{route.destination_cidr_block} over #{route.vpc_peering_connection_id}", MU::WARN
                  end
                  next if route.state != "active"
                  vpc_peer_mapping[route.vpc_peering_connection_id] = route.destination_cidr_block
                end
              end
            }
          }
          my_routes.uniq!
          target_routes = []
          @rtb_cache[target_subnets_key].each { |route_table|
            route_table.routes.each { |route|
              next if route.destination_cidr_block == "0.0.0.0/0" or route.state != "active" or route.destination_cidr_block.nil?
              cidr = NetAddr::IPv4Net.parse(route.destination_cidr_block)
              shared_ip_space = false
              my_routes.each { |my_cidr|
                target_routes << NetAddr::IPv4Net.parse(route.destination_cidr_block)
                if my_cidr.contains(NetAddr::IPv4Net.parse(route.destination_cidr_block).nth(2)) or my_cidr.cmp(cidr)
                  shared_ip_space = true
                  break
                end
              }

              if shared_ip_space && !route.vpc_peering_connection_id.nil? && vpc_peer_mapping.has_key?(route.vpc_peering_connection_id)
                MU.log "I share a VPC peering connection (#{route.vpc_peering_connection_id}) with #{instance_id} for #{route.destination_cidr_block}, I can route to it directly", MU::DEBUG
                @route_cache[instance_id] = true
                return true
              end
            }
          }

          return false
        end

        # Retrieves the route tables of used by subnets
        # @param subnet_ids [Array]: The cloud identifier of the subnets to retrieve the route tables for.
        # @param vpc_ids [Array]: The cloud identifier of the VPCs to retrieve route tables for.
        # @param region [String]: The cloud provider region of the target subnet.
        # @return [Array<OpenStruct>]: The cloud provider's complete descriptions of the route tables
        def self.get_route_tables(subnet_ids: [], vpc_ids: [], region: MU.curRegion, credentials: nil)
          resp = []
          if !subnet_ids.empty?
            resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_route_tables(
              filters: [
                {
                  name: "association.subnet-id", 
                  values: subnet_ids
                }
              ]
            ).route_tables
          elsif !vpc_ids.empty?
            resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_route_tables(
              filters: [
                {
                  name: "vpc-id", 
                  values: vpc_ids
                }
              ]
            ).route_tables
          else
            resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_route_tables.route_tables
          end

          return resp
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

        # Remove all VPC resources associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU.log "AWS::VPC.cleanup: need to support flags['known']", MU::DEBUG, details: flags

          tagfilters = [
            {name: "tag:MU-ID", values: [deploy_id]}
          ]
          if !ignoremaster
            tagfilters << {name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip]}
          end

          vpcs = []
          MU.retrier([Aws::EC2::Errors::InvalidVpcIDNotFound], wait: 5) {
            resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_vpcs(filters: tagfilters, max_results: 1000).vpcs
            vpcs = resp if !resp.empty?
          }

#          resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_vpc_peering_connections(
#            filters: [
#              {
#                name: "requester-vpc-info.vpc-id",
#                values: [@cloud_id]
#              },
#              {
#                name: "accepter-vpc-info.vpc-id",
#                values: [peer_id.to_s]
#              }
#            ]
#          )

          if !vpcs.empty?
            gwthreads = []
            vpcs.each { |vpc|
              purge_peering_connections(noop, vpc.vpc_id, region: region, credentials: credentials)
              # NAT gateways don't have any tags, and we can't assign them a name. Lets find them based on a VPC ID
              gwthreads << Thread.new {
                purge_nat_gateways(noop, vpc_id: vpc.vpc_id, region: region, credentials: credentials)
                purge_endpoints(noop, vpc_id: vpc.vpc_id, region: region, credentials: credentials)
                purge_interfaces(noop, [{name: "vpc-id", values: [vpc.vpc_id]}], region: region, credentials: credentials)
              }
            }
            gwthreads.each { |t|
              t.join
            }
          end

          purge_gateways(noop, tagfilters, region: region, credentials: credentials)
          purge_routetables(noop, tagfilters, region: region, credentials: credentials)
          purge_interfaces(noop, tagfilters, region: region, credentials: credentials)
          purge_subnets(noop, tagfilters, region: region, credentials: credentials)
          purge_vpcs(noop, tagfilters, region: region, credentials: credentials)
          purge_dhcpopts(noop, tagfilters, region: region, credentials: credentials)
          purge_eips(noop, tagfilters, region: region, credentials: credentials)

#          unless noop
#            MU::Cloud::AWS.iam.list_roles.roles.each{ |role|
#              match_string = "#{deploy_id}.*TRAFFIC-LOG"
#            }
#          end
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          # Flow Logs can be declared at the VPC level or the subnet level
          flowlogs = {
            "traffic_type_to_log" => {
              "type" => "string",
              "description" => "The class of traffic to log - accepted traffic, rejected traffic or all traffic.",
              "enum" => ["accept", "reject", "all"],
              "default" => "all"
            },
            "log_group_name" => {
              "type" => "string",
              "description" => "An existing CloudWachLogs log group the traffic will be logged to. If not provided, a new one will be created"
            },
            "enable_traffic_logging" => {
              "type" => "boolean",
              "description" => "If traffic logging is enabled or disabled. Will be enabled on all subnets and network interfaces if set to true on a VPC",
              "default" => false
            }
          }

          schema = {
            "subnets" => {
              "items" => {
                "properties" => flowlogs
              }
            }
          }
          schema.merge!(flowlogs)
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::vpcs}, bare and unvalidated.
        # @param vpc [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment config of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(vpc, configurator)
          ok = true

          if vpc["enable_traffic_logging"]
            logdesc = {
              "name" => vpc['name']+"loggroup",
            }
            logdesc["tags"] = vpc["tags"] if !vpc["tags"].nil?
#            logdesc["optional_tags"] = vpc["optional_tags"] if !vpc["optional_tags"].nil?
            configurator.insertKitten(logdesc, "logs")
            MU::Config.addDependency(vpc, vpc['name']+"loggroup", "log")

            roledesc = {
              "name" => vpc['name']+"logrole",
              "can_assume" => [
                {
                  "entity_id" => "vpc-flow-logs.amazonaws.com",
                  "entity_type" => "service"
                }
              ],
              "policies" => [
                {
                  "name" => "FlowLogPerms",
                  "permissions" => [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:PutLogEvents"
                  ],
                  "targets" => [
                    {
                      "type" => "log",
                      "identifier" => vpc['name']+"loggroup"
                    }
                  ]
                }
              ],
              "dependencies" => [
                {
                  "type" => "log",
                  "name" => vpc['name']+"loggroup"
                }
              ]
            }
            roledesc["tags"] = vpc["tags"] if !vpc["tags"].nil?
            roledesc["optional_tags"] = vpc["optional_tags"] if !vpc["optional_tags"].nil?
            configurator.insertKitten(roledesc, "roles")
            MU::Config.addDependency(vpc, vpc['name']+"logrole", "role")
          end

          subnet_routes = Hash.new

          if vpc['subnets']
            vpc['subnets'].each { |subnet|
              subnet_routes[subnet['route_table']] = Array.new if subnet_routes[subnet['route_table']].nil?
              subnet_routes[subnet['route_table']] << subnet['name']
            }
          end
          if vpc['endpoint_policy'] && !vpc['endpoint_policy'].empty?
            if !vpc['endpoint']
              MU.log "'endpoint_policy' is declared however endpoint is not set", MU::ERR
              ok = false
            end

            attributes = %w{Effect Action Resource Principal Sid}
            vpc['endpoint_policy'].each { |rule|
              rule.keys.each { |key|
                if !attributes.include?(key)
                  MU.log "'Attribute #{key} can't be used in 'endpoint_policy'", MU::ERR
                  ok = false
                end
              }
            }
          end

          nat_gateway_route_tables = []
          nat_gateway_added = false
          public_rtbs = []
          private_rtbs = []
          nat_routes = {}
          vpc['route_tables'].each { |table|
            routes = []
            table['routes'].each { |route|
              if routes.include?(route['destination_network'])
                MU.log "Duplicate routes to #{route['destination_network']} in route table #{table['name']}", MU::ERR
                ok = false
              else
                routes << route['destination_network']
              end

              if (route['nat_host_name'] or route['nat_host_id'])
                private_rtbs << table['name']
                route.delete("gateway") if route['gateway'] == '#INTERNET'
              end
              if !route['nat_host_name'].nil? and configurator.haveLitterMate?(route['nat_host_name'], "server") and !subnet_routes.nil? and !subnet_routes.empty?
                subnet_routes[table['name']].each { |subnet|
                  nat_routes[subnet] = route['nat_host_name']
                }
                MU::Config.addDependency(vpc, route['nat_host_name'], "server", no_create_wait: true)
              elsif route['gateway'] == '#NAT'
                vpc['create_nat_gateway'] = true
                private_rtbs << table['name']
              elsif route['gateway'] == '#INTERNET'
                public_rtbs << table['name']
              end
              next if !vpc['subnets']
              
              vpc['subnets'].each { |subnet|
                if route['gateway'] == '#INTERNET'
                  if table['name'] == subnet['route_table']
                    subnet['is_public'] = true
                    if vpc['create_nat_gateway'] and (vpc['nat_gateway_multi_az'] or !nat_gateway_added)
                      subnet['create_nat_gateway'] = true
                      nat_gateway_added = true
                    else
                      subnet['create_nat_gateway'] = false
                    end
                  else
                    subnet['is_public'] = false
                  end
                  if !nat_routes[subnet['name']].nil?
                    subnet['nat_host_name'] = nat_routes[subnet['name']]
                  end
                elsif route['gateway'] == '#NAT'
                  if table['name'] == subnet['route_table']
                    if route['nat_host_name'] or route['nat_host_id']
                      MU.log "You can either use a NAT gateway or a NAT server, not both.", MU::ERR
                      ok = false
                    end

                    subnet['is_public'] = false
                    nat_gateway_route_tables << table
                  end
                end
              }
            }
          }

          if (!vpc['subnets'] or vpc['subnets'].empty?) and vpc['create_standard_subnets']
            if vpc['availability_zones'].nil? or vpc['availability_zones'].empty?
              vpc['availability_zones'] = MU::Cloud::AWS.listAZs(region: vpc['region'], credentials: vpc['credentials'])
            else
              # turn into a hash so we can use list parameters easily
              vpc['availability_zones'] = vpc['availability_zones'].map { |val| val['zone'] }
            end

            subnets = configurator.divideNetwork(vpc['ip_block'], vpc['availability_zones'].size*vpc['route_tables'].size, 28)

            ok = false if subnets.nil?
            vpc['subnets'] = []
            count = 0
            vpc['availability_zones'].each { |az|
              addnat = false
              if vpc['create_nat_gateway'] and (vpc['nat_gateway_multi_az'] or !nat_gateway_added) and public_rtbs.size > 0
                addnat = true
                nat_gateway_added = true
              end
              vpc['route_tables'].each { |rtb|
                vpc['subnets'] << {
                  "name" => "Subnet#{count}#{rtb['name'].capitalize}",
                  "availability_zone" => az,
                  "ip_block" => subnets.shift,
                  "route_table" => rtb['name'],
                  
                  "map_public_ips" => (public_rtbs and public_rtbs.include?(rtb['name'])),
                  "is_public" => (public_rtbs and public_rtbs.include?(rtb['name'])),
                  "create_nat_gateway" => (addnat and public_rtbs and public_rtbs.include?(rtb['name']))
                }
              }
              count = count + 1
            }
          end

          nat_gateway_route_tables.uniq!
          if nat_gateway_route_tables.size < 2 && vpc['nat_gateway_multi_az']
            MU.log "'nat_gateway_multi_az' is enabled but only one route table exists. For multi-az support create one private route table per AZ", MU::ERR
            ok = false
          end

          if nat_gateway_route_tables.size > 0 && !vpc['create_nat_gateway']
            MU.log "There are route tables with a NAT gateway route, but create_nat_gateway is set to false. Setting to true", MU::NOTICE
            vpc['create_nat_gateway'] = true
          end

          ok
        end

        # List the CIDR blocks to which these VPC has routes. Exclude obvious
        # things like +0.0.0.0/0+.
        # @param subnets [Array<String>]: Only return the routes relevant to these subnet ids
        def routes(subnets: [])
          @my_visible_cidrs ||= {}
          return @my_visible_cidrs[subnets] if @my_visible_cidrs[subnets]
          filters = [{ :name => "vpc-id", :values => [@cloud_id] }]
          if subnets and subnets.size > 0
            filters << { :name => "association.subnet-id", :values => subnets }
          end
          tables = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_route_tables(
            filters: filters
          )
          cidrs = []
          if tables and tables.route_tables
            tables.route_tables.each { |rtb|
              rtb.routes.each { |route|
                next if route.destination_cidr_block == "0.0.0.0/0"
                cidrs << route.destination_cidr_block
              }
            }
          end
          @my_visible_cidrs[subnets] = cidrs.uniq.sort
          @my_visible_cidrs[subnets]
        end


        # List the route tables for each subnet in the given VPC
        # @param vpc_id [String]:
        # @param region [String]:
        # @param credentials [String]:
        def self.listAllSubnetRouteTables(vpc_id, region: MU.curRegion, credentials: nil)
          resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_subnets(
              filters: [
                  {
                      name: "vpc-id",
                      values: [vpc_id]
                  }
              ]
          )

          subnets = resp.subnets.map { |subnet| subnet.subnet_id }

          tables = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_route_tables(
              filters: [
                  {
                      name: "vpc-id",
                      values: [vpc_id]
                  },
                  {
                      name: "association.subnet-id",
                      values: subnets
                  }
              ]
          )

          if tables.nil? or tables.route_tables.size == 0
            MU.log "No route table associations found for #{subnets}, falling back to the default table for #{vpc_id}", MU::NOTICE
            tables = MU::Cloud::AWS.ec2(region: MU.myRegion).describe_route_tables(
              filters: [
                {name: "vpc-id", values: [vpc_id]},
                {name: "association.main", values: ["true"]},
              ]
            )
          end

          table_ids = []
          tables.route_tables.each { |rtb|
            table_ids << rtb.route_table_id
          }
          return table_ids.uniq
        end

        # Remove all network interfaces associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param filters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_interfaces(noop = false, filters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion, credentials: nil)
          resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_network_interfaces(
            filters: filters
          )
          ifaces = resp.data.network_interfaces

          return if ifaces.nil? or ifaces.size == 0

          ifaces.each { |iface|
            if iface.vpc_id
              default_sg = MU::Cloud::AWS::VPC.getDefaultSg(iface.vpc_id, region: region, credentials: credentials)
              if default_sg and (iface.groups.size > 1 or (iface.groups.size == 1 and iface.groups.first.group_id != default_sg))
                MU.log "Removing extra security groups from ENI #{iface.network_interface_id}"
                if !noop
                  begin
                    MU::Cloud::AWS.ec2(credentials: credentials, region: region).modify_network_interface_attribute(
                      network_interface_id: iface.network_interface_id,
                      groups: [default_sg]
                    )
                  rescue ::Aws::EC2::Errors::AuthFailure
                    MU.log "Permission denied attempting to trim Security Group list for #{iface.network_interface_id}", MU::WARN, details: iface.groups.map { |g| g.group_name }.join(",")+" => default"
                  end
                end
              end
            end
            begin
              if iface.attachment and iface.attachment.status == "attached"
                MU.log "Detaching Network Interface #{iface.network_interface_id} from #{iface.attachment.instance_owner_id}"
                tried_lbs = false
                begin
                  MU::Cloud::AWS.ec2(credentials: credentials, region: region).detach_network_interface(attachment_id: iface.attachment.attachment_id) if !noop
                rescue Aws::EC2::Errors::OperationNotPermitted => e
                  MU.log "Can't detach #{iface.network_interface_id}: #{e.message}", MU::WARN, details: iface.attachment
                  next
                rescue Aws::EC2::Errors::IncorrectState => e
                  MU.log e.message, MU::WARN
                  sleep 5
                  retry
                rescue Aws::EC2::Errors::InvalidAttachmentIDNotFound => e
                  # suits me just fine
                rescue Aws::EC2::Errors::AuthFailure => e
                  if !tried_lbs and iface.attachment.instance_owner_id == "amazon-elb"
                    MU::Cloud.resourceClass("AWS", "LoadBalancer").cleanup(
                      noop: noop,
                      region: region,
                      credentials: credentials,
                      flags: {"vpc_id" => iface.vpc_id}
                    )
                    tried_lbs = true
                    retry
                  end
                  MU.log e.message, MU::ERR, details: iface.attachment
                end
              end
              MU.log "Deleting Network Interface #{iface.network_interface_id}"
              MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_network_interface(network_interface_id: iface.network_interface_id) if !noop
            rescue Aws::EC2::Errors::InvalidNetworkInterfaceIDNotFound
              # ok then!
            rescue Aws::EC2::Errors::InvalidParameterValue => e
              MU.log e.message, MU::ERR, details: iface
            end
          }
        end

        # Fetch the group id of the +default+ security group for the given VPC
        # @param vpc_id [String]
        # @param region [String]
        # @param credentials [String]
        # @return [String]
        def self.getDefaultSg(vpc_id, region: MU.curRegion, credentials: nil)
          default_sg_resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_security_groups(
            filters: [
              { name: "group-name", values: ["default"] },
              { name: "vpc-id", values: [vpc_id] }
            ]
          ).security_groups
          if default_sg_resp and default_sg_resp.size == 1
            return default_sg_resp.first.group_id
          end
          nil
        end

        # Try to locate the default VPC for a region, and return a BoK-style
        # config fragment for something that might want to live in it.
        def self.defaultVpc(region, credentials)
          cfg_fragment = nil
          MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_vpcs.vpcs.each { |vpc|
            if vpc.is_default
              cfg_fragment = {
                "id" => vpc.vpc_id,
                "cloud" => "AWS",
                "region" => region,
                "credentials" => credentials
              }
              cfg_fragment['subnets'] = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_subnets(
                filters: [
                  {
                    name: "vpc-id",
                    values: [vpc.vpc_id]
                  }
                ]
              ).subnets.map { |s| { "subnet_id" => s.subnet_id } }
              break
            end
          }

          cfg_fragment
        end

        # Return a {MU::Config::Ref} that indicates this VPC.
        # @param subnet_ids [Array<String>]: Optional list of subnet ids with which to infer a +subnet_pref+ parameter.
        # @return [MU::Config::Ref]
        def getReference(subnet_ids = [])
          have_private = have_public = false
          subnets.each { |s|
            next if subnet_ids and !subnet_ids.empty? and !subnet_ids.include?(s.cloud_id)
            if s.private?
              have_private = true
            else
              have_public = true
            end
          }
          subnet_pref = if have_private == have_public
            "any"
          elsif have_private
            "all_private"
          elsif have_public
            "all_public"
          end
          MU::Config::Ref.get(
            id: @cloud_id,
            cloud: "AWS",
            credentials: @credentials,
            region: @region,
            type: "vpcs",
            subnet_pref: subnet_pref
          )
        end

        private

        def peerWith(peer)
          peer_ref = MU::Config::Ref.get(peer['vpc'])
          peer_obj = peer_ref.kitten
          if !peer_obj
            raise MuError.new "#{@mu_name}: Failed to locate my peer VPC", details: peer_ref.to_h
          end
          peer_id = peer_ref.kitten.cloud_id
          if peer_id == @cloud_id
            MU.log "#{@mu_name} attempted to peer with itself (#{@cloud_id})", MU::ERR, details: peer
            raise "#{@mu_name} attempted to peer with itself (#{@cloud_id})"
          end

          if peer_obj and peer_obj.config['peers']
            peer_obj.config['peers'].each { |peerpeer|
              if peerpeer['vpc']['name'] == @config['name'] and
                 (peer['vpc']['name'] <=> @config['name']) == -1
                MU.log "VPCs #{peer['vpc']['name']} and #{@config['name']} both declare mutual peering connection, ignoring #{@config['name']}'s redundant declaration", MU::DEBUG
                return
# XXX and if deploy_id matches or is unset
              end
            }

            peer['account'] ||= MU::Cloud::AWS.credToAcct(peer_obj.credentials)
          end

          peer['account'] ||= MU::Cloud::AWS.account_number

          # See if the peering connection exists before we bother
          # creating it.
          resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_vpc_peering_connections(
            filters: [
              {
                name: "requester-vpc-info.vpc-id",
                values: [@cloud_id]
              },
              {
                name: "accepter-vpc-info.vpc-id",
                values: [peer_id.to_s]
              }
            ]
          )

          peering_id = if !resp or !resp.vpc_peering_connections or
             resp.vpc_peering_connections.empty?

            MU.log "Setting peering connection from VPC #{@config['name']} (#{@cloud_id} in account #{MU::Cloud::AWS.credToAcct(@credentials)}) to #{peer_id} in account #{peer['account']}", details: peer
            resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_vpc_peering_connection(
              vpc_id: @cloud_id,
              peer_vpc_id: peer_id,
              peer_owner_id: peer['account'],
              peer_region: peer_obj.config['region']
            )
            resp.vpc_peering_connection.vpc_peering_connection_id
          else
            resp.vpc_peering_connections.first.vpc_peering_connection_id
          end

          peering_name = @deploy.getResourceName(@config['name']+"-PEER-"+peer_id)

          tag_me(peering_id, peering_name)

          # Create routes to our new friend.
          MU::Cloud::AWS::VPC.listAllSubnetRouteTables(@cloud_id, region: @region, credentials: @credentials).each { |rtb_id|
            my_route_config = {
              :route_table_id => rtb_id,
              :destination_cidr_block => peer_obj.cloud_desc.cidr_block,
              :vpc_peering_connection_id => peering_id
            }
            rtbdesc = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_route_tables(
              route_table_ids: [rtb_id]
            ).route_tables.first
            already_exists = false
            rtbdesc.routes.each { |r|
              if r.destination_cidr_block == peer_obj.cloud_desc.cidr_block
                if r.vpc_peering_connection_id != peering_id
                  MU.log "Attempt to create duplicate route to #{peer_obj.cloud_desc.cidr_block} from VPC #{@config['name']}", MU::ERR, details: r
                  raise MuError, "Can't create route via #{peering_id}, a route to #{peer_obj.cloud_desc.cidr_block} already exists"
                else
                  already_exists = true
                end
              end
            }
            next if already_exists

            MU.log "Creating peering route to #{peer_obj.cloud_desc.cidr_block} in #{peer['vpc']['region']} from VPC #{@config['name']} in #{@region}"
            resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_route(my_route_config)
          } # MU::Cloud::AWS::VPC.listAllSubnetRouteTables

          can_auto_accept = ((!peer_obj.nil? and !peer_obj.deploydata.nil? and peer_obj.deploydata['auto_accept_peers']) or $MU_CFG['allow_invade_foreign_vpcs'])

          cnxn = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_vpc_peering_connections(
            vpc_peering_connection_ids: [peering_id]
          ).vpc_peering_connections.first

          loop_if = Proc.new {
            cnxn = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_vpc_peering_connections(
              vpc_peering_connection_ids: [peering_id]
            ).vpc_peering_connections.first
            ((can_auto_accept and cnxn.status.code == "pending-acceptance") or (cnxn.status.code != "active" and cnxn.status.code != "pending-acceptance"))
          }

          MU.retrier(wait: 5, loop_if: loop_if, ignoreme: [Aws::EC2::Errors::VpcPeeringConnectionAlreadyExists, Aws::EC2::Errors::RouteAlreadyExists]) {
            if cnxn.status.code == "pending-acceptance"
              if can_auto_accept
                MU.log "Auto-accepting peering connection #{peering_id} from VPC #{@config['name']} (#{@cloud_id}) to #{peer_id}", MU::NOTICE
                MU::Cloud::AWS.ec2(region: peer_obj.config['region'], credentials: peer['account']).accept_vpc_peering_connection(
                  vpc_peering_connection_id: peering_id,
                )

                # Create routes back from our new friend to us.
                MU::Cloud::AWS::VPC.listAllSubnetRouteTables(peer_id, region: peer_obj.config['region'], credentials: peer['account']).uniq.each { |rtb_id|
                  peer_route_config = {
                    :route_table_id => rtb_id,
                    :destination_cidr_block => @config['ip_block'],
                    :vpc_peering_connection_id => peering_id
                  }
                  resp = MU::Cloud::AWS.ec2(region: peer_obj.config['region'], credentials: peer['account']).create_route(peer_route_config)
                }
              else
                MU.log "VPC #{peer_id} is not managed by this Mu server or is not configured to auto-accept peering requests. You must accept the peering request for '#{@config['name']}' (#{@cloud_id}) by hand.", MU::WARN, details: "In the AWS Console, go to VPC => Peering Connections and look in the Actions drop-down. You can also set 'Invade Foreign VPCs' to 'true' using mu-configure to auto-accept all peering connections within this account, regardless of whether this Mu server owns the VPCs. This setting is per-user."
              end
            end

            if ["failed", "rejected", "expired", "deleted"].include?(cnxn.status.code)
              MU.log "VPC peering connection from VPC #{@config['name']} (#{@cloud_id} in #{@region}) to #{peer_id} in #{peer_obj.config['region']} #{cnxn.status.code}: #{cnxn.status.message}", MU::ERR
              begin
                MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).delete_vpc_peering_connection(
                  vpc_peering_connection_id: peering_id
                )
              rescue Aws::EC2::Errors::InvalidStateTransition
                # XXX apparently this is normal?
              end
              raise MuError, "VPC peering connection from VPC #{@config['name']} (#{@cloud_id}) to #{peer_id} #{cnxn.status.code}: #{cnxn.status.message}"
            end

          }

        end

        def tag_me(resource_id = @cloud_id, name = @mu_name)
          MU::Cloud::AWS.createStandardTags(
            resource_id,
            region: @region,
            credentials: @credentials,
            optional: @config['optional_tags'],
            nametag: name,
            othertags: @config['tags']
          )
        end

        # Helper method for manufacturing route tables. Expect to be called from
        # {MU::Cloud::AWS::VPC#create} or {MU::Cloud::AWS::VPC#groom}.
        # @param rtb [Hash]: A route table description parsed through {MU::Config::BasketofKittens::vpcs::route_tables}.
        # @return [Hash]: The modified configuration that was originally passed in.
        def createRouteTable(rtb)
          vpc_id = @cloud_id
          vpc_name = @config['name']
          MU.setVar("curRegion", @region) if !@region.nil?
          resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_route_table(vpc_id: vpc_id).route_table
          route_table_id = rtb['route_table_id'] = resp.route_table_id
          sleep 5

          tag_me(route_table_id, vpc_name+"-"+rtb['name'].upcase)

          rtb['routes'].each { |route|
            if route['nat_host_id'].nil? and route['nat_host_name'].nil?
              route_config = {
                :route_table_id => route_table_id,
                :destination_cidr_block => route['destination_network']
              }
              if !route['peer_id'].nil?
                route_config[:vpc_peering_connection_id] = route['peer_id']
              else
                route_config[:gateway_id] = @config['internet_gateway_id']
              end
              # XXX how do the network interfaces work with this?
              unless route['gateway'] == '#NAT'
                # Need to change the order of how things are created to create the route here
                MU.log "Creating route for #{route['destination_network']}", details: route_config
                resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_route(route_config)
              end
            end
          }
          return rtb
        end

        # Remove all network gateways associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_gateways(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion, credentials: nil)
          resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_internet_gateways(
            filters: tagfilters
          )
          gateways = resp.data.internet_gateways

          gateways.each { |gateway|
            vpc_id = nil
            gateway.attachments.each { |attachment|
              vpc_id = attachment.vpc_id
              tried_interfaces = false
              begin
                MU.log "Detaching Internet Gateway #{gateway.internet_gateway_id} from #{attachment.vpc_id}"
                MU::Cloud::AWS.ec2(credentials: credentials, region: region).detach_internet_gateway(
                  internet_gateway_id: gateway.internet_gateway_id,
                  vpc_id: attachment.vpc_id
                ) if !noop
              rescue Aws::EC2::Errors::DependencyViolation => e
                if !tried_interfaces
                  purge_interfaces(noop, [{name: "vpc-id", values: [attachment.vpc_id]}], region: region, credentials: credentials)
                  tried_interfaces = true
                  sleep 2
                  retry
                end
                MU.log e.message, MU::ERR
              rescue Aws::EC2::Errors::GatewayNotAttached => e
                MU.log "Gateway #{gateway.internet_gateway_id} was already detached", MU::WARN
              end
            }

            tried_interfaces = false
            begin
              MU.log "Deleting Internet Gateway #{gateway.internet_gateway_id}"
              MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_internet_gateway(internet_gateway_id: gateway.internet_gateway_id) if !noop
            rescue Aws::EC2::Errors::DependencyViolation => e
              if !tried_interfaces and vpc_id
                purge_interfaces(noop, [{name: "vpc-id", values: [vpc_id]}], region: region, credentials: credentials)
                tried_interfaces = true
                sleep 2
                retry
              end
              MU.log e.message, MU::ERR
            rescue Aws::EC2::Errors::InvalidInternetGatewayIDNotFound
              MU.log "Gateway #{gateway.internet_gateway_id} was already destroyed by the time I got to it", MU::WARN
            end
          }
          return nil
        end
        private_class_method :purge_gateways

        # Remove all NAT gateways associated with the VPC of the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param vpc_id [String]: The cloud provider's unique VPC identifier
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_nat_gateways(noop = false, vpc_id: nil, region: MU.curRegion, credentials: nil)
          gateways = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_nat_gateways(
            filter: [
              {
                name: "vpc-id",
                values: [vpc_id],
              }
            ]
          ).nat_gateways

          threads = []

          if !gateways.empty?
            gateways.each { |gateway|
              next if noop
              MU.log "Deleting NAT Gateway #{gateway.nat_gateway_id}"
              threads << Thread.new {
                MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_nat_gateway(nat_gateway_id: gateway.nat_gateway_id)

                resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_nat_gateways(nat_gateway_ids: [gateway.nat_gateway_id]).nat_gateways.first

                loop_if = Proc.new {
                  resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_nat_gateways(nat_gateway_ids: [gateway.nat_gateway_id]).nat_gateways.first
                  (resp.state != "deleted" and resp.state != "failed")
                }

                MU.retrier([Aws::EmptyStructure, NoMethodError], ignoreme: [Aws::EC2::Errors::NatGatewayMalformed, Aws::EC2::Errors::NatGatewayNotFound], max: 50, loop_if: loop_if) { |retries, _wait|
                  MU.log "Waiting for nat gateway #{gateway.nat_gateway_id} to delete" if retries % 3 == 0
                }

              }
            }
          end

          threads.each { |t|
            t.join
          }

          return nil
        end
        private_class_method :purge_nat_gateways

        # Remove all Elastic IPs from the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_eips(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion, credentials: nil)
          eips = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_addresses(
            filters: tagfilters
          ).addresses

          threads = []

          if !eips.empty?
            eips.each { |eip|
              MU.log "Releasing EIP #{eip.public_ip} (#{eip.allocation_id})"
              next if noop
              if eip.association_id
                MU.log "Tags tell me I should release EIP #{eip.public_ip} (#{eip.allocation_id}), but it appears to be associated with something", MU::WARN, details: eip
                next
              end
              threads << Thread.new {
                MU::Cloud::AWS.ec2(credentials: credentials, region: region).release_address(allocation_id: eip.allocation_id)
              }
            }
          end

          threads.each { |t|
            t.join
          }

          return nil
        end
        private_class_method :purge_eips

        # Remove all VPC endpoints associated with the VPC of the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param vpc_id [String]: The cloud provider's unique VPC identifier
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_endpoints(noop = false, vpc_id: nil, region: MU.curRegion, credentials: nil)
          vpc_endpoints = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_vpc_endpoints(
            filters: [
              {
                name:"vpc-id",
                values: [vpc_id],
              }
            ]
          ).vpc_endpoints

          threads = []

          if !vpc_endpoints.empty?
            vpc_endpoints.each { |endpoint|
              MU.log "Deleting VPC endpoint #{endpoint.vpc_endpoint_id}"
              next if noop
              threads << Thread.new {
                MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_vpc_endpoints(vpc_endpoint_ids: [endpoint.vpc_endpoint_id])
                resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_vpc_endpoints(vpc_endpoint_ids: [endpoint.vpc_endpoint_id]).vpc_endpoints.first
                loop_if = Proc.new {
                  resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_vpc_endpoints(vpc_endpoint_ids: [endpoint.vpc_endpoint_id]).vpc_endpoints.first
                  resp.state != "deleted"
                }
                MU.retrier([Aws::EmptyStructure, NoMethodError], ignoreme: [Aws::EC2::Errors::InvalidVpcEndpointIdNotFound, Aws::EC2::Errors::VpcEndpointIdMalformed], max: 20, wait: 10, loop_if: loop_if) { |retries, _wait|
                  MU.log "Waiting for VPC endpoint #{endpoint.vpc_endpoint_id} to delete" if retries % 5 == 0
                }
              }
            }
          end

          threads.each { |t|
            t.join
          }

          return nil
        end
        private_class_method :purge_endpoints

        # Remove all route tables associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_routetables(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion, credentials: nil)
          resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_route_tables(
              filters: tagfilters
          )
          route_tables = resp.data.route_tables

          return if route_tables.nil? or route_tables.size == 0

          route_tables.each { |table|
            table.routes.each { |route|
              if !route.network_interface_id.nil?
                MU.log "Deleting Network Interface #{route.network_interface_id}"
                begin
                  MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_network_interface(network_interface_id: route.network_interface_id) if !noop
                rescue Aws::EC2::Errors::InvalidNetworkInterfaceIDNotFound
                  MU.log "Network Interface #{route.network_interface_id} has already been deleted", MU::WARN
                end
              end
              if route.gateway_id != "local"
                MU.log "Deleting #{table.route_table_id}'s route for #{route.destination_cidr_block}"
                begin
                  MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_route(
                    route_table_id: table.route_table_id,
                    destination_cidr_block: route.destination_cidr_block
                  ) if !noop
                rescue Aws::EC2::Errors::InvalidRouteNotFound
                  MU.log "Route #{table.route_table_id} has already been deleted", MU::WARN
                end
              end
            }
            can_delete = true
            table.associations.each { |assoc|
              begin
                MU::Cloud::AWS.ec2(credentials: credentials, region: region).disassociate_route_table(association_id: assoc.route_table_association_id) if !noop
              rescue Aws::EC2::Errors::InvalidAssociationIDNotFound
                MU.log "Route table association #{assoc.route_table_association_id} already removed", MU::WARN
              rescue Aws::EC2::Errors::InvalidParameterValue
                # normal and ignorable with the default route table
                can_delete = false
                next
              end
            }
            next if !can_delete
            MU.log "Deleting Route Table #{table.route_table_id}"
            begin
              MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_route_table(route_table_id: table.route_table_id) if !noop
            rescue Aws::EC2::Errors::InvalidRouteTableIDNotFound
              MU.log "Route table #{table.route_table_id} already removed", MU::WARN
            end
          }
          return nil
        end
        private_class_method :purge_routetables

        # Remove all DHCP options sets associated with the currently loaded
        # deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_dhcpopts(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion, credentials: nil)
          resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_dhcp_options(
              filters: tagfilters
          )
          sets = resp.data.dhcp_options

          return if sets.nil? or sets.size == 0

          sets.each { |optset|
            begin
              MU.log "Deleting DHCP Option Set #{optset.dhcp_options_id}"
              if !noop
                MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_dhcp_options(dhcp_options_id: optset.dhcp_options_id)
              end
            rescue Aws::EC2::Errors::DependencyViolation => e
              MU.log e.inspect, MU::ERR
#        rescue Aws::EC2::Errors::InvalidSubnetIDNotFound
#          MU.log "Subnet #{subnet.subnet_id} disappeared before I could remove it", MU::WARN
#          next
            end
          }
        end
        private_class_method :purge_dhcpopts

        def self.purge_peering_connections(noop, vpc_id, region: MU.curRegion, credentials: nil)
          my_peer_conns = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_vpc_peering_connections(
            filters: [
              {
                name: "requester-vpc-info.vpc-id",
                values: [vpc_id]
              }
            ]
          ).vpc_peering_connections
          my_peer_conns.concat(MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_vpc_peering_connections(
            filters: [
              {
                name: "accepter-vpc-info.vpc-id",
                values: [vpc_id]
              }
            ]
          ).vpc_peering_connections)

          my_peer_conns.each { |cnxn|
            [cnxn.accepter_vpc_info.vpc_id, cnxn.requester_vpc_info.vpc_id].each { |peer_vpc|
              MU::Cloud::AWS::VPC.listAllSubnetRouteTables(peer_vpc, region: region, credentials: credentials).each { |rtb_id|
                begin
                  resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_route_tables(
                    route_table_ids: [rtb_id]
                  )
                rescue Aws::EC2::Errors::InvalidRouteTableIDNotFound
                  next
                end
                resp.route_tables.each { |rtb|
                  rtb.routes.each { |route|
                    if route.vpc_peering_connection_id == cnxn.vpc_peering_connection_id
                      MU.log "Removing route #{route.destination_cidr_block} from route table #{rtb_id} in VPC #{peer_vpc}"
                      MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_route(
                          route_table_id: rtb_id,
                          destination_cidr_block: route.destination_cidr_block
                      ) if !noop
                    end
                  }
                }
              }
            }
            MU.log "Deleting VPC peering connection #{cnxn.vpc_peering_connection_id}"
            begin
              MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_vpc_peering_connection(
                vpc_peering_connection_id: cnxn.vpc_peering_connection_id
              ) if !noop
            rescue Aws::EC2::Errors::InvalidStateTransition
              MU.log "VPC peering connection #{cnxn.vpc_peering_connection_id} not in removable (state #{cnxn.status.code})", MU::WARN
            rescue Aws::EC2::Errors::OperationNotPermitted => e
              MU.log "VPC peering connection #{cnxn.vpc_peering_connection_id} refuses to delete: #{e.message}", MU::WARN
            end
          }
        end
        private_class_method :purge_peering_connections

        # Remove all VPCs associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_vpcs(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion, credentials: nil)
          resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_vpcs(
            filters: tagfilters
          )

          vpcs = resp.data.vpcs
          return if vpcs.nil? or vpcs.size == 0

          vpcs.each { |vpc|
            purge_peering_connections(noop, vpc.vpc_id, region: region, credentials: credentials)

            on_retry = Proc.new {
              MU::Cloud.resourceClass("AWS", "FirewallRule").cleanup(
                noop: noop,
                region: region,
                credentials: credentials,
                flags: { "vpc_id" => vpc.vpc_id }
              )
              purge_gateways(noop, tagfilters, region: region, credentials: credentials)
            }

            MU.retrier([Aws::EC2::Errors::DependencyViolation], ignoreme: [Aws::EC2::Errors::InvalidVpcIDNotFound], max: 20, on_retry: on_retry) {
              MU.log "Deleting VPC #{vpc.vpc_id}"
              MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_vpc(vpc_id: vpc.vpc_id) if !noop
            }

            if !MU::Cloud::AWS.isGovCloud?(region)
              mu_zone = MU::Cloud::DNSZone.find(cloud_id: "platform-mu", region: region, credentials: credentials).values.first
              if !mu_zone.nil?
                MU::Cloud.resourceClass("AWS", "DNSZone").toggleVPCAccess(id: mu_zone.id, vpc_id: vpc.vpc_id, remove: true, credentials: credentials)
              end
            end
          }
        end
        private_class_method :purge_vpcs

      end #class
    end #class
  end
end #module
