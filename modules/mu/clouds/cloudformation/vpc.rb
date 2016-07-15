# Copyright:: Copyright (c) 2016 eGlobalTech, Inc., all rights reserved
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
    class CloudFormation

      # Creation of Virtual Private Clouds and associated artifacts (routes, subnets, etc).
      class VPC < MU::Cloud::VPC

        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :cloud_id
        attr_reader :config

        attr_reader :cfm_template
        attr_reader :cfm_name

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::vpcs}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @subnets = []
          @cloud_id = cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
            loadSubnets if !@cloud_id.nil?
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name = @deploy.getResourceName(@config['name'])
          end

        end

        # Populate @cfm_template with a resource description for this VPC
        # in CloudFormation language.
        def create
          @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase(self.class.cfg_name, self, tags: @config['tags'], scrub_mu_isms: @config['scrub_mu_isms']) if @cfm_template.nil?
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "CidrBlock", @config['ip_block'])
          ["enable_dns_support", "enable_dns_hostnames"].each { |arg|
            if !@config[arg].nil?
              key = ""
              arg.split(/_/).each { |chunk| key = key + chunk.capitalize }
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], key, @config[arg])
            end
          }

          igw_name = attach_name = nil
          if @config['create_internet_gateway']
            igw_name, igw_template = MU::Cloud::CloudFormation.cloudFormationBase("igw", name: @mu_name, tags: @config['tags'], scrub_mu_isms: @config['scrub_mu_isms'])
            attach_name, attach_template = MU::Cloud::CloudFormation.cloudFormationBase("vpcgwattach", name: @mu_name, scrub_mu_isms: @config['scrub_mu_isms'])
            MU::Cloud::CloudFormation.setCloudFormationProp(attach_template[attach_name], "DependsOn", igw_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(attach_template[attach_name], "DependsOn", @cfm_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(attach_template[attach_name], "InternetGatewayId", { "Ref" => igw_name } )
            MU::Cloud::CloudFormation.setCloudFormationProp(attach_template[attach_name], "VpcId", { "Ref" => @cfm_name })
            @cfm_template.merge!(igw_template)
            @cfm_template.merge!(attach_template)
          end


          rtb_map = {}
          route_needs_nat = {}
          if !@config['route_tables'].nil?
            @config['route_tables'].each { |rtb|
              rtb_name, rtb_template = MU::Cloud::CloudFormation.cloudFormationBase("rtb", name: rtb['name']+@config['name'], tags: @config['tags'], scrub_mu_isms: @config['scrub_mu_isms'])
              rtb_map[rtb['name']] = rtb_name
              MU::Cloud::CloudFormation.setCloudFormationProp(rtb_template[rtb_name], "VpcId", { "Ref" => @cfm_name })
              MU::Cloud::CloudFormation.setCloudFormationProp(rtb_template[rtb_name], "DependsOn", @cfm_name)
              rtb['routes'].each { |route|
                route_name, route_template = MU::Cloud::CloudFormation.cloudFormationBase("route", name: rtb['name']+@config['name']+route['destination_network'], scrub_mu_isms: @config['scrub_mu_isms'])
                MU::Cloud::CloudFormation.setCloudFormationProp(route_template[route_name], "DependsOn", rtb_name)
                MU::Cloud::CloudFormation.setCloudFormationProp(route_template[route_name], "RouteTableId", { "Ref" => rtb_name } )
                MU::Cloud::CloudFormation.setCloudFormationProp(route_template[route_name], "DestinationCidrBlock", route['destination_network'])
                if !route['interface'].nil?
                  MU::Cloud::CloudFormation.setCloudFormationProp(route_template[route_name], "NetworkInterfaceId", route['interface'] )
                end
                if route['gateway'] == '#INTERNET'
                  if igw_name.nil?
                    raise MuError, "Requested an internet gateway in route table #{rtb_name}, but none is degined"
                  end
                  MU::Cloud::CloudFormation.setCloudFormationProp(route_template[route_name], "GatewayId", { "Ref" => igw_name } )
                  MU::Cloud::CloudFormation.setCloudFormationProp(rtb_template[rtb_name], "DependsOn", igw_name )
                  MU::Cloud::CloudFormation.setCloudFormationProp(route_template[route_name], "DependsOn", igw_name )
                elsif route['gateway'] == '#NAT'
                  route_needs_nat[rtb_name] = route_name
# XXX do these down in subnet world
#                  MU::Cloud::CloudFormation.setCloudFormationProp(route_template[route_name], "NatGatewayId", { "Ref" => nat_name } )
#                  MU::Cloud::CloudFormation.setCloudFormationProp(rtb_template[rtb_name], "DependsOn", nat_name )
#                  MU::Cloud::CloudFormation.setCloudFormationProp(route_template[route_name], "DependsOn", nat_name )
                elsif !route['nat_host_id'].nil?
                  MU::Cloud::CloudFormation.setCloudFormationProp(route_template[route_name], "InstanceId", route['nat_host_id'] )
                elsif !route['nat_host_name'].nil?
                  if !@dependencies.has_key?("server") or !@dependencies["server"][route['nat_host_name']] or @dependencies["server"][route['nat_host_name']].cloudobj.nil?
#                    raise MuError, "VPC #{@config['name']} is missing NAT host dependency #{route['nat_host_name']}"
                    next
                  end
                  MU::Cloud::CloudFormation.setCloudFormationProp(route_template[route_name], "InstanceId", { "Ref" => @dependencies["server"][route['nat_host_name']].cloudobj.cfm_name } )
                  MU::Cloud::CloudFormation.setCloudFormationProp(route_template[route_name], "DependsOn", @dependencies["server"][route['nat_host_name']].cloudobj.cfm_name)
                elsif !route['peer_id'].nil?
                  MU::Cloud::CloudFormation.setCloudFormationProp(route_template[route_name], "VpcPeeringConnectionId", route['peer_id'] )
                end
                @cfm_template.merge!(route_template)
              }
              
              @cfm_template.merge!(rtb_template)
            }
          end

# XXX get back to this flowlogs stuff later
#          if @config["enable_traffic_logging"]
#            @config["log_group_name"] = @mu_name unless @config["log_group_name"]
#            loggroup_name, loggroup_template = MU::Cloud::CloudFormation.cloudFormationBase("loggroup", name: @config["log_group_name"])
#          end

          nats = {} # keep track of what NATs we've stashed in what AZs so that we can set up routes appropriately for private subnets
          if !@config['subnets'].nil?
            @config['subnets'].each { |subnet_cfg|
#              subnet_name = @config['name']+"-"+subnet['name']
              subnet_cfg['mu_name'] = @deploy.getResourceName(@config['name']+"-"+subnet_cfg['name'])
              subnet_cfg['tags'] = @config['tags']
              subnet = MU::Cloud::CloudFormation::VPC::Subnet.new(self, subnet_cfg)
              @subnets << subnet

              if subnet_cfg['create_nat_gateway']
                eip_name, eip_template = MU::Cloud::CloudFormation.cloudFormationBase("eip", name: subnet_cfg['mu_name']+"NATIP", scrub_mu_isms: @config['scrub_mu_isms'])
                MU::Cloud::CloudFormation.setCloudFormationProp(eip_template[eip_name], "Domain", "vpc")

                nat_name, nat_template = MU::Cloud::CloudFormation.cloudFormationBase("nat", name: subnet_cfg['mu_name'], scrub_mu_isms: @config['scrub_mu_isms'])
                MU::Cloud::CloudFormation.setCloudFormationProp(nat_template[nat_name], "AllocationId", { "Fn::GetAtt" => [eip_name, "AllocationId"] })
                MU::Cloud::CloudFormation.setCloudFormationProp(nat_template[nat_name], "DependsOn", eip_name)
                MU::Cloud::CloudFormation.setCloudFormationProp(nat_template[nat_name], "DependsOn", attach_name) # XXX make sure config parser catches this requirement
                MU::Cloud::CloudFormation.setCloudFormationProp(nat_template[nat_name], "SubnetId", { "Ref" => subnet.cfm_name})
                @cfm_template.merge!(eip_template)
                @cfm_template.merge!(nat_template)
                nats[subnet_cfg["availability_zone"]] = nat_name
              end

              assoc_name, assoc_template = MU::Cloud::CloudFormation.cloudFormationBase("rtbassoc", name: subnet.cfm_name+subnet_cfg['route_table'], scrub_mu_isms: @config['scrub_mu_isms'])
              MU::Cloud::CloudFormation.setCloudFormationProp(assoc_template[assoc_name], "SubnetId", { "Ref" => subnet.cfm_name })
              MU::Cloud::CloudFormation.setCloudFormationProp(assoc_template[assoc_name], "RouteTableId", { "Ref" => rtb_map[subnet_cfg['route_table']] })
              MU::Cloud::CloudFormation.setCloudFormationProp(assoc_template[assoc_name], "DependsOn", rtb_map[subnet_cfg['route_table']])

              @cfm_template.merge!(assoc_template)
              @cfm_template.merge!(subnet.cfm_template)
            }

            # Go through again and fix up route tables that now should have
            # NATs tied to them.
            @config['subnets'].each { |subnet_cfg|
              my_rtb = rtb_map[subnet_cfg['route_table']]
              if route_needs_nat.has_key?(my_rtb)
                use_nat = nil
                if nats.has_key?(subnet_cfg["availability_zone"])
                  use_nat = nats[subnet_cfg["availability_zone"]]
                else
                  natnames = nats.values
                  use_nat = natnames[rand(natnames.size)]
                end
                my_route = route_needs_nat[my_rtb]

                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[my_route], "NatGatewayId", { "Ref" => use_nat } )
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[my_route], "DependsOn", use_nat)
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[my_rtb], "DependsOn", use_nat)
              end
            }
          end
          
# XXX get back to this DHCP stuff later
          if @config['dhcp']
          end
        end

        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def groom
          return create
        end

        # Return an array of MU::Cloud::CloudFormation::VPC::Subnet objects
        # describe the member subnets of this VPC.
        # @return [Array<MU::Cloud::AWS::CloudFormation::Subnet>]
        def subnets
          @subnets
        end
        # Return an array of MU::Cloud::CloudFormation::VPC::Subnet objects
        # describe the member subnets of this VPC.
        # @return [Array<MU::Cloud::AWS::CloudFormation::Subnet>]
        def listSubnets
          @subnets
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def getSubnet
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def findBastion(nat_name: nil, nat_cloud_id: nil, nat_tag_key: nil, nat_tag_value: nil, nat_ip: nil)
          # XXX should probably use findSibling, since that's the only
          # valid case.
          return nil
        end

        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def notify
          {}
        end

        protected

        # Subnets are almost a first-class resource. So let's kinda sorta treat
        # them like one. This should only be invoked on objects that already
        # exists in the cloud layer.
        class Subnet < MU::Cloud::CloudFormation::VPC

          attr_reader :cloud_id
          attr_reader :ip_block
          attr_reader :mu_name
          attr_reader :name
          attr_reader :cfm_template
          attr_reader :cfm_name
          attr_reader :name


          # @param parent [MU::Cloud::CloudFormation::VPC]: The parent VPC of this subnet.
          # @param config [Hash<String>]:
          def initialize(parent, config)
            @parent = parent
            @config = config
            @cloud_id = config['cloud_id']
            if @parent.config['scrub_mu_isms']
              @mu_name = @config['name']
            else
              @mu_name = config['mu_name']
            end
            @name = config['name']
            @deploydata = config # This is a dummy for the sake of describe()

            @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase("subnet", self, tags: @config['tags'], scrub_mu_isms: @parent.config['scrub_mu_isms'])
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "VpcId", { "Ref" => parent.cfm_name })
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", parent.cfm_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "CidrBlock", config['ip_block'])
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "MapPublicIpOnLaunch", config['map_public_ips'])
            if config['availability_zone']
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "AvailabilityZone", config['availability_zone'])
            end
          end

        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def self.find(*args)
          MU.log "find() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def self.cleanup(*args)
          MU.log "cleanup() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end

      end #class
    end #class
  end
end #module
