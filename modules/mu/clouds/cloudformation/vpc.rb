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
          else
            @mu_name = @deploy.getResourceName(@config['name'])
            @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase(self.class.cfg_name, self)
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "CidrBlock", @config['ip_block'])
          end

        end

        # Populate @cfm_template with a resource description for this VPC
        # in CloudFormation language.
        def create
          ["enable_dns_support", "enable_dns_hostnames"].each { |arg|
            if !@config[arg].nil?
              key = ""
              arg.split(/_/).each { |chunk| key = key + chunk.capitalize }
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], key, @config[arg])
            end
          }

          igw_name = nil
          if @config['create_internet_gateway']
            igw_name, igw_template = MU::Cloud::CloudFormation.cloudFormationBase("igw", name: @mu_name)
            attach_name, attach_template = MU::Cloud::CloudFormation.cloudFormationBase("vpcgwattach", name: @mu_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(attach_template[attach_name], "DependsOn", igw_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(attach_template[attach_name], "DependsOn", @cfm_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(attach_template[attach_name], "InternetGatewayId", { "Ref" => igw_name } )
            MU::Cloud::CloudFormation.setCloudFormationProp(attach_template[attach_name], "VpcId", { "Ref" => @cfm_name })
            @cfm_template.merge!(igw_template)
            @cfm_template.merge!(attach_template)
          end

          rtb_map = {}
          if !@config['route_tables'].nil?
            @config['route_tables'].each { |rtb|
              rtb_name, rtb_template = MU::Cloud::CloudFormation.cloudFormationBase("rtb", name: rtb['name']+@config['name'])
              rtb_map[rtb['name']] = rtb_name
              MU::Cloud::CloudFormation.setCloudFormationProp(rtb_template[rtb_name], "VpcId", { "Ref" => @cfm_name })
              MU::Cloud::CloudFormation.setCloudFormationProp(rtb_template[rtb_name], "DependsOn", @cfm_name)
              rtb['routes'].each { |route|
                route_name, route_template = MU::Cloud::CloudFormation.cloudFormationBase("route", name: rtb['name']+@config['name']+route['destination_network'])
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

          if !@config['subnets'].nil?
            @config['subnets'].each { |subnet_cfg|
#              subnet_name = @config['name']+"-"+subnet['name']
              subnet_cfg['mu_name'] = @deploy.getResourceName(@config['name']+"-"+subnet_cfg['name'])

              subnet = MU::Cloud::CloudFormation::VPC::Subnet.new(self, subnet_cfg)
              @subnets << subnet
              assoc_name, assoc_template = MU::Cloud::CloudFormation.cloudFormationBase("rtbassoc", name: subnet.cfm_name+subnet_cfg['route_table'])
              MU::Cloud::CloudFormation.setCloudFormationProp(assoc_template[assoc_name], "SubnetId", { "Ref" => subnet.cfm_name })
              MU::Cloud::CloudFormation.setCloudFormationProp(assoc_template[assoc_name], "RouteTableId", { "Ref" => rtb_map[subnet_cfg['route_table']] })
              MU::Cloud::CloudFormation.setCloudFormationProp(assoc_template[assoc_name], "DependsOn", rtb_map[subnet_cfg['route_table']])

              @cfm_template.merge!(assoc_template)
              @cfm_template.merge!(subnet.cfm_template)
            }
          end
          
# XXX get back to this DHCP stuff later
          if @config['dhcp']
          end
        end

        def groom
          return create
        end

        def subnets
          @subnets
        end
        def listSubnets
          @subnets
        end
        def getSubnet
        end
        def findBastion(nat_name: nil, nat_cloud_id: nil, nat_tag_key: nil, nat_tag_value: nil, nat_ip: nil)
          # XXX should probably use findSibling, since that's the only
          # valid case.
          return nil
        end

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
            @mu_name = config['mu_name']
            @name = config['name']
            @deploydata = config # This is a dummy for the sake of describe()

            @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase("subnet", self)
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "VpcId", { "Ref" => parent.cfm_name })
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", parent.cfm_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "CidrBlock", config['ip_block'])
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "MapPublicIpOnLaunch", config['map_public_ips'])
            if config['availability_zone']
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "AvailabilityZone", config['availability_zone'])
            end
          end

        end

      end #class
    end #class
  end
end #module
