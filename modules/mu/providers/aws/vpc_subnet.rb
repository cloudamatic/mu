# Copyright:: Copyright (c) 2020 eGlobalTech, Inc., all rights reserved
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

        # Subnets are almost a first-class resource. So let's kinda sorta treat
        # them like one. This should only be invoked on objects that already
        # exists in the cloud layer.
        class Subnet < MU::Cloud::AWS::VPC

          attr_reader :cloud_id
          attr_reader :ip_block
          attr_reader :mu_name
          attr_reader :name
          attr_reader :az
          attr_reader :config
          attr_reader :cloud_desc

          # @param parent [MU::Cloud::AWS::VPC]: The parent VPC of this subnet.
          # @param config [Hash<String>]:
          def initialize(parent, config)
            @config = MU::Config.manxify(config)
            MU::Cloud::AWS.resourceInitHook(self, @deploy)
            @parent = parent
            @cloud_id = config['cloud_id']
            @credentials ||= config['credentials']
            @mu_name = config['mu_name']
            @name = config['name']
            @deploydata = config # This is a dummy for the sake of describe()
            resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_subnets(subnet_ids: [@cloud_id]).subnets.first
            @az = resp.availability_zone
            @ip_block = resp.cidr_block
            @cloud_desc = resp # XXX this really isn't the cloud implementation's business

          end

          # Return the cloud identifier for the default route of this subnet.
          # @return [String,nil]
          def defaultRoute
            resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_route_tables(
                filters: [{name: "association.subnet-id", values: [@cloud_id]}]
            )
            if resp.route_tables.size == 0 # use default route table for the VPC
              resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_route_tables(
                 filters: [{name: "vpc-id", values: [@parent.cloud_id]}]
              )
            end
            resp.route_tables.each { |route_table|
              route_table.routes.each { |route|
                if route.destination_cidr_block =="0.0.0.0/0" and route.state != "blackhole"
                  return route.instance_id if !route.instance_id.nil?
                  return route.gateway_id if !route.gateway_id.nil?
                  return route.vpc_peering_connection_id if !route.vpc_peering_connection_id.nil?
                  return route.network_interface_id if !route.network_interface_id.nil?
                end
              }
            }
            return nil
          end

          # Is this subnet privately-routable only, or public?
          # @return [Boolean]
          def private?
            return false if @cloud_id.nil?
            resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_route_tables(
                filters: [{name: "association.subnet-id", values: [@cloud_id]}]
            )
            if resp.route_tables.size == 0 # use default route table for the VPC
              resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_route_tables(
                 filters: [{name: "vpc-id", values: [@parent.cloud_id]}]
              )
            end
            resp.route_tables.each { |route_table|
              route_table.routes.each { |route|
                return false if !route.gateway_id.nil? and route.gateway_id != "local" # you can have an IgW and route it to a subset of IPs instead of 0.0.0.0/0
                if route.destination_cidr_block == "0.0.0.0/0"
                  return true if !route.instance_id.nil?
                  return true if route.nat_gateway_id
                end
              }
            }
            return true
          end
        end # VPC::Subnet class

        private

        def create_subnets
          return [] if @config['subnets'].nil? or @config['subnets'].empty?
          nat_gateways = []

          @eip_allocation_ids ||= []

          subnetthreads = Array.new

          azs = MU::Cloud::AWS.listAZs(region: @region, credentials: @credentials)
          @config['subnets'].each { |subnet|
            subnet_name = @config['name']+"-"+subnet['name']
            az = subnet['availability_zone'] ? subnet['availability_zone'] : azs.op
            MU.log "Creating Subnet #{subnet_name} (#{subnet['ip_block']}) in #{az}", details: subnet

            subnetthreads << Thread.new {
              resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_subnet(
                vpc_id: @cloud_id,
                cidr_block: subnet['ip_block'],
                availability_zone: az
              ).subnet
              subnet_id = subnet['subnet_id'] = resp.subnet_id

              tag_me(subnet_id, @mu_name+"-"+subnet['name'])

              loop_if = Proc.new {
                resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_subnets(subnet_ids: [subnet_id]).subnets.first
                (!resp or resp.state != "available")
              }

              MU.retrier([Aws::EC2::Errors::InvalidSubnetIDNotFound, NoMethodError], wait: 5, loop_if: loop_if) { |retries, _wait|
                MU.log "Waiting for Subnet #{subnet_name} (#{subnet_id}) to become available", MU::NOTICE if retries > 0 and (retries % 3) == 0
              }

              if !subnet['route_table'].nil?
                routes = {}
                @config['route_tables'].each { |tbl|
                  routes[tbl['name']] = tbl
                }
                if routes[subnet['route_table']].nil?
                  raise "Subnet #{subnet_name} references nonexistent route #{subnet['route_table']}"
                end
                MU.log "Associating Route Table '#{subnet['route_table']}' (#{routes[subnet['route_table']]['route_table_id']}) with #{subnet_name}"
                MU.retrier([Aws::EC2::Errors::InvalidRouteTableIDNotFound], wait: 10, max: 10) {
                  MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).associate_route_table(
                    route_table_id: routes[subnet['route_table']]['route_table_id'],
                    subnet_id: subnet_id
                  )
                }
              end

              if subnet.has_key?("map_public_ips")
                MU.retrier([Aws::EC2::Errors::InvalidSubnetIDNotFound], wait: 10, max: 10) {
                  resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).modify_subnet_attribute(
                    subnet_id: subnet_id,
                    map_public_ip_on_launch: {
                      value: subnet['map_public_ips'],
                    }
                  )
                }
              end

              if subnet['is_public'] and subnet['create_nat_gateway']
                nat_gateways << create_nat_gateway(subnet)
              end

              if subnet["enable_traffic_logging"]
                loggroup = @deploy.findLitterMate(name: @config['name']+"loggroup", type: "logs")
                logrole = @deploy.findLitterMate(name: @config['name']+"logrole", type: "roles")
                MU.log "Enabling traffic logging on Subnet #{subnet_name} in VPC #{@mu_name} to log group #{loggroup.mu_name}"
                MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_flow_logs(
                  resource_ids: [subnet_id],
                  resource_type: "Subnet",
                  traffic_type: subnet["traffic_type_to_log"],
                  log_group_name: loggroup.mu_name,
                  deliver_logs_permission_arn: logrole.cloudobj.arn
                )
              end
            }
          }

          subnetthreads.each { |t|
            t.join
          }

          nat_gateways
        end

        def allocate_eip_for_nat
          MU::MommaCat.lock("nat-gateway-eipalloc")

#          eips = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_addresses(
#            filters: [
#              {
#                name: "domain",
#                values: ["vpc"]
#              }
#            ]
#          ).addresses

#          allocation_id = nil
#          eips.each { |eip|
#            next if !eip.association_id.nil? and !eip.association_id.empty?
#            if (eip.private_ip_address.nil? || eip.private_ip_address.empty?) and MU::MommaCat.lock(eip.allocation_id, true, true)
#              if !@eip_allocation_ids.include?(eip.allocation_id)
#                allocation_id = eip.allocation_id
#                break
#              end
#            end
#          }

#          if allocation_id.nil?
            allocation_id = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).allocate_address(domain: "vpc").allocation_id
            tag_me(allocation_id)
#            MU::MommaCat.lock(allocation_id, false, true)
#          end

          @eip_allocation_ids << allocation_id

          MU::MommaCat.unlock("nat-gateway-eipalloc")

          allocation_id
        end

        def create_nat_gateway(subnet)
          allocation_id = allocate_eip_for_nat

          nat_gateway_id = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_nat_gateway(
            subnet_id: subnet['subnet_id'],
            allocation_id: allocation_id,
          ).nat_gateway.nat_gateway_id

          ensure_unlock = Proc.new { MU::MommaCat.unlock(allocation_id, true) }
          resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_nat_gateways(nat_gateway_ids: [nat_gateway_id]).nat_gateways.first
          loop_if = Proc.new {
            resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_nat_gateways(nat_gateway_ids: [nat_gateway_id]).nat_gateways.first
            resp.class != Aws::EC2::Types::NatGateway or resp.state == "pending"
          }

          MU.retrier([Aws::EmptyStructure, NoMethodError], wait: 5, max: 30, always: ensure_unlock, loop_if: loop_if) { |retries, _wait|
            MU.log "Waiting for nat gateway #{nat_gateway_id} to become available (EIP allocation: #{allocation_id})" if retries % 5 == 0
          }

          raise MuError, "NAT Gateway failed #{nat_gateway_id}: #{resp}" if resp.state == "failed"

          tag_me(nat_gateway_id)

          {'id' => nat_gateway_id, 'availability_zone' => subnet['availability_zone']}
        end

        # Remove all subnets associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_subnets(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion, credentials: nil)
          resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_subnets(
            filters: tagfilters
          )
          subnets = resp.data.subnets

          return if subnets.nil? or subnets.size == 0

          subnets.each { |subnet|
            on_retry = Proc.new {
              MU::Cloud::AWS::VPC.purge_interfaces(noop, [{name: "subnet-id", values: [subnet.subnet_id]}], region: region, credentials: credentials)
            }

            MU.log "Deleting Subnet #{subnet.subnet_id}"
            MU.retrier([Aws::EC2::Errors::DependencyViolation], ignoreme: [Aws::EC2::Errors::InvalidSubnetIDNotFound], max: 20, on_retry: on_retry) { |_retries, wait|
              begin
                if subnet.state != "available"
                  MU.log "Waiting for #{subnet.subnet_id} to be in a removable state...", MU::NOTICE
                  sleep wait
                else
                  MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_subnet(subnet_id: subnet.subnet_id) if !noop
                end
              end while subnet.state != "available"
            }
          }
        end
        private_class_method :purge_subnets

      end # VPC class

    end #class
  end
end #module
