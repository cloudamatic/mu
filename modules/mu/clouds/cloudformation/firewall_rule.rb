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
      # A firewall ruleset as configured in {MU::Config::BasketofKittens::firewall_rules}
      class FirewallRule < MU::Cloud::FirewallRule

        @deploy = nil
        @config = nil
        @admin_sgs = Hash.new
        @admin_sg_semaphore = Mutex.new

        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id
        attr_reader :cfm_name
        attr_reader :cfm_template

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::firewall_rules}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          else
            if !@vpc.nil?
              @mu_name = @deploy.getResourceName(@config['name'], need_unique_string: true)
            else
              @mu_name = @deploy.getResourceName(@config['name'])
            end
          end

        end

        # Populate @cfm_template with a resource description for this security
        # group in CloudFormation language.
        def create
          @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase(self.class.cfg_name, self, tags: @config['tags']) if @cfm_template.nil?
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "GroupDescription", @mu_name)

          if !@config['vpc'].nil? and !@config['vpc']['vpc_id'].nil?
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "VpcId", @config['vpc']['vpc_id'])
          elsif @dependencies.has_key?("vpc") and !@config["vpc"]["vpc_name"].nil? and @dependencies["vpc"].has_key?(@config["vpc"]["vpc_name"])
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", @dependencies["vpc"][@config["vpc"]["vpc_name"]].cloudobj.cfm_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "VpcId", { "Ref" => @dependencies["vpc"][@config["vpc"]["vpc_name"]].cloudobj.cfm_name })
          end
          egress = false
          egress = true if !@cfm_template[@cfm_name]["VpcId"].nil?
          # XXX the egress logic here is a crude hack, this really needs to be
          # done at config level
          setRules(
            @config['rules'],
            add_to_self: @config['self_referencing'],
            ingress: true,
            egress: egress
          )
#          pp @cfm_template
        end

        # Called by {MU::Deploy#createResources}
        def groom
          create
        end

        # Log metadata about this ruleset to the currently running deployment
        def notify
          {}
        end

        # Insert a rule into an existing security group.
        #
        # @param hosts [Array<String>]: An array of CIDR network addresses to which this rule will apply.
        # @param proto [String]: One of "tcp," "udp," or "icmp"
        # @param port [Integer]: A port number. Only valid with udp or tcp.
        # @param egress [Boolean]: Whether this is an egress ruleset, instead of ingress.
        # @param port_range [String]: A port range descriptor (e.g. 0-65535). Only valid with udp or tcp.
        # @return [void]
        def addRule(hosts,
                    proto: proto = "tcp",
                    port: port = nil,
                    egress: egress = false,
                    port_range: port_range = "0-65535"
        )
          rule = Hash.new
          rule["proto"] = proto
          if hosts.is_a?(String)
            rule["hosts"] = [hosts]
          else
            rule["hosts"] = hosts
          end
          if port != nil
            port = port.to_s if !port.is_a?(String)
            rule["port"] = port
          else
            rule["port_range"] = port_range
          end
          ec2_rule = convertToEc2([rule])

          begin
            if egress
              MU::Cloud::AWS.ec2(@config['region']).authorize_security_group_egress(
                  group_id: @cloud_id,
                  ip_permissions: ec2_rule
              )
            else
              MU::Cloud::AWS.ec2(@config['region']).authorize_security_group_ingress(
                  group_id: @cloud_id,
                  ip_permissions: ec2_rule
              )
            end
          rescue Aws::EC2::Errors::InvalidPermissionDuplicate => e
            MU.log "Attempt to add duplicate rule to #{@cloud_id}", MU::DEBUG, details: ec2_rule
          end
        end

        private

        #########################################################################
        # Manufacture an EC2 security group. The second parameter, rules, is an
        # "ingress_rules" structure parsed and validated by MU::Config.
        #########################################################################
        def setRules(rules, add_to_self: add_to_self = false, ingress: ingress = true, egress: egress = false)
          return if rules.nil? or rules.size == 0

          if add_to_self
            rules.each { |rule|
              if rule['sgs'].nil?
                new_rule = rule.clone
                new_rule.delete('hosts')
                rule['sgs'] = Array.new if rule['sgs'].nil?
                rule['sgs'] << { "Ref" => @cfm_name }
              end
            }
          end

          ec2_rules = convertToEc2(rules)

          # Creating an empty security group is ok, so don't freak out if we get
          # a null rule list.
          if !ec2_rules.nil?
            ec2_rules.each { |rule|
              next if rule.nil? or rule[:ip_ranges].nil? # XXX whaaat
              rule[:ip_ranges].each { |cidr|
                MU::Cloud::CloudFormation.setCloudFormationProp(
                  @cfm_template[@cfm_name],
                  "SecurityGroupIngress",
                  {
                    "IpProtocol" => rule[:ip_protocol],
                    "FromPort" => rule[:from_port],
                    "ToPort" => rule[:to_port],
                    "CidrIp" => cidr[:cidr_ip]
                  }
                )
              }
            }
          end

        end

        #########################################################################
        # Convert our config languages description of firewall rules into Amazon's.
        # This rule structure is as defined in MU::Config.
        #########################################################################
        def convertToEc2(rules)
          ec2_rules = []
          if rules != nil
            rules.each { |rule|
              ec2_rule = Hash.new
              rule['proto'] = "tcp" if rule['proto'].nil? or rule['proto'].empty?
              ec2_rule[:ip_protocol] = rule['proto']

              p_start = nil
              p_end = nil
              if rule['port_range']
                p_start, p_end = rule['port_range'].split(/\s*-\s*/)
              elsif rule['port']
                p_start = rule['port']
                p_end = rule['port']
              elsif rule['proto'] != "icmp"
                raise MuError, "Can't create a TCP or UDP security group rule without specifying ports: #{rule}"
              end
              if rule['proto'] != "icmp"
                if p_start.nil? or p_end.nil?
                  raise MuError, "Got nil ports out of rule #{rule}"
                end
                ec2_rule[:from_port] = p_start.to_i
                ec2_rule[:to_port] = p_end.to_i
              else
                ec2_rule[:from_port] = -1
                ec2_rule[:to_port] = -1
              end

              if (!defined? rule['hosts'] or !rule['hosts'].is_a?(Array)) and
                  (!defined? rule['sgs'] or !rule['sgs'].is_a?(Array)) and
                  (!defined? rule['lbs'] or !rule['lbs'].is_a?(Array))
                raise MuError, "One of 'hosts', 'sgs', or 'lbs' in rules provided to createEc2SG must be an array."
              end
              ec2_rule[:ip_ranges] = []
              ec2_rule[:user_id_group_pairs] = []

              if !rule['hosts'].nil?
                rule['hosts'].each { |cidr|
                  next if cidr.nil? # XXX where is that coming from?
                  cidr = cidr + "/32" if cidr.match(/^\d+\.\d+\.\d+\.\d+$/)
                  ec2_rule[:ip_ranges] << {cidr_ip: cidr}
                }
              end

              if !rule['lbs'].nil?
# XXX This is a dopey place for this, dependencies() should be doing our legwork
                rule['lbs'].each { |lb_name|
                  if @dependencies.has_key?("loadbalancer") and @dependencies["loadbalancer"].has_key?(lb_name)
#                    MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", @dependencies["loadbalancer"][lb_name].cloudobj.cfm_name)
                  end
                }
              end

              if !rule['sgs'].nil?
                rule['sgs'].each { |sg_name|
# XXX This is a dopey place for this, dependencies() should be doing our legwork
                  if @dependencies.has_key?("firewall_rule") and @dependencies["firewall_rule"].has_key?(sg_name)
#                    MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", @dependencies["firewall_rule"][sg_name].cloudobj.cfm_name)
                  end
                }
              end

              if !ec2_rule[:user_id_group_pairs].nil? and
                  ec2_rule[:user_id_group_pairs].size > 0 and
                  !ec2_rule[:ip_ranges].nil? and
                  ec2_rule[:ip_ranges].size > 0
                MU.log "Cannot specify ip_ranges and user_id_group_pairs", MU::ERR
                raise MuError, "Cannot specify ip_ranges and user_id_group_pairs"
              end

              ec2_rule.delete(:ip_ranges) if ec2_rule[:ip_ranges].size == 0
              ec2_rule.delete(:user_id_group_pairs) if ec2_rule[:user_id_group_pairs].size == 0

              if !ec2_rule[:user_id_group_pairs].nil? and
                  ec2_rule[:user_id_group_pairs].size > 0
                ec2_rule.delete(:ip_ranges)
              elsif !ec2_rule[:ip_ranges].nil? and
                  ec2_rule[:ip_ranges].size > 0
                ec2_rule.delete(:user_id_group_pairs)
              end
              ec2_rules << ec2_rule
            }
          end
          return ec2_rules
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
