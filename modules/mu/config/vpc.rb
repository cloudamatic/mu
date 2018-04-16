# Copyright:: Copyright (c) 2018 eGlobalTech, Inc., all rights reserved
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
  class Config
    class VPC

      def self.schema
        {
          "type" => "object",
          "required" => ["name"],
          "additionalProperties" => false,
          "description" => "Create Virtual Private Clouds with custom public or private subnets.",
          "properties" => {
            "name" => {"type" => "string"},
            "cloud" => MU::Config.cloud_primitive,
            "ip_block" => {
              "type" => "string",
              "pattern" => MU::Config::CIDR_PATTERN,
              "description" => MU::Config::CIDR_DESCRIPTION,
              "default" => "10.0.0.0/16"
            },
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => {
                "type" => "boolean",
                "description" => "Tag the resource with our optional tags (MU-HANDLE, MU-MASTER-NAME, MU-OWNER). Defaults to true",
                "default" => true
            },
            "create_standard_subnets" => {
              "type" => "boolean",
              "description" => "If the 'subnets' parameter to this VPC is not specified, we will instead create one set of public subnets and one set of private, with a public/private pair in each Availability Zone in the target region.",
              "default" => true
            },
            "availability_zones" => {
                "type" => "array",
                "items" => {
                    "description" => "When the 'create_standard_subnets' flag is set, use this to target a specific set of availability zones across which to spread those subnets. Will attempt to guess based on the target region, if not specified.",
                    "type" => "object",
                    "required" => ["zone"],
                    "properties" => {
                        "zone" => {
                          "type" => "string"
                        }
                    }
                }
            },
            "create_internet_gateway" => {
                "type" => "boolean",
                "default" => true
            },
            "create_nat_gateway" => {
                "type" => "boolean",
                "description" => "If set to 'true' will create a NAT gateway to enable traffic in private subnets to be routed to the internet.",
                "default" => false
            },
            "enable_dns_support" => {
                "type" => "boolean",
                "default" => true
            },
            "endpoint_policy" => {
                "type" => "array",
                "items" => {
                    "description" => "Amazon-compatible endpoint policy that controls access to the endpoint by other resources in the VPC. If not provided Amazon will create a default policy that provides full access.",
                    "type" => "object"
                }
            },
            "endpoint" => {
                "type" => "string",
                "description" => "An Amazon service specific endpoint that resources within a VPC can route to without going through a NAT or an internet gateway. Currently only S3 is supported. an example S3 endpoint in the us-east-1 region: com.amazonaws.us-east-1.s3."
            },
            "enable_dns_hostnames" => {
                "type" => "boolean",
                "default" => true
            },
            "nat_gateway_multi_az" => {
              "type" => "boolean",
              "description" => "If set to 'true' will create a separate NAT gateway in each availability zone and configure subnet route tables appropriately",
              "default" => false
            },
            "dependencies" => MU::Config.dependencies_primitive,
            "auto_accept_peers" => {
                "type" => "boolean",
                "description" => "Peering connections requested to this VPC by other deployments on the same Mu master will be automatically accepted.",
                "default" => true
            },
            "peers" => {
                "type" => "array",
                "description" => "One or more other VPCs with which to attempt to create a peering connection.",
                "items" => {
                    "type" => "object",
                    "required" => ["vpc"],
                    "description" => "One or more other VPCs with which to attempt to create a peering connection.",
                    "properties" => {
                        "account" => {
                            "type" => "string",
                            "description" => "The AWS account which owns the target VPC."
                        },
                        "vpc" => reference(MANY_SUBNETS, NO_NAT_OPTS, "all")
                        #             "route_tables" => {
                        #               "type" => "array",
                        #               "items" => {
                        #                 "type" => "string",
                        #                 "description" => "The name of a route to which to add a route for this peering connection. If none are specified, all available route tables will have approprite routes added."
                        #               }
                        #             }
                    }
                }
            },
            "route_tables" => {
                "type" => "array",
                "items" => {
                    "type" => "object",
                    "required" => ["name", "routes"],
                    "description" => "A table of route entries, typically for use inside a VPC.",
                    "properties" => {
                        "name" => {"type" => "string"},
                        "routes" => {
                            "type" => "array",
                            "items" => routeschema
                        }
                    }
                }
            },
            "subnets" => {
                "type" => "array",
                "items" => {
                    "type" => "object",
                    "required" => ["name", "ip_block"],
                    "description" => "A list of subnets",
                    "properties" => {
                        "name" => {"type" => "string"},
                        "ip_block" => MU::Config::CIDR_PRIMITIVE,
                        "availability_zone" => {"type" => "string"},
                        "route_table" => {"type" => "string"},
                        "map_public_ips" => {
                            "type" => "boolean",
                            "description" => "If the cloud provider's instances should automatically be assigned publicly routable addresses.",
                            "default" => false
                        }
                    }
                }
            },
            "dhcp" => {
                "type" => "object",
                "description" => "Alternate DHCP behavior for nodes in this VPC",
                "additionalProperties" => false,
                "properties" => {
                    "dns_servers" => {
                        "type" => "array",
                        "minItems" => 1,
                        "maxItems" => 4,
                        "items" => {
                            "type" => "string",
                            "description" => "The IP address of up to four DNS servers",
                            "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$"
                        }
                    },
                    "ntp_servers" => {
                        "type" => "array",
                        "minItems" => 1,
                        "maxItems" => 4,
                        "items" => {
                            "type" => "string",
                            "description" => "The IP address of up to four NTP servers",
                            "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$"
                        }
                    },
                    "netbios_servers" => {
                        "type" => "array",
                        "minItems" => 1,
                        "maxItems" => 4,
                        "items" => {
                            "type" => "string",
                            "description" => "The IP address of up to four NetBIOS servers",
                            "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$"
                        }
                    },
                    "netbios_type" => {
                        "type" => "integer",
                        "enum" => [1, 2, 4, 8],
                        "default" => 2
                    },
                    "domains" => {
                        "type" => "array",
                        "minItems" => 1,
                        "items" => {
                            "type" => "string",
                            "description" => "If you're using AmazonProvidedDNS in us-east-1, specify ec2.internal. If you're using AmazonProvidedDNS in another region, specify region.compute.internal (for example, ap-northeast-1.compute.internal). Otherwise, specify a domain name (for example, MyCompany.com)."
                        }
                    }
                }
            }
          }
        }
      end

      NO_SUBNETS = 0.freeze
      ONE_SUBNET = 1.freeze
      MANY_SUBNETS = 2.freeze
      NAT_OPTS = true.freeze
      NO_NAT_OPTS = false.freeze

      # There's a small amount of variation in the way various resources need to
      # refer to VPCs, so let's wrap the schema in a method that'll handle the
      # wiggling.
      # @param subnets [Integer]:
      # @param nat_opts [Boolean]:
      # @param subnet_pref [String]:
      # @return [Hash]
      def self.reference(subnets = MANY_SUBNETS, nat_opts = NAT_OPTS, subnet_pref = nil)
        vpc_ref_schema = {
          "type" => "object",
          "description" => "Deploy, attach, allow access from, or peer this resource with a VPC of VPCs.",
          "minProperties" => 1,
          "additionalProperties" => false,
          "properties" => {
            "vpc_id" => {
              "type" => "string",
              "description" => "Discover this VPC by looking for this cloud provider identifier."
            },
            "vpc_name" => {
              "type" => "string",
              "description" => "Discover this VPC by Mu-internal name; typically the shorthand 'name' field of a VPC declared elsewhere in the deploy, or in another deploy that's being referenced with 'deploy_id'."
            },
            "region" => MU::Config.region_primitive,
            "cloud" => MU::Config.cloud_primitive,
            "tag" => {
              "type" => "string",
              "description" => "Discover this VPC by a cloud provider tag (key=value); note that this tag must not match more than one resource.",
              "pattern" => "^[^=]+=.+"
            },
            "deploy_id" => {
              "type" => "string",
              "description" => "Search for this VPC in an existing Mu deploy; specify a Mu deploy id (e.g. DEMO-DEV-2014111400-NG)."
            }
          }
        }

        if nat_opts
          vpc_ref_schema["properties"].merge!(
            {
              "nat_host_name" => {
                "type" => "string",
                "description" => "The Mu-internal name of a NAT host to use; Typically the shorthand 'name' field of a Server declared elsewhere in the deploy, or in another deploy that's being referenced with 'deploy_id'."
              },
              "nat_host_id" => {
                "type" => "string",
                "description" => "Discover a Server to use as a NAT by looking for this cloud provider identifier."
              },
              "nat_host_ip" => {
                "type" => "string",
                "description" => "Discover a Server to use as a NAT by looking for an associated IP.",
                "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$"
              },
              "nat_ssh_user" => {
                "type" => "string",
                "default" => "root",
              },
              "nat_ssh_key" => {
                "type" => "string",
                "description" => "An alternate SSH private key for access to the NAT. We'll expect to find this in ~/.ssh along with the regular keys.",
              },
              "nat_host_tag" => {
                "type" => "string",
                "description" => "Discover a Server to use as a NAT by looking for a cloud provider tag (key=value); Note that this tag must not match more than one server.",
                "pattern" => "^[^=]+=.+"
              }
            }
          )
        end

        if subnets > 0
          vpc_ref_schema["properties"]["subnet_pref"] = {
            "type" => "string",
            "default" => subnet_pref,
            "description" => "When auto-discovering VPC resources, this specifies target subnets for this resource. Special keywords: public, private, any, all, all_public, all_private, all. Using the name of a route table defined elsewhere in this BoK will behave like 'all_<routetablename>.'",
          }

#        if subnets == ONE_SUBNET
#          vpc_ref_schema["properties"]["subnet_pref"]["enum"] = ["public", "private", "any"]
#        elsif subnets == MANY_SUBNETS
#          vpc_ref_schema["properties"]["subnet_pref"]["enum"] = ["public", "private", "any", "all", "all_public", "all_private"]
#        else
#          vpc_ref_schema["properties"]["subnet_pref"]["enum"] = ["public", "private", "any", "all_public", "all_private", "all"]
#        end
        end

        if subnets == ONE_SUBNET or subnets == (ONE_SUBNET+MANY_SUBNETS)
          vpc_ref_schema["properties"]["subnet_name"] = {"type" => "string"}
          vpc_ref_schema["properties"]["subnet_id"] = {"type" => "string"}
        end
        if subnets == MANY_SUBNETS or subnets == (ONE_SUBNET+MANY_SUBNETS)
          vpc_ref_schema["properties"]["subnets"] = {
            "type" => "array",
            "items" => {
              "type" => "object",
              "description" => "The subnets to which to attach this resource. Will default to all subnets in this VPC if not specified.",
              "additionalProperties" => false,
              "properties" => {
                "subnet_name" => {"type" => "string"},
                "subnet_id" => {"type" => "string"},
                "tag" => {
                  "type" => "string",
                  "description" => "Identify this subnet by a tag (key=value). Note that this tag must not match more than one resource.",
                  "pattern" => "^[^=]+=.+"
                }
              }
            }
          }
          if subnets == (ONE_SUBNET+MANY_SUBNETS)
            vpc_ref_schema["properties"]["subnets"]["items"]["description"] = "Extra subnets to which to attach this {MU::Cloud::AWS::Server}. Extra network interfaces will be created to accomodate these attachments."
          end
        end

        return vpc_ref_schema
      end

      def self.routeschema
        {
          "type" => "object",
          "description" => "Define a network route, typically for use inside a VPC.",
          "properties" => {
              "destination_network" => {
                "type" => "string",
                "pattern" => MU::Config::CIDR_PATTERN,
                "description" => MU::Config::CIDR_DESCRIPTION,
                "default" => "0.0.0.0/0"
              },
              "peer_id" => {
                  "type" => "string",
                  "description" => "The ID of a VPC peering connection to use as a gateway"
              },
              "gateway" => {
                  "type" => "string",
                  "description" => "The ID of a VPN, NAT, or Internet gateway attached to your VPC. #INTERNET will refer to this VPC's default internet gateway, if one exists. #NAT will refer to a this VPC's NAT gateway, and will implicitly create one if none exists. #DENY will ensure that the subnets associated with this route do *not* have a route outside of the VPC's local address space (primarily for Google Cloud, where we must explicitly disable egress to the internet)."
              },
              "nat_host_id" => {
                  "type" => "string",
                  "description" => "The instance id of a NAT host in this VPN."
              },
              "nat_host_name" => {
                  "type" => "string",
                  "description" => "The MU resource name or Name tag of a NAT host in this VPN."
              },
              "interface" => {
                  "type" => "string",
                  "description" => "A network interface over which to route."
              }
          }
        }
      end

      def self.validate(vpc, configurator)
        ok = true

        # Look for a common YAML screwup in route table land
        if vpc['route_tables']
          vpc['route_tables'].each { |rtb|
            next if !rtb['routes']
            rtb['routes'].each { |r|
              if r.has_key?("gateway") and (!r["gateway"] or r["gateway"].to_s.empty?)
                MU.log "Route gateway in VPC #{vpc['name']} cannot be nil- did you forget to puts quotes around a #INTERNET, #NAT, or #DENY?", MU::ERR, details: rtb
                ok = false
              end
            }
          }
        end

        ok
      end

      # If the passed-in VPC configuration declares any peer VPCs, run it
      # through MU::Config::VPC.processReference. This is separate from our
      # initial validation, because we want all sibling VPCs to have had
      # MU::Config#insertKitten called on them before we do this.
      # @param vpc [Hash]: The config chunk for this VPC
      # @return [Hash]: The modified config chunk containing resolved peers
      def self.resolvePeers(vpc, configurator)
        ok = true
        if !vpc["peers"].nil?
          vpc["peers"].each { |peer|
            peer["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("VPC")
            # If we're peering with a VPC in this deploy, set it as a dependency
            if !peer['vpc']["vpc_name"].nil? and
               configurator.haveLitterMate?(peer['vpc']["vpc_name"], "vpcs") and
               peer["vpc"]['deploy_id'].nil? and peer["vpc"]['vpc_id'].nil?
              peer['vpc']['region'] = config['region'] if peer['vpc']['region'].nil? # XXX this is AWS-specific
              peer['vpc']['cloud'] = vpc['cloud'] if peer['vpc']['cloud'].nil?
              vpc["dependencies"] << {
                "type" => "vpc",
                "name" => peer['vpc']["vpc_name"]
              }
              # If we're using a VPC from somewhere else, make sure the flippin'
              # thing exists, and also fetch its id now so later search routines
              # don't have to work so hard.
            else
              peer['vpc']['region'] = config['region'] if peer['vpc']['region'].nil? # XXX this is AWS-specific
              peer['vpc']['cloud'] = vpc['cloud'] if peer['vpc']['cloud'].nil?
              if !peer['account'].nil? and peer['account'] != MU.account_number
                if peer['vpc']["vpc_id"].nil?
                  MU.log "VPC peering connections to non-local accounts must specify the vpc_id of the peer.", MU::ERR
                  ok = false
                end
              elsif !processReference(peer['vpc'], "vpcs", "vpc '#{vpc['name']}'", self, dflt_region: peer["vpc"]['region'])
                ok = false
              end
            end
          }
        end
        ok
      end

      # Pick apart an external VPC reference, validate it, and resolve it and its
      # various subnets and NAT hosts to live resources.
      # @param vpc_block [Hash]:
      # @param parent_type [String]:
      # @param parent_name [String]:
      # @param configurator [MU::Config]:
      # @param is_sibling [Boolean]:
      # @param sibling_vpcs [Array]:
      # @param dflt_region [String]:
      def self.processReference(vpc_block, parent_type, parent_name, configurator, is_sibling: false, sibling_vpcs: [], dflt_region: MU.curRegion)
        puts vpc_block.ancestors if !vpc_block.is_a?(Hash)
        if !vpc_block.is_a?(Hash) and vpc_block.kind_of?(MU::Cloud::VPC)
          return true
        end
        ok = true

        if vpc_block['region'].nil? and dflt_region and !dflt_region.empty?
          vpc_block['region'] = dflt_region.to_s
        end

        flags = {}
        flags["subnet_pref"] = vpc_block["subnet_pref"] if !vpc_block["subnet_pref"].nil?

        # First, dig up the enclosing VPC 
        tag_key, tag_value = vpc_block['tag'].split(/=/, 2) if !vpc_block['tag'].nil?
        if !is_sibling
          begin
            if vpc_block['cloud'] != "CloudFormation"
              found = MU::MommaCat.findStray(
                vpc_block['cloud'],
                "vpc",
                deploy_id: vpc_block["deploy_id"],
                cloud_id: vpc_block["vpc_id"],
                name: vpc_block["vpc_name"],
                tag_key: tag_key,
                tag_value: tag_value,
                region: vpc_block["region"],
                flags: flags,
                dummy_ok: true
              )

              ext_vpc = found.first if found.size == 1
            end
          rescue Exception => e
            raise MuError, e.inspect, e.backtrace
          ensure
            if !ext_vpc and vpc_block['cloud'] != "CloudFormation"
              MU.log "Couldn't resolve VPC reference to a unique live VPC in #{parent_name} (called by #{caller[0]})", MU::ERR, details: vpc_block
              return false
            elsif !vpc_block["vpc_id"]
              MU.log "Resolved VPC to #{ext_vpc.cloud_id} in #{parent_name}", MU::DEBUG, details: vpc_block
              vpc_block["vpc_id"] = configurator.getTail("#{parent_name} Target VPC", value: ext_vpc.cloud_id, prettyname: "#{parent_name} Target VPC", cloudtype: "AWS::EC2::VPC::Id")
            end
          end

          # Other !is_sibling logic for external vpcs
          # Next, the NAT host, if there is one
          if (vpc_block['nat_host_name'] or vpc_block['nat_host_ip'] or vpc_block['nat_host_tag'])
            if !vpc_block['nat_host_tag'].nil?
              nat_tag_key, nat_tag_value = vpc_block['nat_host_tag'].to_s.split(/=/, 2)
            else
              nat_tag_key, nat_tag_value = [tag_key.to_s, tag_value.to_s]
            end

            ext_nat = ext_vpc.findBastion(
              nat_name: vpc_block["nat_host_name"],
              nat_cloud_id: vpc_block["nat_host_id"],
              nat_tag_key: nat_tag_key,
              nat_tag_value: nat_tag_value,
              nat_ip: vpc_block['nat_host_ip']
            )
            ssh_keydir = Etc.getpwnam(MU.mu_user).dir+"/.ssh"
            if !vpc_block['nat_ssh_key'].nil? and !File.exists?(ssh_keydir+"/"+vpc_block['nat_ssh_key'])
              MU.log "Couldn't find alternate NAT key #{ssh_keydir}/#{vpc_block['nat_ssh_key']} in #{parent_name}", MU::ERR, details: vpc_block
              return false
            end

            if !ext_nat
              if vpc_block["nat_host_id"].nil? and nat_tag_key.nil? and vpc_block['nat_host_ip'].nil? and vpc_block["deploy_id"].nil?
                MU.log "Couldn't resolve NAT host to a live instance in #{parent_name}.", MU::DEBUG, details: vpc_block
              else
                MU.log "Couldn't resolve NAT host to a live instance in #{parent_name}", MU::ERR, details: vpc_block
                return false
              end
            elsif !vpc_block["nat_host_id"]
              MU.log "Resolved NAT host to #{ext_nat.cloud_id} in #{parent_name}", MU::DEBUG, details: vpc_block
              vpc_block["nat_host_id"] = ext_nat.cloud_id
              vpc_block.delete('nat_host_name')
              vpc_block.delete('nat_host_ip')
              vpc_block.delete('nat_host_tag')
              vpc_block.delete('nat_ssh_user')
            end
          end

          # Some resources specify multiple subnets...
          if vpc_block.has_key?("subnets")
            vpc_block['subnets'].each { |subnet|
              tag_key, tag_value = subnet['tag'].split(/=/, 2) if !subnet['tag'].nil?
              if !ext_vpc.nil?
                begin
                  ext_subnet = ext_vpc.getSubnet(cloud_id: subnet['subnet_id'], name: subnet['subnet_name'], tag_key: tag_key, tag_value: tag_value)
                rescue MuError
                end
              end

              if ext_subnet.nil? and vpc_block["cloud"] != "CloudFormation"
                ok = false
                MU.log "Couldn't resolve subnet reference (list) in #{parent_name} to a live subnet", MU::ERR, details: subnet
              elsif !subnet['subnet_id']
                subnet['subnet_id'] = ext_subnet.cloud_id
                subnet['az'] = ext_subnet.az
                subnet.delete('subnet_name')
                subnet.delete('tag')
                MU.log "Resolved subnet reference in #{parent_name} to #{ext_subnet.cloud_id}", MU::DEBUG, details: subnet
              end
            }
            # ...others single subnets
          elsif vpc_block.has_key?('subnet_name') or vpc_block.has_key?('subnet_id')
            tag_key, tag_value = vpc_block['tag'].split(/=/, 2) if !vpc_block['tag'].nil?
            begin
              ext_subnet = ext_vpc.getSubnet(cloud_id: vpc_block['subnet_id'], name: vpc_block['subnet_name'], tag_key: tag_key, tag_value: tag_value)
            rescue MuError => e
            end

            if ext_subnet.nil?
              ok = false
              MU.log "Couldn't resolve subnet reference (name/id) in #{parent_name} to a live subnet", MU::ERR, details: vpc_block
            elsif !vpc_block['subnet_id']
              vpc_block['subnet_id'] = ext_subnet.cloud_id
              vpc_block['az'] = ext_subnet.az
              vpc_block.delete('subnet_name')
              vpc_block.delete('subnet_pref')
              MU.log "Resolved subnet reference in #{parent_name} to #{ext_subnet.cloud_id}", MU::DEBUG, details: vpc_block
            end
          end
        end

        # ...and other times we get to pick

        # First decide whether we should pay attention to subnet_prefs.
        honor_subnet_prefs = true
        if vpc_block['subnets']
          count = 0
          vpc_block['subnets'].each { |subnet|
            if subnet['subnet_id'] or subnet['subnet_name']
              honor_subnet_prefs=false
            end
            if !subnet['subnet_id'].nil? and subnet['subnet_id'].is_a?(String)
              subnet['subnet_id'] = configurator.getTail("Subnet #{count} for #{parent_name}", value: subnet['subnet_id'], prettyname: "Subnet #{count} for #{parent_name}", cloudtype: "AWS::EC2::Subnet::Id")
              count = count + 1
            end
          }
        elsif (vpc_block['subnet_name'] or vpc_block['subnet_id'])
          honor_subnet_prefs=false
        end

        if vpc_block['subnet_pref'] and honor_subnet_prefs
          private_subnets = []
          private_subnets_map = {}
          public_subnets = []
          public_subnets_map = {}
          subnet_ptr = "subnet_id"
          all_subnets = []
          if !is_sibling
            pub = priv = 0
            raise MuError, "No subnets found in #{ext_vpc}" if ext_vpc.subnets.nil?
            ext_vpc.subnets.each { |subnet|
              next if dflt_region and vpc_block["cloud"] == "Google" and subnet.az != dflt_region
              if subnet.private? and (vpc_block['subnet_pref'] != "all_public" and vpc_block['subnet_pref'] != "public")
                private_subnets << { "subnet_id" => configurator.getTail("#{parent_name} Private Subnet #{priv}", value: subnet.cloud_id, prettyname: "#{parent_name} Private Subnet #{priv}",  cloudtype:  "AWS::EC2::Subnet::Id"), "az" => subnet.az }
                private_subnets_map[subnet.cloud_id] = subnet
                priv = priv + 1
              elsif !subnet.private? and vpc_block['subnet_pref'] != "all_private" and vpc_block['subnet_pref'] != "private"
                public_subnets << { "subnet_id" => configurator.getTail("#{parent_name} Public Subnet #{pub}", value: subnet.cloud_id, prettyname: "#{parent_name} Public Subnet #{pub}",  cloudtype: "AWS::EC2::Subnet::Id"), "az" => subnet.az }
                public_subnets_map[subnet.cloud_id] = subnet
                pub = pub + 1
              else
                MU.log "#{subnet} didn't match subnet_pref: '#{vpc_block['subnet_pref']}' (private? returned #{subnet.private?})", MU::DEBUG
              end
            }
          else
            sibling_vpcs.each { |ext_vpc|
              if ext_vpc['name'].to_s == vpc_block['vpc_name'].to_s
                subnet_ptr = "subnet_name"
                ext_vpc['subnets'].each { |subnet|
                  next if dflt_region and vpc_block["cloud"] == "Google" and subnet['availability_zone'] != dflt_region
                  if subnet['is_public'] # NAT nonsense calculated elsewhere, ew
                    public_subnets << {"subnet_name" => subnet['name'].to_s}
                  else
                    private_subnets << {"subnet_name" => subnet['name'].to_s}
                    configurator.nat_routes[subnet['name'].to_s] = [] if configurator.nat_routes[subnet['name'].to_s].nil?
                    if !subnet['nat_host_name'].nil?
                      configurator.nat_routes[subnet['name'].to_s] << subnet['nat_host_name'].to_s
                    end
                  end
                }
                break
              end
            }
          end

          if public_subnets.size == 0 and private_subnets == 0
            MU.log "Couldn't find any subnets for #{parent_name}", MU::ERR
            return false
          end
          all_subnets = public_subnets + private_subnets

          case vpc_block['subnet_pref']
            when "public"
              if !public_subnets.nil? and public_subnets.size > 0
                vpc_block.merge!(public_subnets[rand(public_subnets.length)]) if public_subnets
              else
                MU.log "Public subnet requested for #{parent_name}, but none found in #{vpc_block}", MU::ERR
                return false
              end
            when "private"
              if !private_subnets.nil? and private_subnets.size > 0
                vpc_block.merge!(private_subnets[rand(private_subnets.length)])
              else
                MU.log "Private subnet requested for #{parent_name}, but none found in #{vpc_block}", MU::ERR
                return false
              end
              if !is_sibling and !private_subnets_map[vpc_block[subnet_ptr]].nil?
                vpc_block['nat_host_id'] = private_subnets_map[vpc_block[subnet_ptr]].defaultRoute
              elsif configurator.nat_routes.has_key?(vpc_block[subnet_ptr])
                vpc_block['nat_host_name'] == configurator.nat_routes[vpc_block[subnet_ptr]]
              end
            when "any"
              vpc_block.merge!(all_subnets.sample)
            when "all"
              vpc_block['subnets'] = []
              public_subnets.each { |subnet|
                vpc_block['subnets'] << subnet
              }
              private_subnets.each { |subnet|
                vpc_block['subnets'] << subnet
              }
            when "all_public"
              vpc_block['subnets'] = []
              public_subnets.each { |subnet|
                vpc_block['subnets'] << subnet
              }
            when "all_private"
              vpc_block['subnets'] = []
              private_subnets.each { |subnet|
                vpc_block['subnets'] << subnet
                if !is_sibling and vpc_block['nat_host_id'].nil? and private_subnets_map.has_key?(subnet[subnet_ptr]) and !private_subnets_map[subnet[subnet_ptr]].nil?
                  vpc_block['nat_host_id'] = private_subnets_map[subnet[subnet_ptr]].defaultRoute
                elsif configurator.nat_routes.has_key?(subnet) and vpc_block['nat_host_name'].nil?
                  vpc_block['nat_host_name'] == configurator.nat_routes[subnet]
                end
              }
            else
              vpc_block['subnets'] ||= []

              sibling_vpcs.each { |ext_vpc|
                next if ext_vpc["name"] != vpc_block["vpc_name"]
                ext_vpc["subnets"].each { |subnet|
                  if subnet["route_table"] == vpc_block["subnet_pref"]
                    vpc_block["subnets"] << subnet
                  end
                }
              }
              if vpc_block['subnets'].size < 1
                MU.log "Unable to resolve subnet_pref '#{vpc_block['subnet_pref']}' to any route table"
                ok = false
              end
          end
        end

        if ok
          # Delete values that don't apply to the schema for whatever this VPC's
          # parent resource is.
          vpc_block.keys.each { |vpckey|
            if MU::Config.schema["properties"][parent_type]["items"]["properties"]["vpc"] and
               !MU::Config.schema["properties"][parent_type]["items"]["properties"]["vpc"]["properties"].has_key?(vpckey)
              vpc_block.delete(vpckey)
            end
          }
          if vpc_block['subnets'] and
             MU::Config.schema["properties"][parent_type]["items"]["properties"]["vpc"] and
             MU::Config.schema["properties"][parent_type]["items"]["properties"]["vpc"]["properties"]["subnets"]
            vpc_block['subnets'].each { |subnet|
              subnet.each_key { |subnetkey|
                if !MU::Config.schema["properties"][parent_type]["items"]["properties"]["vpc"]["properties"]["subnets"]["items"]["properties"].has_key?(subnetkey)
                  subnet.delete(subnetkey)
                end
              }
            }
          end

          vpc_block.delete('deploy_id')
          vpc_block.delete('vpc_name') if vpc_block.has_key?('vpc_id')
          vpc_block.delete('deploy_id')
          vpc_block.delete('tag')
          MU.log "Resolved VPC resources for #{parent_name}", MU::DEBUG, details: vpc_block
        end

        if !vpc_block["vpc_id"].nil? and vpc_block["vpc_id"].is_a?(String)
          vpc_block["vpc_id"] = configurator.getTail("#{parent_name}vpc_id", value: vpc_block["vpc_id"], prettyname: "#{parent_name} Target VPC",  cloudtype: "AWS::EC2::VPC::Id")
        elsif !vpc_block["nat_host_name"].nil? and vpc_block["nat_host_name"].is_a?(String)
          vpc_block["nat_host_name"] = MU::Config::Tail.new("#{parent_name}nat_host_name", vpc_block["nat_host_name"])

        end

        ok = false if !resolvePeers(vpc, configurator)

        return ok
      end

    end
  end
end
