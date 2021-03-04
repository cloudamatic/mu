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
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/vpc.rb
    class VPC

      # Base configuration schema for a VPC
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "required" => ["name"],
          "description" => "Create Virtual Private Clouds with custom public or private subnets.",
          "properties" => {
            "name" => {"type" => "string"},
            "habitat" => MU::Config::Habitat.reference,
            "cloud" => MU::Config.cloud_primitive,
            "ip_block" => {
              "type" => "string",
              "pattern" => MU::Config::CIDR_PATTERN,
              "description" => MU::Config::CIDR_DESCRIPTION
            },
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => MU::Config.optional_tags_primitive,
            "create_bastion" => {
              "type" => "boolean",
              "description" => "If we have private subnets and our Mu Master will not be able to route directly to them, create a small instance to serve as an ssh relay.",
              "default" => true
            },
            "bastion" => MU::Config::Ref.schema(type: "servers", desc: "A reference to a bastion host that can be used to tunnel into private address space in this VPC."),
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
              "default_if" => [
                {
                  "key_is" => "create_standard_subnets",
                  "value_is" => true,
                  "set" => [
                    {
                      "name" => "internet",
                      "routes" => [ { "destination_network" => "0.0.0.0/0", "gateway" => "#INTERNET" } ]
                    },
                    {
                      "name" => "private",
                      "routes" => [ { "destination_network" => "0.0.0.0/0", "gateway" => "#NAT" } ]
                    }
                  ]
                },
                {
                  "key_is" => "create_standard_subnets",
                  "value_is" => false,
                  "set" => [
                    {
                      "name" => "private",
                      "routes" => [ { "destination_network" => "0.0.0.0/0" } ]
                    }
                  ]
                }
              ],
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

      # Constant for passing into MU::Config::VPC.reference
      NO_SUBNETS = 0.freeze
      # Constant for passing into MU::Config::VPC.reference
      ONE_SUBNET = 1.freeze
      # Constant for passing into MU::Config::VPC.reference
      MANY_SUBNETS = 2.freeze
      # Constant for passing into MU::Config::VPC.reference
      NAT_OPTS = true.freeze
      # Constant for passing into MU::Config::VPC.reference
      NO_NAT_OPTS = false.freeze

      # There's a small amount of variation in the way various resources need to
      # refer to VPCs, so let's wrap the schema in a method that'll handle the
      # wiggling.
      # @param subnets [Integer]:
      # @param nat_opts [Boolean]:
      # @param subnet_pref [String]:
      # @return [Hash]
      def self.reference(subnets = MANY_SUBNETS, nat_opts = NAT_OPTS, subnet_pref = nil)
        schema_aliases = [
          { "vpc_id" => "id" },
          { "vpc_name" => "name" }
        ]
        vpc_ref_schema = MU::Config::Ref.schema(schema_aliases, type: "vpcs")

#        vpc_ref_schema = {
#          "type" => "object",
#          "description" => "Deploy, attach, allow access from, or peer this resource with a VPC of VPCs.",
#          "minProperties" => 1,
#          "additionalProperties" => false,
#          "properties" => {
#            "vpc_id" => {
#              "type" => "string",
#              "description" => "Discover this VPC by looking for this cloud provider identifier."
#            },
#            "credentials" => MU::Config.credentials_primitive,
#            "vpc_name" => {
#              "type" => "string",
#              "description" => "Discover this VPC by Mu-internal name; typically the shorthand 'name' field of a VPC declared elsewhere in the deploy, or in another deploy that's being referenced with 'deploy_id'."
#            },
#            "region" => MU::Config.region_primitive,
#            "cloud" => MU::Config.cloud_primitive,
#            "tag" => {
#              "type" => "string",
#              "description" => "Discover this VPC by a cloud provider tag (key=value); note that this tag must not match more than one resource.",
#              "pattern" => "^[^=]+=.+"
#            },
#            "deploy_id" => {
#              "type" => "string",
#              "description" => "Search for this VPC in an existing Mu deploy; specify a Mu deploy id (e.g. DEMO-DEV-2014111400-NG)."
#            }
#          }
#        }

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

      # Generate schema for a network route, usually used in the context of a VPC resource
      # @return [Hash]
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
                "description" => "The instance id of a NAT host in this VPC."
              },
              "nat_host_name" => {
                "type" => "string",
                "description" => "The MU resource name or Name tag of a NAT host in this VPC."
              },
              "interface" => {
                "type" => "string",
                "description" => "A network interface over which to route."
              }
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::vpcs}, bare and unvalidated.
      # @param vpc [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(vpc, configurator)
        ok = true

        have_public = false
        have_private = false

        using_default_cidr = false
        if !vpc['ip_block']
          if configurator.updating and configurator.existing_deploy and
             configurator.existing_deploy.original_config and
             configurator.existing_deploy.original_config['vpcs']
            configurator.existing_deploy.original_config['vpcs'].each { |v|
              if v['name'].to_s == vpc['name'].to_s
                vpc['ip_block'] = v['ip_block']
                vpc['peers'] ||= []
                vpc['peers'].concat(v['peers'])
                break
              elsif v['virtual_name'] == vpc['name']
                vpc['ip_block'] = v['parent_block']
                vpc['peers'] ||= []
                vpc['peers'].concat(v['peers'])
                break
              end
            }
            if !vpc['ip_block']
              MU.log "Loading existing deploy but can't find IP block of VPC #{vpc['name']}", MU::ERR
              ok = false
            end
          else
            using_default_cidr = true
            vpc['ip_block'] = "10.0.0.0/16"
          end
        end

        # Look for a common YAML screwup in route table land
        vpc['route_tables'].each { |rtb|
          next if !rtb['routes']
          rtb['routes'].each { |r|
            have_public = true if r['gateway'] == "#INTERNET"
            have_private = true if r['gateway'] == "#NAT" or r['gateway'] == "#DENY"
            # XXX the above logic doesn't cover VPN ids, peering connections, or
            # instances used as routers. If you're doing anything that complex
            # you should probably be declaring your own bastion hosts and 
            # routing behaviors, rather than relying on our inferred defaults.
            if r.has_key?("gateway") and (!r["gateway"] or r["gateway"].to_s.empty?)
              MU.log "Route gateway in VPC #{vpc['name']} cannot be nil- did you forget to puts quotes around a #INTERNET, #NAT, or #DENY?", MU::ERR, details: rtb
              ok = false
            end
          }
          rtb['routes'].uniq!
        }

        peer_blocks = []
        siblings = configurator.haveLitterMate?(nil, "vpcs", has_multiple: true)
        if siblings
          siblings.each { |v|
            next if v['name'] == vpc['name']
            peer_blocks << v['ip_block'] if v['ip_block']
          }
        end

        # if we're peering with other on-the-fly VPCs who might be using
        # the default range, make sure our ip_blocks don't overlap
        my_cidr = NetAddr::IPv4Net.parse(vpc['ip_block'].to_s)
        if peer_blocks.size > 0 and using_default_cidr and !configurator.updating
          begin
            have_overlaps = false
            peer_blocks.each { |cidr|
              sibling_cidr = NetAddr::IPv4Net.parse(cidr.to_s)
              have_overlaps = true if my_cidr.rel(sibling_cidr) != nil
            }
            if have_overlaps
              my_cidr = my_cidr.next_sib
              my_cidr = nil if my_cidr.to_s.match(/^10\.255\./)
            end
          end while have_overlaps
          if !my_cidr.nil? and vpc['ip_block'] != my_cidr.to_s
            vpc['ip_block'] = my_cidr.to_s
          else
            my_cidr = NetAddr::IPv4Net.parse(vpc['ip_block'])
          end
        end

        # Work out what we'll do 
        if have_private
          vpc["cloud"] ||= MU.defaultCloud

          # See if we'll be able to create peering connections
          can_peer = false
          already_peered = false

          if MU.myCloud == vpc["cloud"] and MU.myVPCObj
            if vpc['peers']
              vpc['peers'].each { |peer|
                if peer["vpc"]["id"] == MU.myVPC
                  already_peered = true
                  break
                end
              }
            end
            if !already_peered
              peer_blocks.concat(MU.myVPCObj.routes)
              begin
                can_peer = true
                peer_blocks.each { |cidr|
                  cidr_obj = NetAddr::IPv4Net.parse(cidr)
                  if my_cidr.rel(cidr_obj) != nil
                    can_peer = false
                  end
                }
                if !can_peer and using_default_cidr
                  my_cidr = my_cidr.next_sib
                  my_cidr = nil if my_cidr.to_s.match(/^10\.255\./)
                end
              end while !can_peer and using_default_cidr and !my_cidr.nil?
              if !my_cidr.nil? and vpc['ip_block'] != my_cidr.to_s
                vpc['ip_block'] = my_cidr.to_s
              end
              if using_default_cidr
                MU.log "Defaulting address range for VPC #{vpc['name']} to #{vpc['ip_block']}", MU::NOTICE
              end
              if can_peer
                vpc['peers'] ||= []
                vpc['peers'] << {
                  "vpc" => { "id" => MU.myVPC, "type" => "vpcs" }
                }
              elsif !configurator.updating
                MU.log "#{vpc['name']} CIDR block #{vpc['ip_block']} overlaps with existing routes, will not be able to peer with Master's VPC", MU::WARN
              end
            end
          end

          # Failing that, generate a generic bastion/NAT host to do the job.
          # Clouds that don't have some kind of native NAT gateway can also
          # leverage this host to honor "gateway" => "#NAT" situations.
          if !can_peer and !already_peered and have_public and vpc["create_bastion"]
            serverclass = MU::Cloud.resourceClass(vpc["cloud"], "Server")
            bastion = serverclass.genericNAT.dup
            bastion["groomer_variables"] = {
              "nat_ip_block" => vpc["ip_block"].to_s
            }
            bastion['name'] = vpc['name']+"-natstion" # XXX account for multiples somehow
            bastion['credentials'] = vpc['credentials']
            bastion['region'] = vpc['region']
            bastion['ingress_rules'] ||= []
            ["tcp", "udp", "icmp"].each { |proto|
              bastion['ingress_rules'] << {
                "hosts" => [vpc["ip_block"].to_s],
                "proto" => proto
              }
            }
            bastion["vpc"] = {
              "name" => vpc["name"],
              "subnet_pref" => "public"
            }
#            MU::Config.addDependency(vpc, bastion['name'], "server", my_phase: "groom")
#            vpc["bastion"] = MU::Config::Ref.get(
#              name: bastion['name'],
#              cloud: vpc['cloud'],
#              credentials: vpc['credentials'],
#              type: "servers"
#            )

            ok = false if !configurator.insertKitten(bastion, "servers", true)
          end

        end


        ok = false if !resolvePeers(vpc, configurator)

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
          append = []
          delete = []
          vpc["peers"].each { |peer|
            if peer.nil? or !peer.is_a?(Hash) or !peer["vpc"]
              MU.log "Skipping malformed VPC peer in #{vpc['name']}", MU::ERR, details: peer
              next
            end
            peer["#MU_CLOUDCLASS"] = MU::Cloud.loadBaseType("VPC")
            # We check for multiple siblings because some implementations
            # (Google) can split declared VPCs into parts to get the mimic the
            # routing behaviors we expect.
            siblings = configurator.haveLitterMate?(peer['vpc']["name"], "vpcs", has_multiple: true)

            # If we're peering with a VPC in this deploy, set it as a dependency
            if !peer['vpc']["name"].nil? and siblings.size > 0 and
               peer["vpc"]['deploy_id'].nil? and peer["vpc"]['vpc_id'].nil?

              peer['vpc']['cloud'] = vpc['cloud'] if peer['vpc']['cloud'].nil?
              siblings.each { |sib|
                if sib['name'] != peer['vpc']["name"]
                  if sib['name'] != vpc['name']
                    append_me = { "vpc" => peer["vpc"].dup }
                    append_me['vpc']['name'] = sib['name']
                    append << append_me
                    MU::Config.addDependency(vpc, sib['name'], "vpc", their_phase: "create", my_phase: "groom")
                  end
                  delete << peer
                else
                  MU::Config.addDependency(vpc, peer['vpc']['name'], "vpc", their_phase: "create", my_phase: "groom")
                end
                delete << peer if sib['name'] == vpc['name']
              }
              # If we're using a VPC from somewhere else, make sure the flippin'
              # thing exists, and also fetch its id now so later search routines
              # don't have to work so hard.
            else
              peer['vpc']['cloud'] = vpc['cloud'] if peer['vpc']['cloud'].nil?
              if !peer['account'].nil? and peer['account'] != MU.account_number
                if peer['vpc']["vpc_id"].nil?
                  MU.log "VPC peering connections to non-local accounts must specify the vpc_id of the peer.", MU::ERR
                  ok = false
                end
              elsif !processReference(peer['vpc'], "vpcs", vpc, configurator, dflt_region: peer["vpc"]['region'])
                ok = false
              end
            end
          }
          append.each { |append_me|
            vpc["peers"] << append_me
          }
          delete.each { |delete_me|
            vpc["peers"].delete(delete_me)
          }
          vpc["peers"].uniq!
        end
        ok
      end


      @@reference_cache = {}

      # Pick apart an external VPC reference, validate it, and resolve it and its
      # various subnets and NAT hosts to live resources.
      # @param vpc_block [Hash]:
      # @param parent_type [String]:
      # @param parent [MU::Cloud::VPC]:
      # @param configurator [MU::Config]:
      # @param sibling_vpcs [Array]:
      # @param dflt_region [String]:
      def self.processReference(vpc_block, parent_type, parent, configurator, sibling_vpcs: [], dflt_region: MU.curRegion, dflt_project: nil, credentials: nil)

        if !vpc_block.is_a?(Hash) and vpc_block.kind_of?(MU::Cloud::VPC)
          return true
        end
        ok = true

        if vpc_block['region'].nil? and dflt_region and !dflt_region.empty?
          vpc_block['region'] = dflt_region.to_s
        end
        dflt_region ||= vpc_block['region']
        vpc_block['name'] ||= vpc_block['vpc_name'] if vpc_block['vpc_name']
        vpc_block['id'] ||= vpc_block['vpc_id'] if vpc_block['vpc_id']

        vpc_block['credentials'] ||= credentials if credentials
        vpc_block['project'] ||= dflt_project if dflt_project
        vpc_block["cloud"] ||= parent["cloud"]

# XXX the right thing to do here is have a per-cloud callback hook for resolving
# projects/accounts/whatever, but for now let's get it working with Google's case
        if vpc_block["cloud"] and vpc_block["cloud"] == "Google" and
           vpc_block['project']
          vpc_block["habitat"] ||= MU::Cloud::Google.projectToRef(vpc_block['project'], config: configurator, credentials: vpc_block['credentials']).to_h
          vpc_block.delete("project")
        end

        # If this appears to be a sibling VPC that's destined to live in a
        # sibling habitat, then by definition it doesn't exist yet. So don't
        # try to do anything else clever here.
# XXX except maybe there's some stuff we should still do
        if vpc_block["habitat"] and vpc_block["habitat"]["name"] and
           !vpc_block["habitat"]["id"]
          return ok
        end

        # Resolve "forked" Google VPCs to the correct literal resources, based
        # on the original reference to the (now virtual) parent VPC and, if
        # set, subnet_pref or subnet_name
        sibling_vpcs.each { |sibling|
          if sibling['virtual_name'] and
             sibling['virtual_name'] == vpc_block['name']
            if vpc_block['region'] and
               sibling['regions'].include?(vpc_block['region'])
              gateways = sibling['route_tables'].map { |rtb|
                rtb['routes'].map { |r| r["gateway"] }
              }.flatten.uniq
              if ["public", "all_public"].include?(vpc_block['subnet_pref']) and
                 gateways.include?("#INTERNET")
                vpc_block['name'] = sibling['name']
                break
              elsif ["private", "all_private"].include?(vpc_block['subnet_pref']) and
                 !gateways.include?("#INTERNET")
                vpc_block['name'] = sibling['name']
                break
              end
            end
          end
        }

        is_sibling = (vpc_block['name'] and configurator.haveLitterMate?(vpc_block["name"], "vpcs"))

        # Sometimes people set subnet_pref to "private" or "public" when they
        # mean "all_private" or "all_public." Help them out.
        if parent_type and 
           MU::Config.schema["properties"][parent_type] and
           MU::Config.schema["properties"][parent_type]["items"]["properties"]["vpc"] and
           MU::Config.schema["properties"][parent_type]["items"]["properties"]["vpc"]["properties"].has_key?("subnets") and
           !MU::Config.schema["properties"][parent_type]["items"]["properties"]["vpc"]["properties"].has_key?("subnet_id")
           vpc_block["subnet_pref"] = "all_public" if vpc_block["subnet_pref"] == "public"
           vpc_block["subnet_pref"] = "all_private" if vpc_block["subnet_pref"] == "private"
        end

#        flags = {}
#        flags["subnet_pref"] = vpc_block["subnet_pref"] if !vpc_block["subnet_pref"].nil?
        hab_arg = if vpc_block['habitat']
          if vpc_block['habitat'].is_a?(MU::Config::Ref)
            [vpc_block['habitat'].id] # XXX actually, findStray it
          elsif vpc_block['habitat'].is_a?(Hash)
            [vpc_block['habitat']['id']] # XXX actually, findStray it
          else
            [vpc_block['habitat'].to_s]
          end
        elsif vpc_block['project']
          [vpc_block['project']]
        else
          []
        end

        # First, dig up the enclosing VPC 
        tag_key, tag_value = vpc_block['tag'].split(/=/, 2) if !vpc_block['tag'].nil?
        if !is_sibling
          begin
            if vpc_block['cloud'] != "CloudFormation"
              ext_vpc = if @@reference_cache[vpc_block]
MU.log "VPC lookup cache hit", MU::WARN, details: vpc_block
                @@reference_cache[vpc_block]
              else
                found = MU::MommaCat.findStray(
                  vpc_block['cloud'],
                  "vpc",
                  deploy_id: vpc_block["deploy_id"],
                  cloud_id: vpc_block["id"],
                  name: vpc_block["name"],
                  credentials: vpc_block["credentials"],
                  tag_key: tag_key,
                  tag_value: tag_value,
                  region: vpc_block["region"],
                  habitats: hab_arg,
                  dummy_ok: true,
                  subnet_pref: vpc_block["subnet_pref"]
                )

                found.first if found and found.size == 1
              end
              @@reference_cache[vpc_block] ||= ext_vpc

              # Make sure we don't have a weird mismatch between requested
              # credential sets and the VPC we actually found
              if ext_vpc and ext_vpc.cloudobj and ext_vpc.cloudobj.config and
                 ext_vpc.cloudobj.config["credentials"]
                if vpc_block['credentials'] and # probably can't happen
                   vpc_block['credentials'] != ext_vpc.cloudobj.config["credentials"]
                  ok = false
                  MU.log "#{parent_type} #{parent['name']} requested a VPC on credentials '#{vpc_block['credentials']}' but matched VPC is under credentials '#{ext_vpc.cloudobj.config["credentials"]}'", MU::ERR, details: vpc_block
                end
                if credentials and
                   credentials != ext_vpc.cloudobj.config["credentials"]
                  ok = false
                  MU.log "#{parent_type} #{parent['name']} is using credentials '#{credentials}' but matched VPC is under credentials '#{ext_vpc.cloudobj.config["credentials"]}'", MU::ERR, details: vpc_block
                end
                @@reference_cache[vpc_block] ||= ext_vpc if ok
                vpc_block['credentials'] ||= ext_vpc.cloudobj.config["credentials"]
              end
              @@reference_cache[vpc_block] ||= ext_vpc if ok
            end
          rescue StandardError => e
            raise MuError.new e.inspect, details: { "my call stack" => caller, "exception call stack" => e.backtrace }
          ensure
            if !ext_vpc and vpc_block['cloud'] != "CloudFormation"
              MU.log "Couldn't resolve VPC reference to a unique live VPC in #{parent_type} #{parent['name']} (called by #{caller[0]})", MU::ERR, details: vpc_block
              return false
            elsif !vpc_block["id"]
              MU.log "Resolved VPC to #{ext_vpc.cloud_id} in #{parent['name']}", MU::DEBUG, details: vpc_block
              vpc_block["id"] = configurator.getTail("#{parent['name']} Target VPC", value: ext_vpc.cloud_id, prettyname: "#{parent['name']} Target VPC", cloudtype: "AWS::EC2::VPC::Id")
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
            if !vpc_block['nat_ssh_key'].nil? and !File.exist?(ssh_keydir+"/"+vpc_block['nat_ssh_key'])
              MU.log "Couldn't find alternate NAT key #{ssh_keydir}/#{vpc_block['nat_ssh_key']} in #{parent['name']}", MU::ERR, details: vpc_block
              return false
            end

            if !ext_nat
              if vpc_block["nat_host_id"].nil? and nat_tag_key.nil? and vpc_block['nat_host_ip'].nil? and vpc_block["deploy_id"].nil?
                MU.log "Couldn't resolve NAT host to a live instance in #{parent['name']}.", MU::DEBUG, details: vpc_block
              else
                MU.log "Couldn't resolve NAT host to a live instance in #{parent['name']}", MU::ERR, details: vpc_block
                return false
              end
            elsif !vpc_block["nat_host_id"]
              MU.log "Resolved NAT host to #{ext_nat.cloud_id} in #{parent['name']}", MU::DEBUG, details: vpc_block
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
                MU.log "Couldn't resolve subnet reference (list) in #{parent['name']} to a live subnet", MU::ERR, details: subnet
              elsif !subnet['subnet_id']
                subnet['subnet_id'] = ext_subnet.cloud_id
                subnet['az'] = ext_subnet.az
                subnet.delete('subnet_name')
                subnet.delete('tag')
                MU.log "Resolved subnet reference in #{parent['name']} to #{ext_subnet.cloud_id}", MU::DEBUG, details: subnet
              end
            }
            # ...others single subnets
          elsif vpc_block.has_key?('subnet_name') or vpc_block.has_key?('subnet_id')
            tag_key, tag_value = vpc_block['tag'].split(/=/, 2) if !vpc_block['tag'].nil?
            begin
              ext_subnet = ext_vpc.getSubnet(cloud_id: vpc_block['subnet_id'], name: vpc_block['subnet_name'], tag_key: tag_key, tag_value: tag_value)
            rescue MuError
            end

            if ext_subnet.nil?
              ok = false
              MU.log "Couldn't resolve subnet reference (name/id) in #{parent['name']} to a live subnet", MU::ERR, details: vpc_block
            elsif !vpc_block['subnet_id']
              vpc_block['subnet_id'] = ext_subnet.cloud_id
              vpc_block['az'] = ext_subnet.az
              vpc_block.delete('subnet_name')
              vpc_block.delete('subnet_pref')
              MU.log "Resolved subnet reference in #{parent['name']} to #{ext_subnet.cloud_id}", MU::DEBUG, details: vpc_block
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
              subnet['subnet_id'] = configurator.getTail("Subnet #{count} for #{parent['name']}", value: subnet['subnet_id'], prettyname: "Subnet #{count} for #{parent['name']}", cloudtype: "AWS::EC2::Subnet::Id")
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
          if !is_sibling
            pub = priv = 0
            raise MuError, "No subnets found in #{ext_vpc}" if ext_vpc.subnets.nil?
            ext_vpc.subnets.each { |subnet|
              next if dflt_region and vpc_block["cloud"] == "Google" and subnet.az != dflt_region
              if subnet.private? and (vpc_block['subnet_pref'] != "all_public" and vpc_block['subnet_pref'] != "public")
                private_subnets << {
                  "subnet_id" => configurator.getTail(
                    "#{parent['name']} Private Subnet #{priv}",
                    value: subnet.cloud_id,
                    prettyname: "#{parent['name']} Private Subnet #{priv}",
                    cloudtype: "AWS::EC2::Subnet::Id"),
                  "az" => subnet.az
                }
                private_subnets_map[subnet.cloud_id] = subnet
                priv = priv + 1
              elsif !subnet.private? and vpc_block['subnet_pref'] != "all_private" and vpc_block['subnet_pref'] != "private"
                public_subnets << { "subnet_id" => configurator.getTail("#{parent['name']} Public Subnet #{pub}", value: subnet.cloud_id, prettyname: "#{parent['name']} Public Subnet #{pub}",  cloudtype: "AWS::EC2::Subnet::Id"), "az" => subnet.az }
                public_subnets_map[subnet.cloud_id] = subnet
                pub = pub + 1
              else
                MU.log "#{subnet} didn't match subnet_pref: '#{vpc_block['subnet_pref']}' (private? returned #{subnet.private?})", MU::DEBUG
              end
            }
          else
            sibling_vpcs.each { |sibling_vpc|
              if (sibling_vpc['name'].to_s == vpc_block['name'].to_s or
                 sibling_vpc['virtual_name'].to_s == vpc_block['name'].to_s) and
                 sibling_vpc['subnets']
                subnet_ptr = "subnet_name"

                sibling_vpc['subnets'].each { |subnet|
                  next if dflt_region and vpc_block["cloud"].to_s == "Google" and subnet['availability_zone'] != dflt_region
                  if subnet['is_public']
                    public_subnets << {"subnet_name" => subnet['name'].to_s}
                  else
                    private_subnets << {"subnet_name" => subnet['name'].to_s}
                    configurator.nat_routes[subnet['name'].to_s] = [] if configurator.nat_routes[subnet['name'].to_s].nil?
                    if !subnet['nat_host_name'].nil?
                      configurator.nat_routes[subnet['name'].to_s] << subnet['nat_host_name'].to_s
                    end
                  end
                }
              end
            }
          end

          if public_subnets.size == 0 and private_subnets == 0
            MU.log "Couldn't find any subnets for #{parent['name']}", MU::ERR
            return false
          end
          all_subnets = public_subnets + private_subnets

          case vpc_block['subnet_pref']
            when "public"
              if !public_subnets.nil? and public_subnets.size > 0
                vpc_block.merge!(public_subnets[rand(public_subnets.length)]) if public_subnets
              else
                MU.log "Public subnet requested for #{parent_type} #{parent['name']}, but none found among #{all_subnets.join(", ")}", MU::ERR, details: vpc_block.to_h
                pp is_sibling
                return false
              end
            when "private"
              if !private_subnets.nil? and private_subnets.size > 0
                vpc_block.merge!(private_subnets[rand(private_subnets.length)])
              else
                MU.log "Private subnet requested for #{parent_type} #{parent['name']}, but none found among #{all_subnets.join(", ")}", MU::ERR, details: vpc_block.to_h
                pp is_sibling
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

              sibling_vpcs.each { |sibling_vpc|
                next if sibling_vpc["name"] != vpc_block["name"]
                sibling_vpc["subnets"].each { |subnet|
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

          vpc_block.delete('id') if vpc_block['id'].nil?
          vpc_block.delete('name') if vpc_block.has_key?('id')
          vpc_block.delete('tag')
          MU.log "Resolved VPC resources for #{parent['name']}", MU::DEBUG, details: vpc_block
        end

        if !vpc_block["id"].nil? and vpc_block["id"].is_a?(String)
          vpc_block["id"] = configurator.getTail("#{parent['name']}_id", value: vpc_block["id"], prettyname: "#{parent['name']} Target VPC",  cloudtype: "AWS::EC2::VPC::Id")
        elsif !vpc_block["nat_host_name"].nil? and vpc_block["nat_host_name"].is_a?(String)
          vpc_block["nat_host_name"] = MU::Config::Tail.new("#{parent['name']}nat_host_name", vpc_block["nat_host_name"])

        end

        # XXX This definitely should be generic
        if vpc_block['id'].is_a?(MU::Cloud::Azure::Id)
          vpc_block['id'] = vpc_block['id'].to_s
        end

        return ok
      end

    end

    # Take an IP block and split it into a more-or-less arbitrary number of
    # subnets.
    # @param ip_block [String]: CIDR of the network to subdivide
    # @param subnets_desired [Integer]: Number of subnets we want back
    # @param max_mask [Integer]: The highest netmask we're allowed to use for a subnet (various by cloud provider)
    # @return [MU::Config::Tail]: Resulting subnet tails, or nil if an error occurred.
    def divideNetwork(ip_block, subnets_desired, max_mask = 28)
      cidr = NetAddr::IPv4Net.parse(ip_block.to_s)

      # Ugly but reliable method of landing on the right subnet size
      subnet_bits = cidr.netmask.prefix_len
      begin
        subnet_bits += 1
        if subnet_bits > max_mask
          MU.log "Can't subdivide #{cidr.to_s} into #{subnets_desired.to_s}", MU::ERR
          raise MuError, "Subnets smaller than /#{max_mask} not permitted"
        end
      end while cidr.subnet_count(subnet_bits) < subnets_desired

      if cidr.subnet_count(subnet_bits) > subnets_desired
        MU.log "Requested #{subnets_desired.to_s} subnets from #{cidr.to_s}, leaving #{(cidr.subnet_count(subnet_bits)-subnets_desired).to_s} unused /#{subnet_bits.to_s}s available", MU::NOTICE
      end

      begin
        subnets = []
        (0..subnets_desired).each { |x|
          subnets << cidr.nth_subnet(subnet_bits, x).to_s
        }
      rescue RuntimeError => e
        if e.message.match(/exceeds subnets available for allocation/)
          MU.log e.message, MU::ERR
          MU.log "I'm attempting to create #{subnets_desired} subnets (one public and one private for each Availability Zone), of #{subnet_size} addresses each, but that's too many for a /#{cidr.netmask.prefix_len} network. Either declare a larger network, or explicitly declare a list of subnets with few enough entries to fit.", MU::ERR
          return nil
        else
          raise e
        end
      end

      subnets = getTail("subnetblocks", value: subnets.join(","), cloudtype: "CommaDelimitedList", description: "IP Address ranges to be used for VPC subnets", prettyname: "SubnetIpBlocks", list_of: "ip_block").map { |tail| tail["ip_block"] }
      subnets
    end
  end
end
