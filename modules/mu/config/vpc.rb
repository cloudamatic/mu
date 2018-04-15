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

    end
  end
end
