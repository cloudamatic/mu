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
    class DNSZone

      def self.schema
        {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "Create a DNS zone in Route 53.",
          "required" => ["name", "cloud"],
          "properties" => {
            "name" => {
                "type" => "string",
                "description" => "The domain name to create. Must comply with RFC 1123",
                "pattern" => "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
            },
            "scrub_mu_isms" => {
                "type" => "boolean",
                "default" => false,
                "description" => "When 'cloud' is set to 'CloudFormation,' use this flag to strip out Mu-specific artifacts (tags, standard userdata, naming conventions, etc) to yield a clean, source-agnostic template."
            },
            "private" => {
                "type" => "boolean",
                "default" => true,
                "description" => "Create as a private internal domain, not publicly resolvable."
            },
            "all_account_vpcs" => {
                "type" => "boolean",
                "default" => true,
                "description" => "If this zone is private, make sure it is resolvable from all VPCs in this account. Will supercede the list in {MU::Config::BasketofKittens::dnszones.vpcs} for VPCs in this account."
            },
            "records" => records_primitive(),
            "vpcs" => {
                "type" => "array",
                "items" => MU::Config::VPC.reference(MU::Config::VPC::NO_SUBNETS, MU::Config::VPC::NO_NAT_OPTS)
            }
          }
        }
      end

      def self.records_primitive(need_target: true, default_type: nil, need_zone: false)
        dns_records_primitive = {
          "type" => "array",
          "maxItems" => 100,
          "items" => {
              "type" => "object",
              "required" => ["target", "type"],
              "additionalProperties" => false,
              "description" => "DNS records to create. If specified inside another resource (e.g. {MU::Config::BasketofKittens::servers}, {MU::Config::BasketofKittens::loadbalancers}, or {MU::Config::BasketofKittens::databases}), the record(s) will automatically target that resource.",
              "properties" => {
                  "override_existing" => {
                      "type" => "boolean",
                      "description" => "If true, this record will overwrite any existing record of the same name and type.",
                      "default" => false
                  },
                  "type" => {
                      "type" => "string",
                      "description" => "The class of DNS record to create. The R53ALIAS type is not traditional DNS, but instead refers to AWS Route53's alias functionality. An R53ALIAS is only valid if the target is an Elastic LoadBalancer, CloudFront, S3 bucket (configured as a public web server), or another record in the same Route53 hosted zone.",
                      "enum" => ["SOA", "A", "TXT", "NS", "CNAME", "MX", "PTR", "SRV", "SPF", "AAAA", "R53ALIAS"],
                      "default_if" => [
                        {
                          "key_is" => "mu_type",
                          "value_is" => "loadbalancer",
                          "set" => "R53ALIAS"
                        },
                        {
                          "key_is" => "mu_type",
                          "value_is" => "database",
                          "set" => "CNAME"
                        },
                        {
                          "key_is" => "mu_type",
                          "value_is" => "server",
                          "set" => "A"
                        }
                      ]
                  },
                  "alias_zone" => {
                      "type" => "string",
                      "description" => "If using a type of R53ALIAS, this is the hosted zone ID of the target. Defaults to the zone to which this record is being added."
                  },
                  "deploy_id" => {
                    "type" => "string",
                    "description" => "Look for a resource in another Mu deployment with this id. Requires mu_type",
                  },
                  "mu_type" => {
                    "type" => "string",
                    "description" => "The Mu resource type to search the deployment for.",
                      "enum" => ["loadbalancer", "server", "database", "cache_cluster"]
                  },
                  "target_type" => {
                      "description" => "If the target is a public or a private resource. This only applies to servers/server_pools when using automatic DNS registration. If set to public but the target only has a private address, the private address will be used",
                      "type" => "string",
                      "enum" => ["public", "private"]
                  },
                  "weight" => {
                      "type" => "integer",
                      "description" => "Set the proportion of traffic directed to this target, based on the relative weight of other records with the same DNS name and type."
                  },
                  "region" => MU::Config.region_primitive,
                  "failover" => {
                      "type" => "string",
                      "description" => "Failover classification",
                      "enum" => ["PRIMARY", "SECONDARY"]
                  },
                  "ttl" => {
                      "type" => "integer",
                      "description" => "DNS time-to-live value for query caching.",
                      "default" => 7200
                  },
                  "target" => {
                      "type" => "string",
                      "description" => "The value of this record. Must be valid for the 'type' field, e.g. A records must point to an IP address. If creating a record for an existing deployment, specify the mu_name of the resource, you must also specifiy deploy_id and mu_type",
                  },
                  "name" => {
                      "description" => "Name of the record to create. If not specified, will default to the Mu resource name.",
                      "type" => "string",
                      "pattern" => "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
                  },
                  "append_environment_name" => {
                      "description" => "If to append the environment name (eg mydnsname.dev.mudomain.com). to the DNS name",
                      "type" => "boolean",
                      "default" => false
                  },
                  "geo_location" => {
                      "type" => "object",
                      "description" => "Set location for location-based routing.",
                      "additionalProperties" => false,
                      "properties" => {
                          "continent_code" => {
                              "type" => "string",
                              "description" => "The code for a continent geo location. Note: only continent locations have a continent code. Specifying continent_code with either country_code or subdivision_code returns an InvalidInput error.",
                              "enum" => ["AF", "AN", "AS", "EU", "OC", "NA", "SA"]
                          },
                          "country_code" => {
                              "type" => "string",
                              "description" => "The code for a country geo location. The default location uses '' for the country code and will match all locations that are not matched by a geo location. All other country codes follow the ISO 3166 two-character code."
                          },
                          "subdivision_code" => {
                              "type" => "string",
                              "description" => "The code for a country's subdivision (e.g., a province of Canada). A subdivision code is only valid with the appropriate country code. Specifying subdivision_code without country_code returns an InvalidInput error."
                          }
                      }
                  },
                  "healthchecks" => {
                    "type" => "array",
                    "items" => {
                        "type" => "object",
                        "required" => ["method", "name"],
                        "additionalProperties" => false,
                        "description" => "Check used to determine instance health for failover routing.",
                        "properties" => {
                          "method" => {
                              "type" => "string",
                              "description" => "The health check method to use",
                              "enum" => ["HTTP", "HTTPS", "HTTP_STR_MATCH", "HTTPS_STR_MATCH", "TCP", "CALCULATED", "CLOUDWATCH_METRIC"]
                          },
                          "port" => {
                              "type" => "integer",
                              "description" => "Port on which this health check should expect to find a working service.  For HTTP and HTTP_STR_MATCH this defaults to 80 if the port is not specified. For HTTPS and HTTPS_STR_MATCH this defaults to 443 if the port is not specified.",
                          },
                          "path" => {
                              "type" => "string",
                              "description" => "Path to check for HTTP-based health checks."
                          },
                          "type" => {
                            "type" => "string",
                            "description" => "When using CALCULATED based health checks make sure to set only the CALCULATED health check to primary while setting all other health checks to secondary.",
                            "default" => "primary",
                            "enum" => ["primary", "secondary"]
                          },
                          "name" => {
                              "type" => "string",
                              "description" => "The health check name."
                          },
                          "search_string" => {
                              "type" => "string",
                              "description" => "Path to check for STR_MATCH-based health checks."
                          },
                          "check_interval" => {
                              "type" => "integer",
                              "description" => "The frequency of health checks in seconds.",
                              "default" => 30,
                              "enum" => [10, 30]
                          },
                          "failure_threshold" => {
                              "type" => "integer",
                              "description" => "The number of failed health checks before we consider this entry in failure. Values can be between 1-10.",
                              "default" => 2,
                              "pattern" => "^([1-9]|10)$"
                          },
                          "insufficient_data" => {
                            "type" => "string",
                            "description" => "What should the health check status be set to if there is insufficient data return from the CloudWatch alarm. Used only with CLOUDWATCH_METRIC based health checks.",
                            "enum" => ["Healthy", "Unhealthy", "LastKnownStatus"]
                          },
                          "regions" => {
                            "type" => "array",
                            "description" => "The cloud provider's regions from which to test the status of the health check. If not specified will use all regions. Used only with HTTP/HTTPS/TCP based health checks.",
                            "items" => {
                              "type" => "string"
                            }
                          },
                          "latency" => {
                            "description" => "If to measure and graph latency between the health checkers and the endpoint. Used only with HTTP/HTTPS/TCP based health checks.",
                            "type" => "boolean",
                            "default" => false
                          },
                          "inverted" => {
                            "description" => "If the status of the health check should be inverted, eg. if health check status is healthy but you would like it to be evaluated as not healthy",
                            "type" => "boolean",
                            "default" => false
                          },
                          "enable_sni" => {
                            "description" => "Enabled by default on HTTPS or HTTPS_STR_MATCH",
                            "type" => "boolean",
                            "default" => false,
                            "default_if" => [
                              {
                                "key_is" => "method",
                                "value_is" => "HTTPS",
                                "set" => true
                              },
                              {
                                "key_is" => "method",
                                "value_is" => "HTTPS_STR_MATCH",
                                "set" => true
                              }
                            ]
                          },
                          "health_threshold" => {
                            "type" => "integer",
                            "description" => "The minimum number of health checks that must be healthy when configuring a health check of type CALCULATED. Values can be between 0-256.",
                            "default" => 1,
                            "pattern" => "^[\\d]?{3}$"
                          },
                          "health_check_ids" => {
                            "type" => "array",
                            "description" => "The IDs of existing health checks to use when method is set to CALCULATED.",
                            "items" => {
                              "type" => "string"
                            }
                          },
                          "alarm_region" => {
                            "type" => "string",
                            "description" => "The cloud provider's region the cloudwatch alarm was created in. Used with CLOUDWATCH_METRIC health checks"
                          },
                          "alarm_name" => {
                            "type" => "string",
                            "description" => "The cloudwatch alarm name. Used with CLOUDWATCH_METRIC health checks"
                          }
                        }
                    }
                }
              }
          }
        }

        if !need_target
          dns_records_primitive["items"]["required"].delete("target")
          dns_records_primitive["items"]["properties"].delete("target")
        end

        if need_zone
          dns_records_primitive["items"]["required"] << "zone"
          dns_records_primitive["items"]["properties"]["zone"] = {
            "type" => "object",
            "additionalProperties" => false,
            "minProperties" => 1,
            "description" => "The zone to which to add this record, either as a domain name or as a Route53 zone identifier.",
            "properties" => {
                "name" => {
                    "type" => "string",
                    "description" => "The domain name of the DNS zone to which to add this record."
                },
                "id" => {
                    "type" => "string",
                    "description" => "The Route53 identifier of the zone to which to add this record."
                }
            }
          }
        end

        if !default_type.nil?
          dns_records_primitive["items"]["properties"]["type"]["default"] = default_type
          dns_records_primitive["items"]["required"].delete("type")
        end

        return dns_records_primitive
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::dnszones}, bare and unvalidated.
      # @param zone [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(zone, configurator)
        ok = true
        ok
      end
# TODO non-local VPCs are valid, but require an account field, which insertKitten doesn't know anything about
# if !zone['account'].nil? and zone['account'] != MU.account_number

    end
  end
end
