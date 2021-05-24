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
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/loadbalancer.rb
    class LoadBalancer

      # Generate schema for a LoadBalancer health check
      # @return [Hash]
      def self.healthcheck
        {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "The method used by a Load Balancer to check the health of its client nodes.",
          "required" => ["target"],
          "properties" => {
            "target" => {
              "type" => "String",
              "pattern" => "^(TCP:\\d+|SSL:\\d+|HTTP:\\d+\\/.*|HTTPS:\\d+\\/.*)$",
              "description" => 'Specifies the instance being checked. The protocol is either TCP, HTTP, HTTPS, or SSL. The range of valid ports is one (1) through 65535.
        
          TCP is the default, specified as a TCP: port pair, for example "TCP:5000". In this case a healthcheck simply attempts to open a TCP connection to the instance on the specified port. Failure to connect within the configured timeout is considered unhealthy.
        
          SSL is also specified as SSL: port pair, for example, SSL:5000.
        
          For HTTP or HTTPS protocol, the situation is different. You have to include a ping path in the string. HTTP is specified as a HTTP:port;/;PathToPing; grouping, for example "HTTP:80/weather/us/wa/seattle". In this case, a HTTP GET request is issued to the instance on the given port and path. Any answer other than "200 OK" within the timeout period is considered unhealthy.
        
          The total length of the HTTP ping target needs to be 1024 16-bit Unicode characters or less.'
            },
            "timeout" => {
              "type" => "integer",
              "default" => 5
            },
            "interval" => {
              "type" => "integer",
              "default" => 30
            },
            "unhealthy_threshold" => {
              "type" => "integer",
              "default" => 2
            },
            "healthy_threshold" => {
              "type" => "integer",
              "default" => 10
            },
            "httpcode" => {
              "type" => "string",
              "default" => "200,301,302",
              "description" => "The HTTP codes to use when checking for a successful response from a target."
            }
          }
        }
      end

      # Generate schema for a LoadBalancer redirect
      # @return [Hash]
      def self.redirect
        {
          "type" => "object",
          "title" => "redirect",
          "additionalProperties" => false,
          "description" => "Instruct our LoadBalancer to redirect traffic to another host, port, and/or path.",
          "properties" => {
            "protocol" => {
              "type" => "string",
              "default" => "HTTPS"
            },
            "port" => {
              "type" => "integer",
              "default" => 443
            },
            "host" => {
              "type" => "string",
              "default" => "\#{host}"
            },
            "path" => {
              "type" => "string",
              "default" => "/\#{path}"
            },
            "query" => {
              "type" => "string",
              "default" => "\#{query}"
            },
            "status_code" => {
              "type" => "integer",
              "description" => "The HTTP status code when issuing a redirect",
              "default" => 301,
              "enum" => [301, 302]
            },
          }
        }
      end

      # Base configuration schema for a LoadBalancer
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "title" => "loadbalancer",
          "description" => "Create Load Balancers",
          "required" => ["name", "listeners", "cloud"],
          "properties" => {
            "name" => {
                "type" => "string",
                "description" => "Note that Amazon Elastic Load Balancer names must be relatively short. Brevity is recommended here."
            },
            "override_name" => {
                "type" => "string",
                "description" => "Normally an ELB's Amazon identifier will be named the same as its internal Mu identifier. This allows you to override that name with a specific value. Note that Amazon Elastic Load Balancer names must be relatively short. Brevity is recommended here. Note also that setting a static name here may result in deploy failures due to name collision with existing ELBs."
            },
            "classic" => {
                "type" => "boolean",
                "default" => false,
                "description" => "For AWS Load Balancers, revert to the old API instead ElasticLoadbalancingV2 (ALBs)"
            },
            "scrub_mu_isms" => {
                "type" => "boolean",
                "default" => false,
                "description" => "When 'cloud' is set to 'CloudFormation,' use this flag to strip out Mu-specific artifacts (tags, standard userdata, naming conventions, etc) to yield a clean, source-agnostic template."
            },
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => MU::Config.optional_tags_primitive,
            "add_firewall_rules" => {
              "type" => "array",
              "items" => MU::Config::FirewallRule.reference,
            },
            "dns_records" => MU::Config::DNSZone.records_primitive(need_target: false, default_type: "R53ALIAS", need_zone: true),
            "dns_sync_wait" => {
                "type" => "boolean",
                "description" => "Wait for DNS record to propagate in DNS Zone.",
                "default" => true,
            },
            "alarms" => MU::Config::Alarm.inline,
            "ingress_rules" => {
              "type" => "array",
              "items" => MU::Config::FirewallRule.ruleschema
            },
            "region" => MU::Config.region_primitive,
            "cross_zone_unstickiness" => {
                "type" => "boolean",
                "default" => false,
                "description" => "Set true to disable Cross-Zone load balancing, which we enable by default: http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/how-elb-works.html#request-routing"
            },
            "idle_timeout" => {
                "type" => "integer",
                "description" => "Specifies the time (in seconds) the connection is allowed to be idle (no data has been sent over the connection) before it is closed by the load balancer.",
                "default" => 60
            },
            "lb_cookie_stickiness_policy" => {
                "type" => "object",
                "additionalProperties" => false,
                "description" => "Creates a cookie to tie client sessions to back-end servers. Only valid with HTTP/HTTPS listeners.",
                "required" => ["name"],
                "properties" => {
                    "name" => {
                        "type" => "string",
                        "description" => "The name of this policy.",
                        "pattern" => "^([a-zA-Z0-9\\-]+)$"
                    },
                    "timeout" => {
                        "type" => "integer",
                        "description" => "The time period in seconds after which the cookie should be considered stale. Not specifying this parameter indicates that the sticky session will last for the duration of the browser session."
                    }
                }
            },
            "ip_stickiness_policy" => {
                "type" => "object",
                "additionalProperties" => false,
                "description" => "Use IP addresses or IP/port/proto combinations to map client sessions to back-end servers. Only valid with Google Cloud, and is ignored for UDP-based listeners.",
                "properties" => {
                    "map_proto" => {
                        "type" => "boolean",
                        "default" => false,
                        "description" => "Include the client protocol as well as the IP when determining session affinity. Only valid for internal load balancers."
                    },
                    "map_port" => {
                        "type" => "boolean",
                        "default" => false,
                        "description" => "Include the client port as well as the IP when determining session affinity. Only valid for internal load balancers, and only in combination with map_proto."
                    }
                }
            },
            "app_cookie_stickiness_policy" => {
                "type" => "object",
                "additionalProperties" => false,
                "description" => "Use an application cookie to tie client sessions to back-end servers. Only valid with HTTP/HTTPS listeners, on AWS.",
                "required" => ["name", "cookie"],
                "properties" => {
                    "name" => {
                        "type" => "string",
                        "description" => "The name of this policy.",
                        "pattern" => "^([a-zA-Z0-9\\-]+)$"
                    },
                    "cookie" => {
                        "type" => "string",
                        "description" => "The name of an application cookie to use for session tracking."
                    }
                }
            },
            "connection_draining_timeout" => {
                "type" => "integer",
                "description" => "Permits the load balancer to complete connections to unhealthy backend instances before retiring them fully. Timeout is in seconds; set to -1 to disable.",
                "default" => -1
            },
            "private" => {
                "type" => "boolean",
                "default" => false,
                "description" => "Set to true if this ELB should only be assigned a private IP address (no public interface)."
            },
            "global" => {
                "type" => "boolean",
                "default" => true,
                "description" => "Google Cloud only. Deploy as a global artifact instead of in a specific region. Not valid for UDP targets."
            },
            "vpc" => MU::Config::VPC.reference(MU::Config::VPC::MANY_SUBNETS, MU::Config::VPC::NO_NAT_OPTS, "all_public"),
            "zones" => {
                "type" => "array",
                "minItems" => 1,
                "description" => "Availability Zones in which this Load Balancer can operate. Specified Availability Zones must be in the same EC2 Region as the load balancer. Traffic will be equally distributed across all zones. If no zones are specified, we'll use all zones in the current region.",
                "items" => {
                    "type" => "string"
                }
            },
            "access_log" => {
              "type" => "object",
                "additionalProperties" => false,
                "description" => "Access logging for Load Balancer requests.",
                "required" => ["enabled", "s3_bucket_name"],
                "properties" => {
                "enabled" => {
                  "type" => "boolean",
                  "description" => "Toggle access log publishing.",
                  "default" => false
                },
                "s3_bucket_name" => {
                  "type" => "string",
                  "description" => "The Amazon S3 bucket to which to publish access logs."
                },
                "s3_bucket_prefix" => {
                  "type" => "string",
                  "default" => "",
                  "description" => "The path within the S3 bucket to which to publish the logs."
                },
                "emit_interval" => {
                  "type" => "integer",
                  "description" => "How frequently to publish access logs.",
                  "enum" => [5, 60],
                  "default" => 60
                }
              }
            },
            # 'healthcheck' was a first-class parmeter for classic ELBs, but is
            # embedded inside targetgroups for ALBs. In Google, they can be
            # even more arbitrary, so we also allow you to embed them with
            # listeners.
            "healthcheck" => healthcheck,
            "targetgroups" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "additionalProperties" => false,
                "description" => "A grouping of ",
                "required" => ["name", "proto", "port"],
                "properties" => {
                  "healthcheck" => healthcheck,
                  "name" => {
                    "type" => "string"
                  },
                  "proto" => {
                    "type" => "string",
                    "enum" => ["HTTP", "HTTPS"],
                  },
                  "httpcode" => {
                    "type" => "string",
                    "default" => "200,301,302",
                    "description" => "The HTTP codes to use when checking for a successful response from a target."
                  },
                  "port" => {
                    "type" => "integer",
                    "minimum" => 1,
                    "maximum" => 65535,
                    "description" => "Specifies the TCP port on which the instance server is listening. This property cannot be modified for the life of the load balancer."
                  }
                }
              }
            },
            "listeners" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "required" => ["lb_protocol", "lb_port"],
                "additionalProperties" => false,
                "description" => "A list of port/protocols which this Load Balancer should answer.",
                "properties" => {
                  "healthcheck" => healthcheck,
                  "lb_port" => {
                    "type" => "integer",
                    "description" => "Specifies the external load balancer port number. This property cannot be modified for the life of the load balancer."
                  },
                  "instance_port" => {
                    "type" => "integer",
                    "description" => "Specifies the TCP port on which the instance server is listening. This property cannot be modified for the life of the load balancer."
                  },
                  "lb_protocol" => {
                    "type" => "string",
                    "enum" => ["HTTP", "HTTPS", "TCP", "SSL", "UDP"],
                    "description" => "Specifies the load balancer transport protocol to use for routing - HTTP, HTTPS, TCP, SSL, or UDP. SSL and UDP are only valid in Google Cloud."
                  },
                  "redirect" => MU::Config::LoadBalancer.redirect,
                  "targetgroup" => {
                    "type" => "string",
                    "description" => "Which of our declared targetgroups should be the back-end for this listener's traffic"
                  },
                  "instance_protocol" => {
                    "type" => "string",
                    "enum" => ["HTTP", "HTTPS", "TCP", "SSL", "UDP"],
                    "description" => "Specifies the protocol to use for routing traffic to back-end instances - HTTP, HTTPS, TCP, or SSL. This property cannot be modified for the life of the load balancer.

            If the front-end protocol is HTTP or HTTPS, InstanceProtocol has to be at the same protocol layer, i.e., HTTP or HTTPS. Likewise, if the front-end protocol is TCP or SSL, InstanceProtocol has to be TCP or SSL."
                  },
                  "ssl_certificate_name" => {
                    "type" => "string",
                    "description" => "The name of a server certificate."
                  },
                  "ssl_certificate_id" => {
                    "type" => "string",
                    "description" => "The ARN string of an Amazon IAM server certificate."
                  },
                  "tls_policy" => {
                    "type" => "string",
                    "description" => "Lowest level of TLS to support.",
                    "default" => "tls1.2",
                    "enum" => ["tls1.0", "tls1.1", "tls1.2"]
                  },
                  "rules" => {
                    "type" => "array",
                    "items" => {
                      "type" => "object",
                      "description" => "Rules to route requests to different target groups based on the request path",
                      "required" => ["order", "conditions"],
                      "additionalProperties" => false,
                      "properties" => {
                        "conditions" => {
                          "type" => "array",
                          "items" => {
                            "type" => "object",
                            "description" => "Rule conditionl; if none are specified (or if none match) the default action will be set.",
                            "required" => ["field", "values"],
                            "additionalProperties" => false,
                            "properties" => {
                              "field" => {
                                "type" => "string",
                                "default" => "path-pattern",
                                "enum" => ["path-pattern"]
                              },
                              "values" => {
                                "type" => "array",
                                "items" => {
                                  "type" => "string",
                                  "description" => "A pattern to match against for this field."
                                }
                              }
                            }
                          }
                        },
                        "actions" => {
                          "type" => "array",
                          "items" => {
                            "type" => "object",
                            "description" => "Rule action, which must specify one of +targetgroup+ or +redirect+",
                            "required" => ["action"],
                            "additionalProperties" => false,
                            "properties" => {
                              "action" => {
                                "type" => "string",
                                "default" => "forward",
                                "description" => "An action to take when a match occurs. Currently, only forwarding to a targetgroup is supported.",
                                "enum" => ["forward", "redirect"]
                              },
                              "redirect" => MU::Config::LoadBalancer.redirect,
                              "targetgroup" => {
                                "type" => "string",
                                "description" => "Which of our declared targetgroups should be the recipient of this traffic. If left unspecified, will default to the default targetgroup of this listener."
                              }
                            }
                          }
                        },
                        "order" => {
                          "type" => "integer",
                          "default" => 1,
                          "description" => "The priority for the rule. Use to order processing relative to other rules."
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      end

      # Schema block for other resources to use when referencing a sibling LoadBalancer
      # @return [Hash]
      def self.reference
        schema_aliases = [
          { "concurrent_load_balancer" => "name" },
          { "existing_load_balancer" => "id" }
        ]
        MU::Config::Ref.schema(schema_aliases, type: "loadbalancers")
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::loadbalancers}, bare and unvalidated.
      # @param lb [Hash]: The resource to process and validate
      # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(lb, _configurator)
        ok = true
        # Convert old-school listener declarations into target groups and health
        # checks, for which AWS and Google both have equivalents.
        if lb["targetgroups"].nil? or lb["targetgroups"].size == 0
          if lb["listeners"].nil? or lb["listeners"].size == 0
            ok = false
            MU.log "No targetgroups or listeners defined in LoadBalancer #{lb['name']}", MU::ERR
          end
          lb["targetgroups"] = []

          # Manufacture targetgroups out of old-style listener configs
          lb["listeners"].each { |l|
            tgname = lb["name"]+l["lb_protocol"].downcase+l["lb_port"].to_s
            l["targetgroup"] = tgname
            tg = { 
              "name" => tgname,
              "proto" => l["instance_protocol"] || l["lb_protocol"],
              "port" => l["instance_port"] || l["lb_port"]
            }
            if l["redirect"]
              tg["proto"] ||= l["redirect"]["protocol"]
              tg["port"] ||= l["redirect"]["port"]
            end
            tg["vpc"] = l["vpc"] if l["vpc"]
            l['healthcheck'] ||= lb['healthcheck'] if lb['healthcheck']
            if l["healthcheck"]
              hc_target = l['healthcheck']['target'].match(/^([^:]+):(\d+)(.*)/)
              tg["healthcheck"] = l['healthcheck'].dup
              proto = ["HTTP", "HTTPS"].include?(hc_target[1]) ? hc_target[1] : l["instance_protocol"]
              tg['healthcheck']['target'] = "#{proto}:#{hc_target[2]}#{hc_target[3]}"
              tg['healthcheck']["httpcode"] = "200,301,302"
              MU.log "Converting classic-style ELB health check target #{l['healthcheck']['target']} to ALB style for target group #{tgname} (#{l["instance_protocol"]}:#{l["instance_port"]}).", details: tg['healthcheck']
            end
            lb["targetgroups"] << tg
          }
        elsif lb['listeners'].nil?
          # well ok, manufacture listeners out of targetgroups then?
          lb['listeners'] ||= []
          lb["targetgroups"].each { |tg|
            listener = {
              "targetgroup" => tg['name'],
              "lb_protocol" => tg["proto"],
              "lb_port" => tg["port"]
            }
            listener["vpc"] = tg["vpc"] if tg["vpc"]
            lb['listeners'] << listener
          }
        else
          lb['listeners'].each { |l|
            found = false
            lb['targetgroups'].each { |tg|
              if l['targetgroup'] == tg['name']
                found = true
                break
              end
            }
            if !found
              ok = false
              MU.log "listener in LoadBalancer #{lb['name']} refers to targetgroup #{l['targetgroup']}, but no such targetgroup found", MU::ERR
            end
          }
        end

        lb['targetgroups'].each { |tg|
          if tg['target']
            tg['target']['cloud'] ||= lb['cloud']
            if tg['target']['name']
              MU::Config.addDependency(lb, tg['target']['name'], tg['target']['type'], their_phase: "create", my_phase: "groom")
            end
          end
        }

        lb['listeners'].each { |l|
          if !l['rules'].nil? and l['rules'].size > 0
            l['rules'].each { |r|
              if r['actions'].nil?
                r['actions'] = [
                  { "targetgroup" => l["targetgroup"], "action" => "forward" }
                ]
                next
              end
              r['actions'].each { |action|
                if action['targetgroup'].nil?
                  action['targetgroup'] = l['targetgroup']
                else
                  found = false
                  lb['targetgroups'].each { |tg|
                    if tg['name'] == action['targetgroup']
                      found = true
                      break
                    end
                  }
                  if !found
                    ok = false
                    MU.log "listener action in LoadBalancer #{lb['name']} refers to targetgroup #{action['targetgroup']}, but no such targetgroup found", MU::ERR
                  end
                end
              }
            }
          end
        }
        ok
      end

    end
  end
end
