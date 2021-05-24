# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
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
    class Google
      # A load balancer as configured in {MU::Config::BasketofKittens::loadbalancers}
      class LoadBalancer < MU::Cloud::LoadBalancer

        @lb = nil

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          parent_thread_id = Thread.current.object_id

          backends = {}
          targets = {}
          if @config['targetgroups']
            threads = []
            @config['targetgroups'].each { |tg|
              threads << Thread.new {
                MU.dupGlobals(parent_thread_id)
                vpc_obj = myVpc(tg['vpc']).first if tg['vpc'] # XXX inherit top-level vpc config if it's set

#                if !@config['private'] or ["INTERNAL_MANAGED", "INTERNAL_SELF_MANAGED"].include?(@config['scheme'])
                  backends[tg['name']] = createBackendService(tg)
                  targets[tg['name']] = createProxy(tg, backends[tg['name']], region: (@config['global'] ? nil : @config['region']))
#                end
              }
            }
            threads.each do |t|
              t.join
            end
          end

          @cloud_id = @mu_name
MU.log "backends", MU::WARN, details: backends
MU.log "targets", MU::WARN, details: targets
          @config["listeners"].each { |l|
            ruleobj = ::Google::Apis::ComputeV1::ForwardingRule.new(
              name: MU::Cloud::Google.nameStr(@mu_name+"-"+l['targetgroup']),
              description: @deploy.deploy_id,
              load_balancing_scheme: @config['scheme']
            )

            if ["INTERNAL_MANAGED", "INTERNAL_SELF_MANAGED"].include?(@config['scheme'])
              ruleobj.ip_protocol = "TCP"
              ruleobj.all_ports = true
            else
              if @config["private"]
                ruleobj.ports = [l['lb_port'].to_s]
                ruleobj.ip_protocol = l['lb_protocol']
              else
                ruleobj.ip_protocol = ["HTTP", "HTTPS"].include?(l['lb_protocol']) ? l['lb_protocol'] : "TCP"
                ruleobj.port_range = l['lb_port'].to_s
              end
            end

            if @config['private'] and l['vpc'] # XXX inherit top-level vpc config if it's set
              vpc_obj, _n = myVpc(l['vpc'])
              ruleobj.network = vpc_obj.url.sub(/^.*?\/projects\//, 'projects/')
              ruleobj.subnetwork = mySubnets(vpc_obj, l["vpc"]).first.url
            end

            if targets[l['targetgroup']]
              ruleobj.target = targets[l['targetgroup']].self_link
            else
              ruleobj.backend_service = backends[l['targetgroup']].self_link
            end

            @cloud_desc_cache ||= {}
            if @config['global']
              MU.log "Creating Global Forwarding Rule #{@mu_name}", MU::NOTICE, details: ruleobj
              MU::Cloud::Google.compute(credentials: @config['credentials']).insert_global_forwarding_rule(
                @project_id,
                ruleobj
              )
            else
              MU.log "Creating regional Forwarding Rule #{@mu_name} in #{@config['region']}", MU::NOTICE, details: ruleobj
              MU::Cloud::Google.compute(credentials: @config['credentials']).insert_forwarding_rule(
                @project_id,
                @config['region'],
                ruleobj
              )
            end
          }

        end

        def groom
          if @config['targetgroups']
            @config['targetgroups'].each { |tg|
              if tg['target']
MU.log "le fuckerie", MU::WARN, details: tg['target']
pp cloud_desc
pp @backend_cache
                pp createNetworkEndpointGroup(tg['name'], tg['target'], region: @config['region'])
              end
            }
          end
        end

        @cloud_desc_cache = nil
        @backend_cache = nil
        # Return the cloud descriptor for this LoadBalancer, or specifically
        # its forwarding rule(s) since there's really no one artifact.
        # @return [Google::Apis::Core::Hashable]
        def cloud_desc(use_cache: true)
          return @cloud_desc_cache if @cloud_desc_cache and use_cache
          rules = {}

          @config["listeners"].each { |l|
            name = MU::Cloud::Google.nameStr(@cloud_id+"-"+l['targetgroup'])
            rule = if @config['global']
              MU::Cloud::Google.compute(credentials: @config['credentials']).get_global_forwarding_rule(
                @project_id,
                name
              )
            else
              MU::Cloud::Google.compute(credentials: @config['credentials']).get_forwarding_rule(
                @project_id,
                @config['region'],
                name
              )
            end
            rule = rule.first if !rule.respond_to?(:name)
            rules[rule.name] = rule
            if rule.respond_to?(:backend_service) and !rule.backend_service.nil?
              @backend_cache ||= []
              @backend_cache << rule.backend_service.gsub(/.*?\//, '')
            elsif rule.respond_to?(:target) and !rule.target.nil?
              proxy = self.class.desc_from_url(rule.target, @project_id, credentials: @credentials)
puts PP.pp(proxy, '').magenta
              if proxy.respond_to?(:url_map) and !proxy.url_map.nil?
                urlmap = self.class.desc_from_url(proxy.url_map, @project_id, credentials: @credentials)
                if urlmap.respond_to?(:default_service) and !urlmap.default_service.nil?
                  backend = self.class.desc_from_url(urlmap.default_service, @project_id, credentials: @credentials)
                  @backend_cache ||= []
                  @backend_cache << backend.name
                end
              end
            end
          }
          rules = nil if rules.empty?
          @backend_cache.uniq! if @backend_cache
          @cloud_desc_cache = rules

          rules
        end


        # Return the metadata for this LoadBalancer
        # @return [Hash]
        def notify
          rules = cloud_desc(use_cache: false)
          if rules
            rules.each_pair { |name, rule|
              rules[name] = MU.structToHash(rule, stringify_keys: true)
              rules[name].delete("label_fingerprint")
              rules[name].delete("fingerprint")
            }
          end
          rules["project_id"] = @project_id

          rules
        end

        # Register a Server node with an existing LoadBalancer.
        #
        # @param target [String] A node or URL or something to register.
        # @param backends [Array<String>] The target group(s) of which this node should be made a member.
        def registerTarget(target, backends: nil)
          pp target
          neg_desc = createNetworkEndpointGroup(tg['name'], tg['target'])
pp cloud_desc
          describeBackends.each { |b|
            next if backends and !backends.include?(b.name)
MU.log "Google LB registerTarget called for #{target}", MU::WARN, details: b
            b.backends ||= []
b.health_checks = [] # XXX this is a SERVERLESS thing
            b.backends << MU::Cloud::Google.compute(:Backend).new(
              group: target
            )
            MU.log "Adding backend service #{b.name}"
            if @config['private'] and !@config['global']
              MU::Cloud::Google.compute(credentials: @credentials).update_region_backend_service(@project_id, @config['region'], b.name, b)
            else
              MU::Cloud::Google.compute(credentials: @credentials).update_backend_services(@project_id, b.name, b)
            end
          }

        end

        def describeBackends
          resp = if @config['private'] and !@config['global']
            MU::Cloud::Google.compute(credentials: @credentials).list_region_backend_services(@project_id, @config['region'], filter: "description = \"#{@deploy.deploy_id}\"")
          else
            MU::Cloud::Google.compute(credentials: @credentials).list_backend_services(@project_id, filter: "description = \"#{@deploy.deploy_id}\"")
          end
          return [] if !resp

          resp.items.reject { |b| !@backend_cache.include?(b.name) }
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false # XXX it's both, actually
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::RELEASE
        end

        # Remove all load balancers associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: nil, credentials: nil, flags: {})
          flags["habitat"] ||= MU::Cloud::Google.defaultProject(credentials)

          return if !MU::Cloud.resourceClass("Google", "Habitat").isLive?(flags["habitat"], credentials)
          filter = %Q{(labels.mu-id = "#{MU.deploy_id.downcase}")}
          if !ignoremaster and MU.mu_public_ip
            filter += %Q{ AND (labels.mu-master-ip = "#{MU.mu_public_ip.gsub(/\./, "_")}")}
          end
          MU.log "Placeholder: Google LoadBalancer artifacts do not support labels, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: filter

          if region
            # Network Endpoint Groups don't have labels, so our deploy id gets
            # shoved into the description.
            resp = MU::Cloud::Google.compute(credentials: credentials).list_region_network_endpoint_groups(flags["habitat"], region, filter: "description eq #{deploy_id}")
            if resp and resp.items
              resp.items.each { |neg|
                MU.log "Removing regional Network Endpoint Group #{neg.name}"
                MU::Cloud::Google.compute(credentials: credentials).delete_region_network_endpoint_group(flags["habitat"], region, neg.name) if !noop
              }
            end

            ["forwarding_rule", "region_backend_service", "network_endpoint_group"].each { |type|
              MU::Cloud::Google.compute(credentials: credentials).delete(
                type,
                flags["habitat"],
                region,
                noop,
                filter
              )
            }
          end

#          if flags['global']
#            resp = MU::Cloud::Google.compute(credentials: credentials).list_network_endpoint_groups(flags["habitat"], filter: "description eq #{deploy_id}")
#            resp.items.each { |neg|
#              MU.log "Removing Network Endpoint Group #{neg.name}"
#              MU::Cloud::Google.compute(credentials: credentials).delete_network_endpoint_group(flags["habitat"], neg.name) if !noop
#            }

            ["global_forwarding_rule", "target_tcp_proxy", "target_grpc_proxy", "target_ssl_proxy", "target_http_proxy", "target_https_proxy", "url_map", "backend_service", "network_endpoint_group", "health_check", "http_health_check", "https_health_check"].each { |type|
              MU::Cloud::Google.compute(credentials: credentials).delete(
                type,
                flags["habitat"],
                nil,
                noop,
                filter
              )
            }
#          end
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "targetgroups" => {
              "items" => {
                "properties" => {
                  "proto" => {
                    "enum" => ["HTTP", "HTTPS", "TCP", "SSL", "GRPC"]
                  },
                  "target" => MU::Config::Ref.schema(parent_obj: "loadbalancer", type: "functions"),
                  "vpc" => MU::Config::VPC.reference(MU::Config::VPC::ONE_SUBNET, MU::Config::VPC::NO_NAT_OPTS, "public")
                }
              }
            },
            "listeners" => {
              "items" => {
                "properties" => {
                  "vpc" => MU::Config::VPC.reference(MU::Config::VPC::ONE_SUBNET, MU::Config::VPC::NO_NAT_OPTS, "public")
                }
              }
            },
            "scheme" => {
              "type" => "string",
              "enum" => ["EXTERNAL", "INTERNAL", "INTERNAL_MANAGED", "INTERNAL_SELF_MANAGED"],
              "description" => "Choose +EXTERNAL+ for external HTTP(S), SSL Proxy, TCP Proxy and Network Load Balancing; +INTERNAL+ for Internal TCP/ UDP Load Balancing; +INTERNAL_MANAGED+ for Internal HTTP(S) Load Balancing; +INTERNAL_SELF_MANAGED+ for Traffic Director. If not specified, will default to +EXTERNAL+ or +INTERNAL+ depending on the value of the {private} flag."
            },
            "named_ports" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "required" => ["name", "port"],
                "additionalProperties" => false,
                "description" => "A named network port for a Google instance group, used for health checks and forwarding targets.",
                "properties" => {
                  "name" => {
                    "type" => "string"
                  },
                  "port" => {
                    "type" => "integer"
                  }
                }
              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::loadbalancers}, bare and unvalidated.
        # @param lb [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(lb, _configurator)
          ok = true

          lb['region'] ||= MU::Cloud::Google.myRegion(lb['credentials'])

          if lb['classic']
            MU.log "LoadBalancer 'classic' flag has no meaning in Google Cloud", MU::WARN
          end

          if lb['app_cookie_stickiness_policy']
            MU.log "LoadBalancer 'app_cookie_stickiness_policy' option has no meaning in Google Cloud", MU::WARN
            lb.delete('app_cookie_stickiness_policy')
          end
          if lb['ip_stickiness_policy'] 
            if !lb['private']
              if lb['ip_stickiness_policy']['map_port']
                MU.log "Can only use map_port in IP stickiness policy with private LoadBalancers", MU::ERR
                ok = false
              end
              if lb['ip_stickiness_policy']['map_proto']
                MU.log "Can only use map_proto in IP stickiness policy with private LoadBalancers", MU::ERR
                ok = false
              end
            elsif lb['ip_stickiness_policy']['map_port'] and !lb['ip_stickiness_policy']['map_proto']
              MU.log "Can't use map_port in IP stickiness policy without map_proto", MU::ERR
              ok = false
            end
          end

          if lb['private'] and lb['global']
            MU.log "Private Google Cloud LoadBalancer requested, setting 'global' flag to false", MU::DEBUG
            lb['global'] = false
          end

          lb['scheme'] ||= lb['private'] ? "INTERNAL" : "EXTERNAL"

          lb["listeners"].each { |l|
            if lb['scheme'] == "INTERNAL" and !["TCP", "UDP"].include?(l['lb_protocol'])
#              MU.log "Only TCP and UDP listeners are valid for private LoadBalancers in Google Cloud", MU::ERR
#              ok = false
            end
            l['instance_protocol'] ||= l['lb_protocol']
            l['instance_port'] ||= l['lb_port']

            if lb['global'] and l['lb_protocol'] == "UDP"
              MU.log "UDP LoadBalancers can only be per-region in Google Cloud. Setting 'global' to false.", MU::WARN
              lb['global'] = false
            end
            if lb['global'] and !["HTTP", "HTTPS"].include?(l['instance_protocol'])
              MU.log "Global LoadBalancers in Google Cloud can only target HTTP or HTTPS backends", MU::ERR, details: l
              ok = false
            end
          }

          if lb['scheme'] != "INTERNAL_MANAGED"
            lb["targetgroups"].each { |tg|
              if tg["healthcheck"]
                target = tg["healthcheck"]['target'].match(/^([^:]+):(\d+)(.*)/)
                if tg["proto"] != target[1]
                  MU.log "LoadBalancer #{lb['name']} can't mix and match target group and health check protocols in Google Cloud", MU::ERR, details: tg
                  ok = false
                end
              else
                # health checks are required; create a generic one
                tg["healthcheck"] = {
                  "timeout" => 5,
                  "interval" => 30,
                  "unhealthy_threshold" => 2,
                  "healthy_threshold" => 2,
                }
                if tg["proto"] == "HTTP" or tg["proto"] == "HTTPS"
                  if lb['scheme'] == "INTERNAL"
                    MU.log "INTERNAL GCP LoadBalancers can only target TCP or UDP protocols, changing #{tg["proto"]} to TCP", MU::NOTICE
                    tg["proto"] = "TCP"
                  end
                  tg["healthcheck"]["target"] = tg["proto"]+":"+tg["port"].to_s+"/"
                  tg["healthcheck"]["httpcode"] = "200,301,302"
                else
                  tg["healthcheck"]["target"] = tg["proto"]+":"+tg["port"].to_s
                end
                MU.log "No healthcheck declared for target group #{tg['name']} in LoadBalancer #{lb['name']}, creating one.", details: tg
              end
            }
          end

          ok
        end

        # Locate an existing LoadBalancer or LoadBalancers and return an array containing matching Google resource descriptors for those that match.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching LoadBalancers
        def self.find(**args)
          args = MU::Cloud::Google.findLocationArgs(args)
        end

        private

        # Construct the method call to fetch descriptors for various backend
        # components out of the chunks in a URL, as it might be referenced from
        # another resource.
        def self.desc_from_url(url, project_id, credentials: nil)
          regions = MU::Cloud::Google.listRegions + ["global"]
          loc_pattern = "("+regions.map { |r|
            'regions\/'+Regexp.quote(r)
          }.join("|")+"|global)"
          args = []
          resource_name = nil
          url =~ /\/projects\/#{Regexp.quote(project_id)}\/(#{loc_pattern})\//
          location = Regexp.last_match[1]
          global = (location == "global")
          region = global ? nil : location.sub(/regions\//, '')

          if url =~ /\/#{location}\/target(Https?|Http|Ssl|Grpc|Tcp)Proxies\/([^\/]+)$/i
            proxytype = Regexp.last_match[1]
            resource_name = Regexp.last_match[2]
            args << "get_#{global ? "" : "region_"}target_#{proxytype.downcase}_proxy".to_sym
          elsif url =~ /\/#{location}\/urlMaps\/([^\/]+)$/i
            resource_name = Regexp.last_match[1]
            args << "get_#{global ? "" : "region_"}url_map".to_sym
          elsif url =~ /\/#{location}\/backendServices\/([^\/]+)$/i
            resource_name = Regexp.last_match[1]
            args << "get_#{global ? "" : "region_"}backend_service".to_sym
          else
            MU.log "I don't know how to extract a resource from #{url}", MU::ERR
          end
          args << project_id
          args << region if !global and region
          args << resource_name

          MU::Cloud::Google.compute(credentials: credentials).send(*args)
        end

        def createProxy(tg, backend, region: nil)
          name = MU::Cloud::Google.nameStr(@deploy.getResourceName(tg["name"]))

          desc = {
            :name => name,
            :description => @deploy.deploy_id,
          }

          realproto = @config['scheme'] == "INTERNAL_MANAGED" ? "TCP" : tg['proto']
          proxytype = ("Target"+realproto.capitalize+"Proxy").to_sym

          if ["HTTPS", "SSL"].include?(realproto)
            certdata = @deploy.nodeSSLCerts(self, false, 2048)
            cert_pem = certdata[0].to_s+File.read("/etc/pki/Mu_CA.pem")
            gcpcert = MU::Cloud::Google.createSSLCertificate(@mu_name.downcase+"-"+tg['name'], cert_pem, certdata[1], credentials: @config['credentials'])

# TODO we need a method like MU::Cloud::AWS.findSSLCertificate, with option to hunt down an existing one
            desc[:ssl_certificates] = [gcpcert.self_link]
          elsif realproto == "TCP"
            desc[:service] = backend.self_link
          end

          if ["HTTP", "HTTPS"].include?(realproto)
            urlmap_obj = MU::Cloud::Google.compute(:UrlMap).new(
              name: name,
              description: @deploy.deploy_id,
# TODO this is where path_matchers, host_rules, and tests go (the sophisticated
# Layer 7 stuff)
              default_service: backend.self_link
            )
            MU.log "Creating #{region ? region+" " : ""}url map #{tg['name']}", details: urlmap_obj

            urlmap = if region
              MU::Cloud::Google.compute(credentials: @config['credentials']).insert_region_url_map(
                @project_id,
                region,
                urlmap_obj
              )
            else
              MU::Cloud::Google.compute(credentials: @config['credentials']).insert_url_map(
                @project_id,
                urlmap_obj
              )
            end
            desc[:url_map] = urlmap.self_link
          end

          target_obj = MU::Cloud::Google.compute(proxytype).new(desc)
          MU.log "Creating #{region ? region+" " : ""}#{realproto} target proxy #{tg['name']}", details: target_obj

          if region and ["HTTP", "HTTPS"].include?(realproto)
            MU::Cloud::Google.compute(credentials: @config['credentials']).send(("insert_region_target_"+realproto.downcase+"_proxy").to_sym, @project_id, region, target_obj)
          else
            MU::Cloud::Google.compute(credentials: @config['credentials']).send(("insert_target_"+realproto.downcase+"_proxy").to_sym, @project_id, target_obj)
          end

        end

        def createNetworkEndpointGroup(basename, target, region: nil, type: "SERVERLESS", vpc: nil)
          function = MU::Config::Ref.get(target).kitten
          if !function
            MU::Config::Ref.get(target).kitten(debug: true)
            raise MuError.new "Failed to locate Cloud Function from reference", details: target
          end
#          pp target
#          pp function.cloud_desc
          neg_name = @deploy.getResourceName(basename, max_length: 19, never_gen_unique: true).downcase
          begin
            if region
              MU::Cloud::Google.compute(credentials: @config['credentials']).get_region_network_endpoint_group(@project_id, @config['region'], neg_name)
            else
              MU::Cloud::Google.compute(credentials: @config['credentials']).get_global_network_endpoint_group(@project_id, neg_name)
            end
          rescue ::Google::Apis::ClientError => e
            raise e if e.message !~ /notFound:/
            neg_obj = MU::Cloud::Google.compute(:NetworkEndpointGroup).new(
              name: neg_name,
              description: @deploy.deploy_id,
              cloud_function: MU::Cloud::Google.compute(:NetworkEndpointGroupCloudFunction).new(
                function: function.cloud_id.gsub(/.*?\//, '')
              ),
              network_endpoint_type: type
            )
            neg_obj.network = vpc.url if vpc and type != "SERVERLESS"
            MU.log "Creating Network Endpoint Group #{neg_name}", details: neg_obj
            if region
              MU::Cloud::Google.compute(credentials: @config['credentials']).insert_region_network_endpoint_group(@project_id, @config['region'], neg_obj)
            else
              MU::Cloud::Google.compute(credentials: @config['credentials']).insert_global_network_endpoint_group(@project_id, neg_obj)
            end
            retry
          end

        end

        def createBackendService(tg)
          desc = {
            :name => MU::Cloud::Google.nameStr(@deploy.getResourceName(tg["name"])),
            :description => @deploy.deploy_id,
            :load_balancing_scheme => @config['scheme'],
            :global => @config['global'],
            :protocol => tg['proto'],
            :timeout_sec => @config['idle_timeout']
          }
# TODO EXTERNAL only: port_name, enable_cdn
          if @config['connection_draining_timeout'] > 0
            desc[:connection_draining] = MU::Cloud::Google.compute(:ConnectionDraining).new(
              draining_timeout_sec: @config['connection_draining_timeout']
            )
          end
          if @config['lb_cookie_stickiness_policy'] and !@config["private"]
            desc[:session_affinity] = "GENERATED_COOKIE"
            desc[:affinity_cookie_ttl_sec] = @config['lb_cookie_stickiness_policy']['timeout']
          elsif @config['ip_stickiness_policy'] and tg['proto'] != "UDP"
            desc[:session_affinity] = "CLIENT_IP"
            if @config["private"]
              if @config['ip_stickiness_policy']["map_port"]
                desc[:session_affinity] += "_PORT"
              end
              if @config['ip_stickiness_policy']["map_proto"]
                desc[:session_affinity] += "_PROTO"
              end
            end
          else
            desc[:session_affinity] = "NONE"
          end
          if tg["healthcheck"]
            hc = createHealthCheck(tg["healthcheck"], tg["name"])
            desc[:health_checks] = [hc.self_link]
          end

          backend_obj = MU::Cloud::Google.compute(:BackendService).new(desc)
          MU.log "Creating backend service #{MU::Cloud::Google.nameStr(@deploy.getResourceName(tg["name"]))}", details: backend_obj

          if @config['private'] and !@config['global']
            return MU::Cloud::Google.compute(credentials: @config['credentials']).insert_region_backend_service(
              @project_id,
              @config['region'],
              backend_obj
            )
          else
            return MU::Cloud::Google.compute(credentials: @config['credentials']).insert_backend_service(
              @project_id,
              backend_obj
            )
          end
        end

        def createHealthCheck(hc, namebase)
#          MU.log "HEALTH CHECK", MU::NOTICE, details: hc
          target = hc['target'].match(/^([^:]+):(\d+)(.*)/)
          proto = target[1]
          port = target[2]
          path = target[3]
          name = MU::Cloud::Google.nameStr(@deploy.getResourceName(namebase+"-hc-"+proto.downcase+"-"+port.to_s))

          if proto == "HTTP" or proto == "HTTPS"
            hc_obj = MU::Cloud::Google.compute(proto == "HTTP" ? :HttpHealthCheck : :HttpsHealthCheck).new(
              check_interval_sec: hc["interval"],
              timeout_sec: hc["timeout"],
              unhealthy_threshold: hc["unhealthy_threshold"],
              healthy_threshold: hc["healthy_threshold"],
              description: @deploy.deploy_id,
              name: name,
              port: port,
              request_path: path ? path : "/"
            )
# other types:
# type: SSL, HTTP2
            MU.log "Creating #{proto} health check #{name}", details: hc_obj
            if proto == "HTTP"
              return MU::Cloud::Google.compute(credentials: @config['credentials']).insert_http_health_check(
                @project_id,
                hc_obj
              )
            else
              return MU::Cloud::Google.compute(credentials: @config['credentials']).insert_https_health_check(
                @project_id,
                hc_obj
              )
            end
          else
            desc = {
              :check_interval_sec => hc["interval"],
              :timeout_sec => hc["timeout"],
              :unhealthy_threshold => hc["unhealthy_threshold"],
              :healthy_threshold => hc["healthy_threshold"],
              :description => @deploy.deploy_id,
              :name => name
            }
            if proto == "TCP"
              desc[:type] = "TCP"
              desc[:tcp_health_check] = MU::Cloud::Google.compute(:TcpHealthCheck).new(
                port: port,
                proxy_header: "NONE",
                request: "",
                response: ""
              )
            elsif proto == "SSL"
              desc[:type] = "SSL"
              desc[:ssl_health_check] = MU::Cloud::Google.compute(:SslHealthCheck).new(
                port: port,
                proxy_header: "NONE",
                request: "", # XXX needs to be configurable
                response: "" # XXX needs to be configurable
              )
            elsif proto == "UDP"
              desc[:type] = "UDP"
              desc[:udp_health_check] = MU::Cloud::Google.compute(:UdpHealthCheck).new(
                port: port,
                request: "ORLY", # XXX needs to be configurable
                response: "YARLY" # XXX needs to be configurable
              )
            end
            hc_obj = MU::Cloud::Google.compute(:HealthCheck).new(desc)

            return MU::Cloud::Google.compute(credentials: @config['credentials']).insert_health_check(
              @project_id,
              hc_obj
            )
          end

        end
      end
    end
  end
end
