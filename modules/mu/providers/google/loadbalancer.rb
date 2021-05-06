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
        attr_reader :targetgroups

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

                if !@config['private']
                  backends[tg['name']] = createBackendService(tg)
                  targets[tg['name']] = createProxy(tg, backends[tg['name']])
                else
                  backends[tg['name']] = createBackendService(tg)
                end
              }
            }
            threads.each do |t|
              t.join
            end
          end

          @config["listeners"].each { |l|
            ruleobj = nil
            if !@config["private"]
#TODO ip_address, port_range, target
              realproto = ["HTTP", "HTTPS"].include?(l['lb_protocol']) ? l['lb_protocol'] : "TCP"
              ruleobj = ::Google::Apis::ComputeV1::ForwardingRule.new(
                name: MU::Cloud::Google.nameStr(@mu_name+"-"+l['targetgroup']),
                description: @deploy.deploy_id,
                load_balancing_scheme: "EXTERNAL",
                target: targets[l['targetgroup']].self_link,
                ip_protocol: realproto,
                port_range: l['lb_port'].to_s
              )
            else
# TODO network, subnetwork, port_range, target
              ruleobj = ::Google::Apis::ComputeV1::ForwardingRule.new(
                name: MU::Cloud::Google.nameStr(@mu_name+"-"+l['targetgroup']),
                description: @deploy.deploy_id,
                load_balancing_scheme: "INTERNAL",
                backend_service: backends[l['targetgroup']].self_link,
                ip_protocol: l['lb_protocol'],
                ports: [l['lb_port'].to_s]
              )
            end
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

        # Return the metadata for this LoadBalancer
        # @return [Hash]
        def notify
          rules = {}
          resp = MU::Cloud::Google.compute(credentials: @config['credentials']).list_global_forwarding_rules(
            @project_id,
            filter: "description eq #{@deploy.deploy_id}"
          )
          if resp.nil? or resp.items.nil? or resp.items.size == 0
            resp = MU::Cloud::Google.compute(credentials: @config['credentials']).list_forwarding_rules(
              @project_id,
              @config['region'],
              filter: "description eq #{@deploy.deploy_id}"
            )
          end
          if !resp.nil? and !resp.items.nil?
            resp.items.each { |rule|
              rules[rule.name] = rule.to_h
              rules[rule.name].delete(:label_fingerprint)
            }
          end
          rules["project_id"] = @project_id

          rules
        end

        # Register a Server node with an existing LoadBalancer.
        #
        # @param instance_id [String] A node to register.
        # @param targetgroups [Array<String>] The target group(s) of which this node should be made a member. Not applicable to classic LoadBalancers. If not supplied, the node will be registered to all available target groups on this LoadBalancer.
        def registerTarget(instance_id, targetgroups: nil)
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          true
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
            ["forwarding_rule", "region_backend_service"].each { |type|
              MU::Cloud::Google.compute(credentials: credentials).delete(
                type,
                flags["habitat"],
                region,
                noop
              )
            }
          end

          if flags['global']
            ["global_forwarding_rule", "target_http_proxy", "target_https_proxy", "url_map", "backend_service", "health_check", "http_health_check", "https_health_check"].each { |type|
              MU::Cloud::Google.compute(credentials: credentials).delete(
                type,
                flags["habitat"],
                nil,
                noop
              )
            }
          end
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
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
            MU.log "Private Google Cloud LoadBalancer requested, setting 'global' flag to false", MU::WARN
            lb['global'] = false
          end

          lb["listeners"].each { |l|
            if lb["private"] and !["TCP", "UDP"].include?(l['lb_protocol'])
              MU.log "Only TCP and UDP listeners are valid for private LoadBalancers in Google Cloud", MU::ERR
              ok = false
            end

            if lb['global'] and l['lb_protocol'] == "UDP"
              MU.log "UDP LoadBalancers can only be per-region in Google Cloud. Setting 'global' to false.", MU::WARN
              lb['global'] = false
            end
            if lb['global'] and !["HTTP", "HTTPS"].include?(l['instance_protocol'])
              MU.log "Global LoadBalancers in Google Cloud can only target HTTP or HTTPS backends", MU::ERR, details: l
              ok = false
            end
          }

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
                if lb['private']
                  MU.log "Private GCP LoadBalancers can only target TCP or UDP protocols, changing #{tg["proto"]} to TCP", MU::NOTICE
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

          ok
        end

        # Locate an existing LoadBalancer or LoadBalancers and return an array containing matching Google resource descriptors for those that match.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching LoadBalancers
        def self.find(**args)
          args = MU::Cloud::Google.findLocationArgs(args)
        end

        private

        def createProxy(tg, backend)
          name = MU::Cloud::Google.nameStr(@deploy.getResourceName(tg["name"]))

          urlmap_obj = MU::Cloud::Google.compute(:UrlMap).new(
            name: name,
            description: @deploy.deploy_id,
# TODO this is where path_matchers, host_rules, and tests go (the sophisticated
# Layer 7 stuff)
            default_service: backend.self_link
          )
          MU.log "Creating url map #{tg['name']}", details: urlmap_obj
          urlmap = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_url_map(
            @project_id,
            urlmap_obj
          )

          desc = {
            :name => name,
            :description => @deploy.deploy_id,
            :url_map => urlmap.self_link
          }

          if tg['proto'] == "HTTP"
            target_obj = MU::Cloud::Google.compute(:TargetHttpProxy).new(desc)
            MU.log "Creating http target proxy #{tg['name']}", details: target_obj
            MU::Cloud::Google.compute(credentials: @config['credentials']).insert_target_http_proxy(
              @project_id,
              target_obj
            )
          else
            certdata = @deploy.nodeSSLCerts(self, false, 2048)
            cert_pem = certdata[0].to_s+File.read("/etc/pki/Mu_CA.pem")
            gcpcert = MU::Cloud::Google.createSSLCertificate(@mu_name.downcase+"-"+tg['name'], cert_pem, certdata[1], credentials: @config['credentials'])

# TODO we need a method like MU::Cloud::AWS.findSSLCertificate, with option to hunt down an existing one
            desc[:ssl_certificates] = [gcpcert.self_link]
            target_obj = MU::Cloud::Google.compute(:TargetHttpsProxy).new(desc)
            MU.log "Creating https target proxy #{tg['name']}", details: target_obj
            MU::Cloud::Google.compute(credentials: @config['credentials']).insert_target_https_proxy(
              @project_id,
              target_obj
            )
          end
        end

        def createBackendService(tg)
          desc = {
            :name => MU::Cloud::Google.nameStr(@deploy.getResourceName(tg["name"])),
            :description => @deploy.deploy_id,
            :load_balancing_scheme => @config['private'] ? "INTERNAL" : "EXTERNAL",
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
            MU.log "INSERTING HEALTH CHECK", MU::NOTICE, details: hc_obj
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
