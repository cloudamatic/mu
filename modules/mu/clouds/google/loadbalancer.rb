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

        @deploy = nil
        @lb = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id
        attr_reader :targetgroups

        @cloudformation_data = {}
        attr_reader :cloudformation_data

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::loadbalancers}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name = @deploy.getResourceName(@config["name"])
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
# UDP: INTERNAL only, single-region only
# HTTP or HTTPS: internet-facing only (EXTERNAL)
# TCP LB, TCP proxy, SSL proxy: either

          parent_thread_id = Thread.current.object_id

          backends = {} # XXX backends are only if we're doing INTERNAL!
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
#TODO ip_address
              realproto = ["HTTP", "HTTPS"].include?(l['lb_protocol']) ? "TCP" : l['lb_protocol']
              ruleobj = ::Google::Apis::ComputeBeta::ForwardingRule.new(
                name: MU::Cloud::Google.nameStr(@mu_name+"-"+l['targetgroup']),
                description: @deploy.deploy_id,
                load_balancing_scheme: "EXTERNAL",
                target: targets[l['targetgroup']].self_link,
                ip_protocol: realproto,
                port_range: l['lb_port'].to_s
              )
            else
# TODO network, subnetwork, ports
              ruleobj = ::Google::Apis::ComputeBeta::ForwardingRule.new(
                name: MU::Cloud::Google.nameStr(@mu_name+"-"+l['targetgroup']),
                description: @deploy.deploy_id,
                load_balancing_scheme: "INTERNAL",
                backend_service: backends[l['targetgroup']].self_link,
                ip_protocol: l['lb_protocol'],
                ports: [l['lb_port'].to_s]
              )
            end
            MU.log "Creating Forwarding Rule #{@mu_name}", MU::NOTICE, details: ruleobj
#            resp = MU::Cloud::Google.compute.insert_forwarding_rule(
            resp = MU::Cloud::Google.compute.insert_global_forwarding_rule(
              @config['project'],
#              @config['region'],
              ruleobj
            )
          }

        end

        # Wrapper that fetches the API's description of one of these things
        def cloud_desc
        end

        # Return the metadata for this LoadBalancer
        # @return [Hash]
        def notify
          resp = MU::Cloud::Google.compute.list_global_forwarding_rules(
            @config["project"],
            filter: "description eq #{@deploy.deploy_id}"
          )
          rules = {}
          if !resp.nil? and !resp.items.nil?
            resp.items.each { |rule|
              rules[rule.name] = rule.to_h
              rules[rule.name].delete(:label_fingerprint)
            }
          end
          pp rules
          rules
        end

        # Register a Server node with an existing LoadBalancer.
        #
        # @param instance_id [String] A node to register.
        # @param targetgroups [Array<String>] The target group(s) of which this node should be made a member. Not applicable to classic LoadBalancers. If not supplied, the node will be registered to all available target groups on this LoadBalancer.
        def registerNode(instance_id, targetgroups: nil)
        end

        # Remove all load balancers associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject

          ["global_forwarding_rule", "target_http_proxy", "target_https_proxy", "url_map", "backend_service", "health_check", "http_health_check", "https_health_check"].each { |type|
            MU::Cloud::Google.compute.delete(
              type,
              flags["project"],
              noop
            )
          }
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::loadbalancers}, bare and unvalidated.
        # @param lb [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(lb, configurator)
          ok = true
          if lb['classic']
            MU.log "LoadBalancer 'classic' flag has no meaning in Google Cloud", MU::WARN
          end

          if lb['app_cookie_stickiness_policy']
            MU.log "LoadBalancer 'app_cookie_stickiness_policy' option has no meaning in Google Cloud", MU::WARN
            lb.delete('app_cookie_stickiness_policy')
          end

          lb["targetgroups"].each { |tg|
            if tg["healthcheck"]
              target = tg["healthcheck"]['target'].match(/^([^:]+):(\d+)(.*)/)
              proto = target[1]
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
                tg["healthcheck"]["target"] = tg["proto"]+":"+tg["port"].to_s+"/"
                tg["healthcheck"]["httpcode"] = "200,301,302"
              end
              MU.log "No healthcheck declared for target group #{tg['name']} in LoadBalancer #{lb['name']}, creating one.", details: tg
            end
          }

          ok
        end

        # Locate an existing LoadBalancer or LoadBalancers and return an array containing matching Google resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @param flags [Hash]: Optional flags
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching LoadBalancers
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, flags: {})
        end

        private

        def createProxy(tg, backend)
          name = MU::Cloud::Google.nameStr(@deploy.getResourceName(tg["name"]))

          urlmap_obj = MU::Cloud::Google.compute(:UrlMap).new(
            name: name,
            description: @deploy.deploy_id,
# TODO this is where path_matchers, host_rules, and tests go (the sophisticated
            default_service: backend.self_link
# Layer 7 stuff)
          )
          MU.log "Creating url map #{tg['name']}", details: urlmap_obj
          urlmap = MU::Cloud::Google.compute.insert_url_map(
            @config['project'],
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
            MU::Cloud::Google.compute.insert_target_http_proxy(
              @config['project'],
              target_obj
            )
          else
# TODO we need a method like MU::Cloud::AWS.findSSLCertificate
# TODO also we can fall back on generateSSLCert(name), with some mods
            desc[:ssl_certificates] = ["https://www.googleapis.com/compute/v1/projects/my-project-1474050033734/global/sslCertificates/stange-momma-cat"]
            target_obj = MU::Cloud::Google.compute(:TargetHttpsProxy).new(desc)
            MU.log "Creating https target proxy #{tg['name']}", details: target_obj
            MU::Cloud::Google.compute.insert_target_https_proxy(
              @config['project'],
              target_obj
            )
          end
        end

        def createBackendService(tg)
          desc = {
            :name => MU::Cloud::Google.nameStr(@deploy.getResourceName(tg["name"])),
            :description => @deploy.deploy_id,
            :load_balancing_scheme => @config['private'] ? "INTERNAL" : "EXTERNAL",
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
          else
            # XXX support other session affinity options (NONE, CLIENT_IP_PROTO, CLIENT_IP_PORT_PROTO, etc)
            desc[:session_affinity] = "CLIENT_IP"
          end
          hc = createHealthCheck(tg["healthcheck"], tg["name"])
          desc[:health_checks] = [hc.self_link]

          backend_obj = MU::Cloud::Google.compute(:BackendService).new(desc)
          MU.log "Creating backend service #{MU::Cloud::Google.nameStr(@deploy.getResourceName(tg["name"]))}", details: backend_obj
          return MU::Cloud::Google.compute.insert_backend_service(
            @config['project'],
            backend_obj
          )
        end

        def createHealthCheck(hc, namebase)
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
            MU.log "Creating #{proto} health check #{name}", details: hc_obj
            if proto == "HTTP"
              return MU::Cloud::Google.compute.insert_http_health_check(
                @config['project'],
                hc_obj
              )
            else
              return MU::Cloud::Google.compute.insert_https_health_check(
                @config['project'],
                hc_obj
              )
            end
          else
#            hc_obj = MU::Cloud::Google.compute(:HealthCheck).new(
#              check_interval_sec: hc["interval"],
#              timeout_sec: hc["timeout"],
#              unhealthy_threshold: hc["unhealthy_threshold"],
#              healthy_threshold: hc["healthy_threshold"],
#              description: @deploy.deploy_id,
#              name: name,
# type: TCP, UDP, SSL, HTTP, HTTPS, HTTP2
# ssl_health_check: ugh, another object
# tcp_health_check: ugh, another object
# etc etc
#            )
# insert_health_check
          end

          def generateSSLCert(name)
            MU.log "Creating self-signed service SSL certificate for #{@server.mu_name} (CN=#{canonical_ip})"

            # Create and save a key
            key = OpenSSL::PKey::RSA.new 4096
            if !Dir.exist?(MU.mySSLDir)
              Dir.mkdir(MU.mySSLDir, 0700)
            end

            open("#{MU.mySSLDir}/#{@server.mu_name}.key", 'w', 0600) { |io|
              io.write key.to_pem
            }

            # Create a certificate request for this node
            csr = OpenSSL::X509::Request.new
            csr.version = 0
            csr.subject = OpenSSL::X509::Name.parse "CN=#{canonical_ip}/O=Mu/C=US"
            csr.public_key = key.public_key
            open("#{MU.mySSLDir}/#{@server.mu_name}.csr", 'w', 0644) { |io|
              io.write csr.to_pem
            }


            if MU.chef_user == "mu"
              @server.deploy.signSSLCert("#{MU.mySSLDir}/#{@server.mu_name}.csr")
            else
              deploykey = OpenSSL::PKey::RSA.new(@server.deploy.public_key)
              deploysecret = Base64.urlsafe_encode64(deploykey.public_encrypt(@server.deploy.deploy_secret))
              res_type = "server"
              res_type = "server_pool" if !@config['basis'].nil?
              uri = URI("https://#{MU.mu_public_addr}:2260/")
              req = Net::HTTP::Post.new(uri)
              req.set_form_data(
                  "mu_id" => MU.deploy_id,
                  "mu_resource_name" => @config['name'],
                  "mu_resource_type" => res_type,
                  "mu_ssl_sign" => "#{MU.mySSLDir}/#{@server.mu_name}.csr",
                  "mu_user" => MU.mu_user,
                  "mu_deploy_secret" => deploysecret
              )
              http = Net::HTTP.new(uri.hostname, uri.port)
              http.ca_file = "/etc/pki/Mu_CA.pem" # XXX why no worky?
              http.use_ssl = true
              http.verify_mode = OpenSSL::SSL::VERIFY_NONE # XXX this sucks
              response = http.request(req)

              MU.log "Got error back on signing request for #{MU.mySSLDir}/#{@server.mu_name}.csr", MU::ERR if response.code != "200"
            end

            cert = OpenSSL::X509::Certificate.new File.read "#{MU.mySSLDir}/#{@server.mu_name}.crt"
            # Upload the certificate to a Chef Vault for this node
            certdata = {
                "data" => {
                    "node.crt" => cert.to_pem.chomp!.gsub(/\n/, "\\n"),
                    "node.key" => key.to_pem.chomp!.gsub(/\n/, "\\n")
                }
            }
          end


        end
      end
    end
  end
end
