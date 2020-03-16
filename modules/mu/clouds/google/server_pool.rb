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
      # A server pool as configured in {MU::Config::BasketofKittens::server_pools}
      class ServerPool < MU::Cloud::ServerPool

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config['name'])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          port_objs = []

          sa = MU::Config::Ref.get(@config['service_account'])
          if !sa or !sa.kitten or !sa.kitten.cloud_desc
            raise MuError, "Failed to get service account cloud id from #{@config['service_account'].to_s}"
          end
          @service_acct = MU::Cloud::Google.compute(:ServiceAccount).new(
            email: sa.kitten.cloud_desc.email,
            scopes: @config['scopes']
          )
          if !@config['scrub_mu_isms']
            MU::Cloud::Google.grantDeploySecretAccess(@service_acct.email, credentials: @config['credentials'])
          end


          @config['named_ports'].each { |port_cfg|
            port_objs << MU::Cloud::Google.compute(:NamedPort).new(
              name: port_cfg['name'],
              port: port_cfg['port']
            )
          }

#          subnet = @vpc.getSubnet(cloud_id: @config['vpc']['subnets'].first["subnet_id"].to_s)

          labels = {}
          MU::MommaCat.listStandardTags.each_pair { |name, value|
            if !value.nil?
              labels[name.downcase] = value.downcase.gsub(/[^a-z0-9\-\_]/i, "_")
            end
          }
          labels["name"] = MU::Cloud::Google.nameStr(@mu_name)

          size = nil
          if !@config['basis']['launch_config'].nil?
            size = @config['basis']['launch_config']['size']
            @config['image_id'] = @config['basis']['launch_config']['image_id']
          end
# XXX this should create a non-regional instance group
#          az = @config['availability_zone']
#          az ||= MU::Cloud::Google.listAZs(@config['region']).sample

          metadata = { # :items?
            "startup-script" => @userdata
          }
          if @config['metadata']
            desc[:metadata] = Hash[@config['metadata'].map { |m|
              [m["key"], m["value"]]
            }]
          end
          deploykey = @config['ssh_user']+":"+@deploy.ssh_public_key
          if desc[:metadata]["ssh-keys"]
            desc[:metadata]["ssh-keys"] += "\n"+deploykey
          else
            desc[:metadata]["ssh-keys"] = deploykey
          end

          instance_props = MU::Cloud::Google.compute(:InstanceProperties).new(
            can_ip_forward: !@config['src_dst_check'],
            description: @deploy.deploy_id,
            machine_type: size,
            service_accounts: [@service_acct],
            labels: labels,
            disks: MU::Cloud::Google::Server.diskConfig(@config, false, false, credentials: @config['credentials']),
            network_interfaces: MU::Cloud::Google::Server.interfaceConfig(@config, @vpc),
            metadata: metadata,
            tags: MU::Cloud::Google.compute(:Tags).new(items: [MU::Cloud::Google.nameStr(@mu_name)])
          )

          template_obj = MU::Cloud::Google.compute(:InstanceTemplate).new(
            name: MU::Cloud::Google.nameStr(@mu_name),
            description: @deploy.deploy_id,
            properties: instance_props
          )

          MU.log "Creating instance template #{@mu_name}", details: template_obj
          template = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_instance_template(
            @project_id,
            template_obj
          )

# XXX AWS-style @config['health_check_type'] doesn't make a lick of sense here
          healing_obj = MU::Cloud::Google.compute(:InstanceGroupManager).new(
            initial_delay_sec: @config['health_check_grace_period']
# TODO here's where health_checks go
          )

          mgr_obj = MU::Cloud::Google.compute(:InstanceGroupManager).new(
            name: MU::Cloud::Google.nameStr(@mu_name),
            description: @deploy.deploy_id,
            target_size: @config['desired_capacity'] || @config['min_size'],
            base_instance_name: MU::Cloud::Google.nameStr(@mu_name),
            instance_template: template.self_link,
            named_ports: port_objs,
            auto_healing_policies: [healing_obj]
          )

          MU.log "Creating region instance group manager #{@mu_name}", details: mgr_obj
          mgr = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_region_instance_group_manager(
            @project_id,
            @config['region'],
            mgr_obj
          )

# TODO this thing supports based on CPU usage, LB usage, or an arbitrary Cloud
# Monitoring metric. The default is "sustained 60%+ CPU usage". We should
# support all that.
# http://www.rubydoc.info/github/google/google-api-ruby-client/Google/Apis/ComputeV1/AutoscalingPolicyCpuUtilization
# http://www.rubydoc.info/github/google/google-api-ruby-client/Google/Apis/ComputeV1/AutoscalingPolicyLoadBalancingUtilization
# http://www.rubydoc.info/github/google/google-api-ruby-client/Google/Apis/ComputeV1/AutoscalingPolicyCustomMetricUtilization
          policy_obj = MU::Cloud::Google.compute(:AutoscalingPolicy).new(
            cooldown_period_sec: @config['default_cooldown'],
            max_num_replicas: @config['max_size'],
            min_num_replicas: @config['min_size']
          )

          scaler_obj = MU::Cloud::Google.compute(:Autoscaler).new(
            name: MU::Cloud::Google.nameStr(@mu_name),
            description: @deploy.deploy_id,
            target: mgr.self_link,
            autoscaling_policy: policy_obj
          )

          MU.log "Creating autoscaler policy #{@mu_name}", details: scaler_obj
          MU::Cloud::Google.compute(credentials: @config['credentials']).insert_region_autoscaler(
            @project_id,
            @config['region'],
            scaler_obj
          )

# TODO honor wait_for_instances
        end

        # This is a NOOP right now, because we're really an empty generator for
        # Servers, and that's what we care about having in deployment
        # descriptors. Should we log some stuff though?
        def notify
          return {}
        end

        # Locate an existing ServerPool or ServerPools and return an array containing matching Google resource descriptors for those that match.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching ServerPools
        def self.find(**args)
          args = MU::Cloud::Google.findLocationArgs(args)

          regions = if args[:region]
            [args[:region]]
          else
            MU::Cloud::Google.listRegions
          end
          found = {}

          regions.each { |r|
            begin
              resp = MU::Cloud::Google.compute(credentials: args[:credentials]).list_region_instance_group_managers(args[:project], args[:region])
              if resp and resp.items
                resp.items.each { |igm|
                  found[igm.name] = igm
                }
              end
            rescue ::Google::Apis::ClientError => e
              raise e if !e.message.match(/forbidden: /)
            end

            begin
# XXX can these guys have name collisions? test this
              MU::Cloud::Google.listAZs(r).each { |az|
                resp = MU::Cloud::Google.compute(credentials: args[:credentials]).list_instance_group_managers(args[:project], az)
                if resp and resp.items
                  resp.items.each { |igm|
                    found[igm.name] = igm
                  }
                end
              }
            rescue ::Google::Apis::ClientError => e
              raise e if !e.message.match(/forbidden: /)
            end
          }

          return found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**_args)
          bok = {
            "cloud" => "Google",
            "credentials" => @credentials,
            "cloud_id" => @cloud_id,
            "region" => @config['region'],
            "project" => @project_id,
          }
          bok['name'] = cloud_desc.name

          scalers = if cloud_desc.zone and cloud_desc.zone.match(/-[a-z]$/)
            bok['availability_zone'] = cloud_desc.zone.sub(/.*?\/([^\/]+)$/, '\1')
            MU::Cloud::Google.compute(credentials: @credentials).list_autoscalers(@project_id, bok['availability_zone'])
          else
            MU::Cloud::Google.compute(credentials: @credentials).list_region_autoscalers(@project_id, @config['region'], filter: "target eq #{cloud_desc.self_link}")
          end

          if scalers and scalers.items and scalers.items.size > 0
            scaler = scalers.items.first
MU.log bok['name'], MU::WARN, details: scaler.autoscaling_policy
# scaler.cpu_utilization.utilization_target
# scaler.cool_down_period_sec
            bok['min_size'] = scaler.autoscaling_policy.min_num_replicas
            bok['max_size'] = scaler.autoscaling_policy.max_num_replicas
          else
            bok['min_size'] = bok['max_size'] = cloud_desc.target_size
          end
if cloud_desc.auto_healing_policies and cloud_desc.auto_healing_policies.size > 0
MU.log bok['name'], MU::WARN, details: cloud_desc.auto_healing_policies
end

          template = MU::Cloud::Google.compute(credentials: @credentials).get_instance_template(@project_id, cloud_desc.instance_template.sub(/.*?\/([^\/]+)$/, '\1'))

          iface = template.properties.network_interfaces.first
          iface.network.match(/(?:^|\/)projects\/(.*?)\/.*?\/networks\/([^\/]+)(?:$|\/)/)
          vpc_proj = Regexp.last_match[1]
          vpc_id = Regexp.last_match[2]

          bok['vpc'] = MU::Config::Ref.get(
            id: vpc_id,
            cloud: "Google",
            habitat: MU::Config::Ref.get(
              id: vpc_proj,
              cloud: "Google",
              credentials: @credentials,
              type: "habitats"
            ),
            credentials: @credentials,
            type: "vpcs",
            subnet_pref: "any" # "anywhere in this VPC" is what matters
          )

          bok['basis'] = {
            "launch_config" => {
              "name" => bok['name']
            }
          }

          template.properties.disks.each { |disk|
            if disk.initialize_params.source_image and disk.boot
              bok['basis']['launch_config']['image_id'] ||= disk.initialize_params.source_image.sub(/^https:\/\/www\.googleapis\.com\/compute\/[^\/]+\//, '')
            elsif disk.type != "SCRATCH"
              bok['basis']['launch_config']['storage'] ||= []
              storage_blob = {
                "size" => disk.initialize_params.disk_size_gb,
                "device" => "/dev/xvd"+(disk.index+97).chr.downcase
              }
              bok['basis']['launch_config']['storage'] <<  storage_blob
            else
              MU.log "Need to sort out scratch disks", MU::WARN, details: disk
            end
            
          }

          if template.properties.labels
            bok['tags'] = template.properties.labels.keys.map { |k| { "key" => k, "value" => template.properties.labels[k] } }
          end
          if template.properties.tags and template.properties.tags.items and template.properties.tags.items.size > 0
            bok['network_tags'] = template.properties.tags.items
          end
          bok['src_dst_check'] = !template.properties.can_ip_forward
          bok['basis']['launch_config']['size'] = template.properties.machine_type.sub(/.*?\/([^\/]+)$/, '\1')
          bok['project'] = @project_id
          if template.properties.service_accounts
            bok['scopes'] = template.properties.service_accounts.map { |sa| sa.scopes }.flatten.uniq
          end
          if template.properties.metadata and template.properties.metadata.items
            bok['metadata'] = template.properties.metadata.items.map { |m| MU.structToHash(m) }
          end

          # Skip nodes that are just members of GKE clusters
          if bok['name'].match(/^gke-.*?-[a-f0-9]+-[a-z0-9]+$/) and
             bok['basis']['launch_config']['image_id'].match(/(:?^|\/)projects\/gke-node-images\//)
            gke_ish = true
            bok['network_tags'].each { |tag|
              gke_ish = false if !tag.match(/^gke-/)
            }
            if gke_ish
              MU.log "ServerPool #{bok['name']} appears to belong to a ContainerCluster, skipping adoption", MU::NOTICE
              return nil
            end
          end
#MU.log bok['name'], MU::WARN, details: [cloud_desc, template]

          bok
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "ssh_user" => MU::Cloud::Google::Server.schema(config)[1]["ssh_user"],
            "metadata" => MU::Cloud::Google::Server.schema(config)[1]["metadata"],
            "service_account" => MU::Cloud::Google::Server.schema(config)[1]["service_account"],
            "scopes" => MU::Cloud::Google::Server.schema(config)[1]["scopes"],
            "network_tags" => MU::Cloud::Google::Server.schema(config)[1]["network_tags"],
            "availability_zone" => {
              "type" => "string",
              "description" => "Target a specific availability zone for this pool, which will create zonal instance managers and scalers instead of regional ones."
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

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::server_pools}, bare and unvalidated.
        # @param pool [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(pool, configurator)
          ok = true
#start = Time.now
          pool['project'] ||= MU::Cloud::Google.defaultProject(pool['credentials'])
          if pool['service_account']
            pool['service_account']['cloud'] = "Google"
            pool['service_account']['habitat'] ||= pool['project']
            found = MU::Config::Ref.get(pool['service_account'])
            if found.id and !found.kitten
              MU.log "GKE pool #{pool['name']} failed to locate service account #{pool['service_account']} in project #{pool['project']}", MU::ERR
              ok = false
            end
          else
            pool = MU::Cloud::Google::User.genericServiceAccount(pool, configurator)
          end

          pool['named_ports'] ||= []
          if !pool['named_ports'].include?({"name" => "ssh", "port" => 22})
            pool['named_ports'] << {"name" => "ssh", "port" => 22}
          end
          
          if pool['basis']['launch_config']
            launch = pool["basis"]["launch_config"]

            launch['size'] = MU::Cloud::Google::Server.validateInstanceType(launch["size"], pool["region"])
            ok = false if launch['size'].nil?

            if launch['image_id'].nil?
              img_id = MU::Cloud.getStockImage("Google", platform: pool['platform'])
              if img_id
                launch['image_id'] = configurator.getTail("server_pool"+pool['name']+"Image", value: img_id, prettyname: "server_pool"+pool['name']+"Image", cloudtype: "Google::Apis::ComputeV1::Image")
              else
                MU.log "No image specified for #{pool['name']} and no default available for platform #{pool['platform']}", MU::ERR, details: launch
                ok = false
              end
            end

            real_image = nil
            begin
              real_image = MU::Cloud::Google::Server.fetchImage(launch['image_id'].to_s, credentials: pool['credentials'])
            rescue ::Google::Apis::ClientError => e
              MU.log e.inspect, MU::WARN
            end

            if real_image.nil?
              MU.log "Image #{launch['image_id']} for server_pool #{pool['name']} does not appear to exist", MU::ERR
              ok = false
            else
              launch['image_id'] = real_image.self_link
            end
          end

          ok
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::RELEASE
        end

        # Remove all autoscale groups associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          flags["habitat"] ||= MU::Cloud::Google.defaultProject(credentials)
          return if !MU::Cloud::Google::Habitat.isLive?(flags["habitat"], credentials)
          filter = %Q{(labels.mu-id = "#{MU.deploy_id.downcase}")}
          if !ignoremaster and MU.mu_public_ip
            filter += %Q{ AND (labels.mu-master-ip = "#{MU.mu_public_ip.gsub(/\./, "_")}")}
          end
          MU.log "Placeholder: Google ServerPool artifacts do not support labels, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: filter

          if !flags["global"]
            ["region_autoscaler", "region_instance_group_manager"].each { |type|
              MU::Cloud::Google.compute(credentials: credentials).delete(
                type,
                flags["habitat"],
                region,
                noop
              )
            }
          else
            MU::Cloud::Google.compute(credentials: credentials).delete(
              "instance_template",
              flags["habitat"],
              noop
            )
          end

        end
      end
    end
  end
end
