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
          az = @config['availability_zone']
          if az.nil?
            az = MU::Cloud::Google.listAZs(@config['region']).sample
          end

          instance_props = MU::Cloud::Google.compute(:InstanceProperties).new(
            can_ip_forward: !@config['src_dst_check'],
            description: @deploy.deploy_id,
#            machine_type: "zones/"+az+"/machineTypes/"+size,
            machine_type: size,
            labels: labels,
            disks: MU::Cloud::Google::Server.diskConfig(@config, false, false, credentials: @config['credentials']),
            network_interfaces: MU::Cloud::Google::Server.interfaceConfig(@config, @vpc),
            metadata: {
              :items => [
                :key => "ssh-keys",
                :value => @config['ssh_user']+":"+@deploy.ssh_public_key
              ]
            },
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
# http://www.rubydoc.info/github/google/google-api-ruby-client/Google/Apis/ComputeBeta/AutoscalingPolicyCpuUtilization
# http://www.rubydoc.info/github/google/google-api-ruby-client/Google/Apis/ComputeBeta/AutoscalingPolicyLoadBalancingUtilization
# http://www.rubydoc.info/github/google/google-api-ruby-client/Google/Apis/ComputeBeta/AutoscalingPolicyCustomMetricUtilization
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
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @param flags [Hash]: Optional flags
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching ServerPools
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, flags: {}, credentials: nil)
          flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)
          MU.log "XXX ServerPool.find not yet implemented", MU::WARN
          return {}
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "ssh_user" => {
              "type" => "string",
              "description" => "Account to use when connecting via ssh. Google Cloud images don't come with predefined remote access users, and some don't work with our usual default of +root+, so we recommend using some other (non-root) username.",
              "default" => "muadmin"
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

          pool['project'] ||= MU::Cloud::Google.defaultProject(pool['credentials'])

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
                launch['image_id'] = configurator.getTail("server_pool"+pool['name']+"Image", value: img_id, prettyname: "server_pool"+pool['name']+"Image", cloudtype: "Google::Apis::ComputeBeta::Image")
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
          flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)
          return if !MU::Cloud::Google::Habitat.isLive?(flags["project"], credentials)

          if !flags["global"]
            ["region_autoscaler", "region_instance_group_manager"].each { |type|
              MU::Cloud::Google.compute(credentials: credentials).delete(
                type,
                flags["project"],
                region,
                noop
              )
            }
          else
            MU::Cloud::Google.compute(credentials: credentials).delete(
              "instance_template",
              flags["project"],
              noop
            )
          end

        end
      end
    end
  end
end
