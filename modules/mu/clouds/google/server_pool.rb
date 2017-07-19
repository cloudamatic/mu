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

        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :cloud_id
        attr_reader :config

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::server_pools}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name = @deploy.getResourceName(@config['name'])
          end
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
pp @config['basis']['launch_config']
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
            disks: MU::Cloud::Google::Server.diskConfig(@config, false, false),
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
          template = MU::Cloud::Google.compute.insert_instance_template(
            @config['project'],
            template_obj
          )

          mgr_obj = MU::Cloud::Google.compute(:InstanceGroupManager).new(
            name: MU::Cloud::Google.nameStr(@mu_name),
            description: @deploy.deploy_id,
            target_size: @config['min_size'],
            base_instance_name: MU::Cloud::Google.nameStr(@mu_name),
            instance_template: template.self_link,
            named_ports: port_objs
          )

          MU.log "Creating region instance group manager #{@mu_name}", details: mgr_obj
          MU::Cloud::Google.compute.insert_region_instance_group_manager(
            @config['project'],
            @config['region'],
            mgr_obj
          )

#          scaler_obj = MU::Cloud::Google.compute(:Autoscaler).new(
#            name: @mu_name
#            description: @deploy.deploy_id
#            target: instancegroup
#          )
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
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, flags: {})
          MU.log "XXX ServerPool.find not yet implemented", MU::WARN
          return {}
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::server_pools}, bare and unvalidated.
        # @param pool [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(pool, configurator)
          ok = true
          pool['named_ports'] ||= []
          if !pool['named_ports'].include?({"name" => "ssh", "port" => 22})
            pool['named_ports'] << {"name" => "ssh", "port" => 22}
          end
          
          if pool['basis']['launch_config']

            if pool['basis']['launch_config']['image_id'].nil?
              if MU::Config.google_images.has_key?(pool['platform'])
                pool['basis']['launch_config']['image_id'] = configurator.getTail("server_pool"+pool['name']+"Image", value: MU::Config.google_images[pool['platform']], prettyname: "server_pool"+pool['name']+"Image", cloudtype: "Google::Apis::ComputeBeta::Image")
              else
                MU.log "No image specified for #{pool['name']} and no default available for platform #{pool['platform']}", MU::ERR, details: pool['basis']['launch_config']
                ok = false
              end
            end

            real_image = nil
            begin
              real_image = MU::Cloud::Google::Server.fetchImage(pool['basis']['launch_config']['image_id'].to_s)
            rescue ::Google::Apis::ClientError => e
              MU.log e.inspect, MU::WARN
            end

            if real_image.nil?
              MU.log "Image #{pool['basis']['launch_config']['image_id']} for server_pool #{pool['name']} does not appear to exist", MU::ERR
              ok = false
            else
              pool['basis']['launch_config']['image_id'] = real_image.self_link
            end
          end

          ok
        end

        # Remove all autoscale groups associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
        end
      end
    end
  end
end
