# Copyright:: Copyright (c) 2019 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#	http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

module MU
  class Cloud
    class Azure
      # A Kubernetes cluster as configured in {MU::Config::BasketofKittens::container_clusters}
      class ContainerCluster < MU::Cloud::ContainerCluster
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :cloud_id
        attr_reader :config
        attr_reader :groomer    

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::container_clusters}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          # @mu_name = mu_name ? mu_name : @deploy.getResourceName(@config["name"])
          @config["groomer"] = MU::Config.defaultGroomer unless @config["groomer"]
          @groomclass = MU::Groomer.loadGroomer(@config["groomer"])

          if !mu_name.nil?
            @mu_name = mu_name
          else
            @mu_name ||= @deploy.getResourceName(@config["name"], max_length: 31)
          end
        end


        # Called automatically by {MU::Deploy#createResources}
        # @return [String]: The cloud provider's identifier for this GKE instance.
        def create
          @config['region'] ||= MU::Cloud::Azure.myRegion(@config['credentials'])
          rgroup_name = @deploy.deploy_id+"-"+@config['region'].upcase

          tags = {}
          if !@config['scrub_mu_isms']
            tags = MU::MommaCat.listStandardTags
          end
          if @config['tags']
            @config['tags'].each { |tag|
              tags[tag['key']] = tag['value']
            }
          end

          key_obj = MU::Cloud::Azure.containers(:ContainerServiceSshPublicKey).new
          key_obj.key_data = @deploy.ssh_public_key

          ssh_obj = MU::Cloud::Azure.containers(:ContainerServiceSshConfiguration).new
          ssh_obj.public_keys = [key_obj]

          lnx_obj = MU::Cloud::Azure.containers(:ContainerServiceLinuxProfile).new
          lnx_obj.admin_username = "muadmin"
          lnx_obj.ssh = ssh_obj

          profile_obj = MU::Cloud::Azure.containers(:ManagedClusterAgentPoolProfile).new
          profile_obj.count = @config['instance_count']
          profile_obj.vm_size = "Standard_DS2_v2"
          profile_obj.min_count = @config['instance_count']
          profile_obj.max_count = @config['instance_count']
          profile_obj.os_type = "Linux"
          profile_obj.os_disk_size_gb = 10
# XXX correlate this with the one(s) we configured in @config['vpc']
          profile_obj.vnet_subnet_id = @vpc.subnets.first.cloud_desc.id


          cluster_obj = MU::Cloud::Azure.containers(:ManagedCluster).new
          cluster_obj.location = @config['region']
#          cluster_obj.dns_prefix = @config['dns_prefix']
#          cluster_obj.tags = tags
#          cluster_obj.linux_profile = lnx_obj
#          cluster_obj.api_server_authorized_ipranges = [MU.mu_public_ip+"/32", MU.my_private_ip+"/32"]
#          cluster_obj.node_resource_group = rgroup_name
#          cluster_obj.agent_pool_profiles = [profile_obj]
          
#          if @config['flavor'] == "Kubernetes"
#            cluster_obj.kubernetes_version = @config['kubernetes']['version']
#          end

          pool_obj = MU::Cloud::Azure.containers(:AgentPool).new
          pool_obj.count = @config['instance_count']
          pool_obj.vm_size = "Standard_DS2_v2"

begin
MU.log "building thing", MU::NOTICE, details: cluster_obj
          MU::Cloud::Azure.containers(credentials: @config['credentials']).managed_clusters.create_or_update(
            rgroup_name,
            @mu_name,
            cluster_obj
          )
MU.log "building other thing", MU::NOTICE, details: cluster_obj
          MU::Cloud::Azure.containers(credentials: @config['credentials']).agent_pools.create_or_update(
            rgroup_name,
            @mu_name,
            @mu_name,
            cluster_obj
          )
          rescue ::MsRestAzure::AzureOperationError => e
            MU::Cloud::Azure.handleError(e)
          end

        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
        end

        # Locate an existing ContainerCluster or ContainerClusters and return an array containing matching GCP resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @param flags [Hash]: Optional flags
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching ContainerClusters
        def self.find(**args)
          found = {}

          # Azure resources are namedspaced by resource group. If we weren't
          # told one, we may have to search all the ones we can see.
          resource_groups = if args[:resource_group]
            [args[:resource_group]]
          elsif args[:cloud_id] and args[:cloud_id].is_a?(MU::Cloud::Azure::Id)
            [args[:cloud_id].resource_group]
          else
            MU::Cloud::Azure.resources(credentials: args[:credentials]).resource_groups.list.map { |rg| rg.name }
          end

          if args[:cloud_id]
            id_str = args[:cloud_id].is_a?(MU::Cloud::Azure::Id) ? args[:cloud_id].name : args[:cloud_id]
            resource_groups.each { |rg|
              begin
                resp = MU::Cloud::Azure.containers(credentials: args[:credentials]).managed_clusters.get(rg, id_str)
                found[Id.new(resp.id)] = resp
              rescue MsRestAzure::AzureOperationError => e
                # this is fine, we're doing a blind search after all
              end
            }
          else
            if args[:resource_group]
              MU::Cloud::Azure.containers(credentials: args[:credentials]).managed_clusters.list(args[:resource_group]).each { |net|
                found[Id.new(net.id)] = net
              }
            else
              MU::Cloud::Azure.containers(credentials: args[:credentials]).managed_clusters.list_all.each { |net|
                found[Id.new(net.id)] = net
              }
            end
          end

          found
        end

        # Register a description of this cluster instance with this deployment's metadata.
        def notify
          MU.structToHash(cloud_desc)
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
          MU::Cloud::ALPHA
        end

        # Called by {MU::Cleanup}. Locates resources that were created by the
        # currently-loaded deployment, and purges them.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region in which to operate
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "flavor" => {
              "enum" => ["Kubernetes", "OpenShift", "Swarm", "DC/OS"],
              "default" => "Kubernetes"
            },
            "kubernetes" => {
              "default" => { "version" => "1.12.8" }
            },
            "dns_prefix" => {
              "type" => "string",
              "description" => "DNS name prefix to use with the hosted Kubernetes API server FQDN. Will default to the global +appname+ value if not specified."
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::container_clusters}, bare and unvalidated.
        # @param cluster [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(cluster, configurator)
          ok = true
# XXX validate k8s versions (master and node)
# XXX validate image types
# MU::Cloud::Azure.container.get_project_zone_serverconfig(@config["project"], @config['availability_zone'])
          cluster["dns_prefix"] ||= $myAppName # XXX woof globals wtf

          ok
        end

        private

      end #class
    end #class
  end
end #module
