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

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          # @mu_name = mu_name ? mu_name : @deploy.getResourceName(@config["name"])
          if !mu_name.nil?
            @mu_name = mu_name
            @cloud_id = Id.new(cloud_desc.id) if @cloud_id
          else
            @mu_name ||= @deploy.getResourceName(@config["name"], max_length: 31)
          end
        end


        # Called automatically by {MU::Deploy#createResources}
        # @return [String]: The cloud provider's identifier for this GKE instance.
        def create
          create_update
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          create_update

          kube_conf = @deploy.deploy_dir+"/kubeconfig-#{@config['name']}"

          admin_creds = MU::Cloud::Azure.containers(credentials: @config['credentials']).managed_clusters.list_cluster_admin_credentials(
            @resource_group,
            @mu_name
          )
          admin_creds.kubeconfigs.each { |kube|
            next if kube.name != "clusterAdmin"

            cfgfile = ""
            kube.value.each { |ord|
              cfgfile += ord.chr
            }

            File.open(kube_conf, "w"){ |k|
              k.puts cfgfile
            }
          }

          if @config['kubernetes_resources']
            MU::Master.applyKubernetesResources(
              @config['name'], 
              @config['kubernetes_resources'],
              kubeconfig: kube_conf,
              outputdir: @deploy.deploy_dir
            )
          end

          MU.log %Q{How to interact with your AKS cluster\nkubectl --kubeconfig "#{kube_conf}" get events --all-namespaces\nkubectl --kubeconfig "#{kube_conf}" get all\nkubectl --kubeconfig "#{kube_conf}" create -f some_k8s_deploy.yml\nkubectl --kubeconfig "#{kube_conf}" get nodes}, MU::SUMMARY

        end

        # Locate and return cloud provider descriptors of this resource type
        # which match the provided parameters, or all visible resources if no
        # filters are specified. At minimum, implementations of +find+ must
        # honor +credentials+ and +cloud_id+ arguments. We may optionally
        # support other search methods, such as +tag_key+ and +tag_value+, or
        # cloud-specific arguments like +project+. See also {MU::MommaCat.findStray}.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching resources
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
              resp = MU::Cloud::Azure.containers(credentials: args[:credentials]).managed_clusters.get(rg, id_str)
              found[Id.new(resp.id)] = resp if resp
            }
          else
            if args[:resource_group]
              MU::Cloud::Azure.containers(credentials: args[:credentials]).managed_clusters.list_by_resource_group(args[:resource_group]).each { |cluster|
                found[Id.new(cluster.id)] = cluster
              }
            else
              MU::Cloud::Azure.containers(credentials: args[:credentials]).managed_clusters.list.each { |cluster|
                found[Id.new(cluster.id)] = cluster
              }
            end
          end

          found
        end

        # Register a description of this cluster instance with this deployment's metadata.
        def notify
          base = MU.structToHash(cloud_desc)
          base["cloud_id"] = @cloud_id.name
          base.merge!(@config.to_h)
          base
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
          MU::Cloud::BETA
        end

        # Stub method. Azure resources are cleaned up by removing the parent
        # resource group.
        # @return [void]
        def self.cleanup(**args)
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "flavor" => {
              "enum" => ["Kubernetes", "OpenShift", "Swarm", "DC/OS"],
              "description" => "The Azure container platform to deploy. Currently only +Kubernetes+ is supported.",
              "default" => "Kubernetes"
            },
            "platform" => {
              "description" => "The OS platform to deploy for workers and containers.",
              "default" => "Linux",
              "enum" => ["Linux", "Windows"]
            },
            "max_pods" => {
              "type" => "integer",
              "description" => "Maximum number of pods allowed on this cluster",
              "default" => 30
            },
            "kubernetes" => {
              "default" => { "version" => "1.12.8" }
            },
            "dns_prefix" => {
              "type" => "string",
              "description" => "DNS name prefix to use with the hosted Kubernetes API server FQDN. Will default to the global +appname+ value if not specified."
            },
            "disk_size_gb" => {
              "type" => "integer",
              "description" => "Size of the disk attached to each worker, specified in GB. The smallest allowed disk size is 30, the largest 1024.",
              "default" => 100
            },
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
          cluster['region'] ||= MU::Cloud::Azure.myRegion(cluster['credentials'])

          if cluster["disk_size_gb"] < 30 or cluster["disk_size_gb"] > 1024
            MU.log "Azure ContainerCluster disk_size_gb must be between 30 and 1024.", MU::ERR
            ok = false
          end

          if cluster['min_size'] and cluster['instance_count'] < cluster['min_size']
            cluster['instance_count'] = cluster['min_size']
          end
          if cluster['max_size'] and cluster['instance_count'] < cluster['max_size']
            cluster['instance_count'] = cluster['max_size']
          end

          cluster['instance_type'] ||= "Standard_DS2_v2" # TODO when Server is implemented, it should have a validateInstanceType method we can use here

          svcacct_desc = {
            "name" => cluster["name"]+"user",
            "region" => cluster["region"],
            "type" => "service",
            "cloud" => "Azure",
            "create_api_key" => true,
            "credentials" => cluster["credentials"],
            "roles" => [
              "Azure Kubernetes Service Cluster Admin Role"
            ]
          }
          MU::Config.addDependency(cluster, cluster['name']+"user", "user")

          ok = false if !configurator.insertKitten(svcacct_desc, "users")

          ok
        end

        private

        def create_update
          need_apply = false

          ext_cluster = MU::Cloud::Azure.containers(credentials: @config[:credentials]).managed_clusters.get(
            @resource_group,
            @mu_name
          )
          if ext_cluster
            @cloud_id = MU::Cloud::Azure::Id.new(ext_cluster.id)
          end

          key_obj = MU::Cloud::Azure.containers(:ContainerServiceSshPublicKey).new
          key_obj.key_data = @deploy.ssh_public_key

          ssh_obj = MU::Cloud::Azure.containers(:ContainerServiceSshConfiguration).new
          ssh_obj.public_keys = [key_obj]

          os_profile_obj = if !ext_cluster
            if @config['platform'] == "Windows"
              os_obj = MU::Cloud::Azure.containers(:ContainerServiceWindowsProfile, model_version: "V2019_02_01").new
              os_obj.admin_username = "muadmin"
              # Azure password constraints are extra-annoying
              winpass = MU.generatePassword(safe_pattern: '!@#$%^&*()', retries: 150)
# TODO store this somewhere the user can get at it
              os_obj.admin_password = winpass
              os_obj
            else
              os_obj = MU::Cloud::Azure.containers(:ContainerServiceLinuxProfile).new
              os_obj.admin_username = "muadmin"
              os_obj.ssh = ssh_obj
              os_obj
            end
          else
            # Azure does not support updates to this parameter
            @config['platform'] == "Windows" ? ext_cluster.windows_profile : ext_cluster.linux_profile
          end

          svc_principal_obj = MU::Cloud::Azure.containers(:ManagedClusterServicePrincipalProfile).new
# XXX this should come from a MU::Cloud::Azure::User object, but right now
# there's no way to get the 'secret' field from a user-assigned identity afaict
# For now, we'll cheat with Mu's system credentials.
          creds = MU::Cloud::Azure.credConfig(@config['credentials'])
          svc_principal_obj.client_id = creds["client_id"]
          svc_principal_obj.secret = creds["client_secret"]

#          svc_acct = @deploy.findLitterMate(type: "user", name: @config['name']+"user")
#          raise MuError, "Failed to locate service account #{@config['name']}user" if !svc_acct
#          svc_principal_obj.client_id = svc_acct.cloud_desc.client_id
#          svc_principal_obj.secret = svc_acct.getSecret

          agent_profiles = if !ext_cluster
            profile_obj = MU::Cloud::Azure.containers(:ManagedClusterAgentPoolProfile).new
            profile_obj.name = @deploy.getResourceName(@config["name"], max_length: 11).downcase.gsub(/[^0-9a-z]/, "")
            if @config['min_size'] and @config['max_size']
              # Special API features need to be enabled for scaling
              MU::Cloud::Azure.ensureFeature("Microsoft.ContainerService/WindowsPreview", credentials: @config['credentials'])
              MU::Cloud::Azure.ensureFeature("Microsoft.ContainerService/VMSSPreview", credentials: @config['credentials'])

              profile_obj.min_count = @config['min_size']
              profile_obj.max_count = @config['max_size']
              profile_obj.enable_auto_scaling = true
              profile_obj.type = MU::Cloud::Azure.containers(:AgentPoolType)::VirtualMachineScaleSets
# XXX if you actually try to do this:
# BadRequest: Virtual Machine Scale Set agent nodes are not allowed since feature "Microsoft.ContainerService/WindowsPreview" is not enabled.
            end
            profile_obj.count = @config['instance_count']
            profile_obj.vm_size = @config['instance_type']
            profile_obj.max_pods = @config['max_pods']
            profile_obj.os_type = @config['platform']
            profile_obj.os_disk_size_gb = @config['disk_size_gb']
# XXX correlate this with the one(s) we configured in @config['vpc']
#          profile_obj.vnet_subnet_id = @vpc.subnets.first.cloud_desc.id # XXX has to have its own subnet for k8s apparently
            [profile_obj]
          else
            # Azure does not support adding/removing agent profiles to a live
            # cluster, but it does support changing some values on an existing
            # one.
            profile_obj = ext_cluster.agent_pool_profiles.first

            nochange_map = {
              "disk_size_gb" => :os_disk_size_gb,
              "instance_type" => :vm_size,
              "platform" => :os_type,
              "max_pods" => :max_pods,
            }

            tried_to_change =[]
            nochange_map.each_pair { |cfg, attribute|
              if @config.has_key?(cfg) and
                 @config[cfg] != profile_obj.send(attribute)
                tried_to_change << cfg
              end
            }
            if @config['min_size'] and @config['max_size'] and
               !profile_obj.enable_auto_scaling
              tried_to_change << "enable_auto_scaling"
            end
            if tried_to_change.size > 0
              MU.log "Changes specified to one or more immutable AKS Agent Pool parameters in cluster #{@mu_name}, ignoring.", MU::NOTICE, details: tried_to_change
            end

            if @config['min_size'] and @config['max_size'] and
               profile_obj.enable_auto_scaling and
               (
                 profile_obj.min_count != @config['min_size'] or
                 profile_obj.max_count != @config['max_size']
               )
              profile_obj.min_count = @config['min_size']
              profile_obj.max_count = @config['max_size']
              need_apply = true
            end

            if profile_obj.count != @config['instance_count']
              profile_obj.count = @config['instance_count']
              need_apply = true
            end

            [profile_obj]
          end

          cluster_obj = MU::Cloud::Azure.containers(:ManagedCluster).new

          if ext_cluster
            cluster_obj.dns_prefix = ext_cluster.dns_prefix
            cluster_obj.location = ext_cluster.location
          else
            # Azure does not support updates to these parameters
            cluster_obj.dns_prefix = @config['dns_prefix']
            cluster_obj.location = @config['region']
          end

          cluster_obj.tags = @tags

          cluster_obj.service_principal_profile = svc_principal_obj
          if @config['platform'] == "Windows"
            cluster_obj.windows_profile = os_profile_obj
          else
            cluster_obj.linux_profile = os_profile_obj
          end
#          cluster_obj.api_server_authorized_ipranges = [MU.mu_public_ip+"/32", MU.my_private_ip+"/32"] # XXX only allowed with Microsoft.ContainerService/APIServerSecurityPreview enabled
          cluster_obj.agent_pool_profiles = agent_profiles

          if @config['flavor'] == "Kubernetes"
            cluster_obj.kubernetes_version = @config['kubernetes']['version'].to_s
            if ext_cluster and @config['kubernetes']['version'] != ext_cluster.kubernetes_version
              need_apply = true
            end
          end

# XXX it may be possible to create a new AgentPool and fall forward into it?
# API behavior suggests otherwise. Project for later.
#          pool_obj = MU::Cloud::Azure.containers(:AgentPool).new
#          pool_obj.count = @config['instance_count']
#          pool_obj.vm_size = "Standard_DS2_v2"

          if !ext_cluster
pp cluster_obj
            MU.log "Creating AKS cluster #{@mu_name}", details: cluster_obj
            need_apply = true
          elsif need_apply
            MU.log "Updating AKS cluster #{@mu_name}", MU::NOTICE, details: cluster_obj
          end

          if need_apply
            resp = MU::Cloud::Azure.containers(credentials: @config['credentials']).managed_clusters.create_or_update(
              @resource_group,
              @mu_name,
              cluster_obj
            )

            @cloud_id = Id.new(resp.id)
          end

        end

      end #class
    end #class
  end
end #module
