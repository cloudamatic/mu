# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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
    class Google
      # A Kubernetes cluster as configured in {MU::Config::BasketofKittens::container_clusters}
      class ContainerCluster < MU::Cloud::ContainerCluster

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          if !@mu_name
            @mu_name ||= @deploy.getResourceName(@config["name"], max_length: 40)
          end
        end


        # Called automatically by {MU::Deploy#createResources}
        # @return [String]: The cloud provider's identifier for this GKE instance.
        def create
          labels = Hash[@tags.keys.map { |k|
            [k.downcase, @tags[k].downcase.gsub(/[^-_a-z0-9]/, '-')] }
          ]
          labels["name"] = MU::Cloud::Google.nameStr(@mu_name)

          if @vpc.nil? and @config['vpc'] and @config['vpc']['vpc_name']
            @vpc = @deploy.findLitterMate(name: @config['vpc']['vpc_name'], type: "vpcs")
          end

          if !@vpc
            raise MuError, "ContainerCluster #{@config['name']} unable to locate its resident VPC from #{@config['vpc']}"
          end

          subnet = nil
          @vpc.subnets.each { |s|
            if s.az == @config['region']
              subnet = s
              break
            end
          }
puts @config['credentials']
          service_acct = MU::Cloud::Google::Server.createServiceAccount(
            @mu_name.downcase,
            @deploy,
            project: @config['project'],
            credentials: @config['credentials']
          )
          MU::Cloud::Google.grantDeploySecretAccess(service_acct.email, credentials: @config['credentials'])

          @config['ssh_user'] ||= "mu"

          node_desc = {
            :machine_type => @config['instance_type'],
            :preemptible => @config['preemptible'],
            :disk_size_gb => @config['disk_size_gb'],
            :labels => labels,
            :tags => [@mu_name.downcase],
            :service_account => service_acct.email,
            :oauth_scopes => ["https://www.googleapis.com/auth/compute", "https://www.googleapis.com/auth/devstorage.read_only"],
            :metadata => {
              "ssh-keys" => @config['ssh_user']+":"+@deploy.ssh_public_key
            }
          }
          [:local_ssd_count, :min_cpu_platform, :image_type].each { |field|
            if @config[field.to_s]
              node_desc[field] = @config[field.to_s]
            end
          }

# tpu
# ip_range
          nodeobj = if @config['min_size'] and @config['max_size']
            MU::Cloud::Google.container(:NodePool).new(
              name: @mu_name.downcase,
              initial_node_count: @config['instance_count'] || @config['min_size'],
              autoscaling: MU::Cloud::Google.container(:NodePoolAutoscaling).new(
                enabled: true,
                min_node_count: @config['min_size'],
                max_node_count: @config['max_size'],
              ),
              config: MU::Cloud::Google.container(:NodeConfig).new(node_desc)
            )
          else
            MU::Cloud::Google.container(:NodeConfig).new(node_desc)
          end
          locations = if @config['availability_zone']
            [@config['availability_zone']]
          else
            MU::Cloud::Google.listAZs(@config['region'])
          end

          desc = {
            :name => @mu_name.downcase,
            :description => @deploy.deploy_id,
            :network => @vpc.cloud_id,
            :subnetwork => subnet.cloud_id,
            :labels => labels,
            :resource_labels => labels,
            :locations => locations,
          }
          if nodeobj.is_a?(::Google::Apis::ContainerV1::NodeConfig)
            desc[:node_config] = nodeobj
            desc[:initial_node_count] = @config['instance_count']
          else
            desc[:node_pools] = [nodeobj]
          end

          if @config['max_pods']
# XXX  DefaultMaxPodsConstraint can only be used if IpAllocationPolicy.UseIpAliases is true
#            desc[:default_max_pods_constraint] = MU::Cloud::Google.container(:MaxPodsConstraint).new(
#              max_pods_per_node: @config['max_pods']
#            )
          end
          if @config['kubernetes'] and @config['kubernetes']['version']
            desc[:initial_cluster_version] = @config['kubernetes']['version']
          end

          requestobj = MU::Cloud::Google.container(:CreateClusterRequest).new(
            :cluster => MU::Cloud::Google.container(:Cluster).new(desc),
#            :parent => "projects/"+@config['project']+"/"+(@config['availability_zone'] ? @config['availability_zone'] : "-")
          )

          MU.log "Creating GKE cluster #{@mu_name.downcase}", MU::NOTICE, details: requestobj
          parent_arg = "projects/"+@config['project']+"/locations/"+locations.sample

          cluster = MU::Cloud::Google.container(credentials: @config['credentials']).create_project_location_cluster(
            parent_arg,
            requestobj
          )
          @cloud_id = parent_arg+"/clusters/"+@mu_name.downcase
MU.log @cloud_id, MU::WARN, details: cluster
          resp = nil
          begin
            resp = MU::Cloud::Google.container(credentials: @config['credentials']).get_project_location_cluster(@cloud_id)
            sleep 30 if resp.status != "RUNNING"
          end while resp.nil? or resp.status != "RUNNING"
#          labelCluster # XXX need newer API release

        end

        # Locate an existing ContainerCluster or ContainerClusters and return an array containing matching GCP resource descriptors for those that match.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching ContainerClusters
        def self.find(**args)
          args[:project] ||= args[:habitat]
          args[:project] ||= MU::Cloud::Google.defaultProject(args[:credentials])
          found = {}

          resp = MU::Cloud::Google.container(credentials: args[:credentials]).list_zone_clusters(args[:project], "-")#, parent: "projects/locations/-")
          if resp and resp.clusters and !resp.clusters.empty?
            resp.clusters.each { |c|
              if args[:cloud_id] and c.name != args[:cloud_id] and
                 c.self_link != args[:cloud_id]
                next
              end
              found[c.name] = c
            }
          end

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(rootparent: nil, billing: nil, habitats: nil)

          bok = {
            "cloud" => "Google",
            "project" => @config['project'],
            "credentials" => @config['credentials'],
            "cloud_id" => cloud_desc.name.dup,
            "name" => cloud_desc.name.dup
          }

          bok['region'] = cloud_desc.location.sub(/\-[a-z]$/, "")
          if cloud_desc.locations.size == 1
            bok['availability_zone'] = cloud_desc.locations.first
          end
          bok["instance_count"] = cloud_desc.current_node_count
          cloud_desc.network_config.network.match(/^projects\/(.*?)\/.*?\/networks\/([^\/]+)(?:$|\/)/)
          vpc_proj = Regexp.last_match[1]
          vpc_id = Regexp.last_match[2]

          bok['vpc'] = MU::Config::Ref.get(
            id: vpc_id,
            cloud: "Google",
            habitat: vpc_proj,
            credentials: @config['credentials'],
            type: "vpcs"
          )

          bok['kubernetes'] = {
            "version" => cloud_desc.current_master_version.gsub(/\-.*/, "")
          }

          if cloud_desc.node_pools
            pool = cloud_desc.node_pools.first # we don't really support multiples atm
            bok["instance_type"] = pool.config.machine_type
            bok["disk_size_gb"] = pool.config.disk_size_gb
            bok["image_type"] = pool.config.image_type
            if pool.autoscaling
              bok['max_size'] = pool.autoscaling.max_node_count
              bok['min_size'] = pool.autoscaling.min_node_count
            end
          end

          MU.log @cloud_id, MU::NOTICE, details: cloud_desc
          MU.log bok['name'], MU::NOTICE, details: bok

          bok
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          resp = MU::Cloud::Google.container(credentials: @config['credentials']).get_project_location_cluster(@cloud_id)
#          pp resp

#          labelCluster # XXX need newer API release

          # desired_*:
          # addons_config
          # image_type
          # locations
          # master_authorized_networks_config
          # master_version
          # monitoring_service
          # node_pool_autoscaling
          # node_pool_id
          # node_version
#          update = {

#          }
#          pp update
#          requestobj = MU::Cloud::Google.container(:UpdateClusterRequest).new(
#            :cluster => MU::Cloud::Google.container(:ClusterUpdate).new(update)
#          )
           # XXX do all the kubernetes stuff like we do in AWS
        end

        # Register a description of this cluster instance with this deployment's metadata.
        def notify
          resp = MU::Cloud::Google.container(credentials: @config['credentials']).get_project_location_cluster(@cloud_id)
          desc = MU.structToHash(resp)
          desc["project"] = @config['project']
          desc["cloud_id"] = @cloud_id
          desc["project_id"] = @project_id
          desc["mu_name"] = @mu_name.downcase
          desc
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

        # Called by {MU::Cleanup}. Locates resources that were created by the
        # currently-loaded deployment, and purges them.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region in which to operate
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          skipsnapshots = flags["skipsnapshots"]

          flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)
          return if !MU::Cloud::Google::Habitat.isLive?(flags["project"], credentials)

          MU::Cloud::Google.listAZs(region).each { |az|
            found = MU::Cloud::Google.container(credentials: credentials).list_zone_clusters(flags["project"], az)
            if found and found.clusters
              found.clusters.each { |cluster|

                if !cluster.resource_labels or (
                     !cluster.name.match(/^#{Regexp.quote(MU.deploy_id)}\-/i) and
                     cluster.resource_labels['mu-id'] != MU.deploy_id.downcase
                   )
                  next
                end
                MU.log "Deleting GKE cluster #{cluster.name}"
                if !noop
                  begin
                    MU::Cloud::Google.container(credentials: credentials).delete_zone_cluster(flags["project"], az, cluster.name)
                    MU::Cloud::Google.container(credentials: credentials).get_zone_cluster(flags["project"], az, cluster.name)
                    sleep 60
                  rescue ::Google::Apis::ClientError => e
                    if e.message.match(/is currently creating cluster/)
                      sleep 60
                      retry
                    elsif !e.message.match(/notFound:/)
                      raise e
                    else
                      break
                    end
                  end while true
                end
              }
            end
          }
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "local_ssd_count" => {
              "type" => "integer",
              "description" => "The number of local SSD disks to be attached to workers. See https://cloud.google.com/compute/docs/disks/local-ssd#local_ssd_limits"
            },
            "disk_size_gb" => {
              "type" => "integer",
              "description" => "Size of the disk attached to each worker, specified in GB. The smallest allowed disk size is 10GB",
              "default" => 100
            },
            "max_pods" => {
              "type" => "integer",
              "description" => "Maximum number of pods allowed per node in this cluster",
              "default" => 30
            },
            "min_cpu_platform" => {
              "type" => "string",
              "description" => "Minimum CPU platform to be used by workers. The instances may be scheduled on the specified or newer CPU platform. Applicable values are the friendly names of CPU platforms, such as minCpuPlatform: 'Intel Haswell' or minCpuPlatform: 'Intel Sandy Bridge'."
            },
            "preemptible" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Whether the workers are created as preemptible VM instances. See: https://cloud.google.com/compute/docs/instances/preemptible for more information about preemptible VM instances."
            },
            "image_type" => {
              "type" => "string",
              "description" => "The image type to use for workers. Note that for a given image type, the latest version of it will be used."
            },
            "availability_zone" => {
              "type" => "string",
              "description" => "Target a specific availability zone for this cluster"
            },
            "ip_range" => {
              "type" => "string",
              "pattern" => MU::Config::CIDR_PATTERN,
              "description" => "The IP address range of the container pods in this cluster, in CIDR notation"
            },
            "tpu" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Enable the ability to use Cloud TPUs in this cluster."
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
# MU::Cloud::Google.container.get_project_zone_serverconfig(@config["project"], @config['availability_zone'])

          cluster['instance_type'] = MU::Cloud::Google::Server.validateInstanceType(cluster["instance_type"], cluster["region"])
          ok = false if cluster['instance_type'].nil?

          ok
        end

        private

        def labelCluster
          labels = {}
          MU::MommaCat.listStandardTags.each_pair { |name, value|
            if !value.nil?
              labels[name.downcase] = value.downcase.gsub(/[^a-z0-9\-\_]/i, "_")
            end
          }
          labels["name"] = MU::Cloud::Google.nameStr(@mu_name)

          labelset = MU::Cloud::Google.container(:SetLabelsRequest).new(
            resource_labels: labels
          )
          MU::Cloud::Google.container(credentials: @config['credentials']).resource_project_zone_cluster_labels(@config["project"], @config['availability_zone'], @mu_name.downcase, labelset)
        end

      end #class
    end #class
  end
end #module
