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

          master_user = @config['master_user']
          # We'll create a temporary basic auth config so that we can grant
          # useful permissions to the Client Certificate user
          master_user ||= "master_user"
          master_pw = Password.pronounceable(16..18)

          desc = {
            :name => @mu_name.downcase,
            :description => @deploy.deploy_id,
            :network => @vpc.cloud_id,
            :subnetwork => subnet.cloud_id,
            :labels => labels,
            :enable_tpu => @config['tpu'],
            :resource_labels => labels,
            :locations => locations,
            :master_auth => MU::Cloud::Google.container(:MasterAuth).new(
              :client_certificate_config => MU::Cloud::Google.container(:ClientCertificateConfig).new(
                :issue_client_certificate => true
              ),
              :username => master_user,
              :password => master_pw
            )
          }
          if nodeobj.is_a?(::Google::Apis::ContainerV1::NodeConfig)
            desc[:node_config] = nodeobj
            desc[:initial_node_count] = @config['instance_count']
          else
            desc[:node_pools] = [nodeobj]
          end

          if @config['kubernetes'] and @config['kubernetes']['version']
            desc[:initial_cluster_version] = @config['kubernetes']['version']
          end

          if @config['preferred_maintenance_window']
            desc[:maintenance_policy] = MU::Cloud::Google.container(:MaintenancePolicy).new(
              window: MU::Cloud::Google.container(:MaintenanceWindow).new(
                daily_maintenance_window: MU::Cloud::Google.container(:DailyMaintenanceWindow).new(
                  start_time: @config['preferred_maintenance_window']
                )
              )
            )
          end

          if @config['private_cluster']
            desc[:private_cluster_config] = MU::Cloud::Google.container(:PrivateClusterConfig).new(
              enable_private_endpoint: @config['private_cluster']['private_master'],
              enable_private_nodes: @config['private_cluster']['private_nodes'],
              master_ipv4_cidr_block: @config['private_cluster']['master_ip_block']
            )
            desc[:ip_allocation_policy] = MU::Cloud::Google.container(:IpAllocationPolicy).new(
              use_ip_aliases: true
            )
          end

          if @config['authorized_networks'] and @config['authorized_networks'].size > 0
            desc[:master_authorized_networks_config] = MU::Cloud::Google.container(:MasterAuthorizedNetworksConfig).new(
              enabled: true,
              cidr_blocks: @config['authorized_networks'].map { |n|
                MU::Cloud::Google.container(:CidrBlock).new(
                  cidr_block: n['ip_block'],
                  display_name: n['label']
                )
              }
            )
          end

          if @config['max_pods']
# XXX  DefaultMaxPodsConstraint can only be used if IpAllocationPolicy.UseIpAliases is true
#            desc[:default_max_pods_constraint] = MU::Cloud::Google.container(:MaxPodsConstraint).new(
#              max_pods_per_node: @config['max_pods']
#            )
          end

          requestobj = MU::Cloud::Google.container(:CreateClusterRequest).new(
            :cluster => MU::Cloud::Google.container(:Cluster).new(desc),
          )

          MU.log "Creating GKE cluster #{@mu_name.downcase}", details: requestobj

          parent_arg = "projects/"+@config['project']+"/locations/"+@config['master_az']
pp desc
          cluster = MU::Cloud::Google.container(credentials: @config['credentials']).create_project_location_cluster(
            parent_arg,
            requestobj
          )
          @cloud_id = parent_arg+"/clusters/"+@mu_name.downcase

          resp = nil
          begin
            resp = MU::Cloud::Google.container(credentials: @config['credentials']).get_project_location_cluster(@cloud_id)
            sleep 30 if resp.status != "RUNNING"
          end while resp.nil? or resp.status != "RUNNING"

          writeKubeConfig

          # delete our temporary master user if we didn't really want one
          if !@config['master_user']
#            :master_auth => MU::Cloud::Google.container(:MasterAuth).new(
#              :client_certificate_config => MU::Cloud::Google.container(:ClientCertificateConfig).new(
#                :issue_client_certificate => true
#              )
#            )
          end
#          labelCluster # XXX need newer API release

        end


        # Called automatically by {MU::Deploy#createResources}
        def groom
          me = cloud_desc

          parent_arg = "projects/"+@config['project']+"/locations/"+me.location

          # Enable/disable basic auth
          authcfg = {}
          action = nil
          if @config['master_user'] and (me.master_auth.username != @config['master_user'] or !me.master_auth.password)
            authcfg[:username] = @config['master_user']
            authcfg[:password] = Password.pronounceable(16..18)
            MU.log "Enabling basic auth for GKE cluster #{@mu_name.downcase}", MU::NOTICE, details: authcfg
          elsif !@config['master_user'] and me.master_auth.username
            authcfg[:username] = ""
            MU.log "Disabling basic auth for GKE cluster #{@mu_name.downcase}", MU::NOTICE
          end
          if authcfg.size > 0
            MU::Cloud::Google.container(credentials: @config['credentials']).set_project_location_cluster_master_auth(
              @cloud_id,
              MU::Cloud::Google.container(:SetMasterAuthRequest).new(
                name: @cloud_id,
                action: "SET_USERNAME",
                update: MU::Cloud::Google.container(:MasterAuth).new(
                  authcfg
                )
              )
            )
            me = cloud_desc(use_cache: false)
          end

          # Now go through all the things that use update_project_location_cluster
          update_desc = {}

          locations = if @config['availability_zone']
            [@config['availability_zone']]
          else
            MU::Cloud::Google.listAZs(@config['region'])
          end
          if me.locations != locations
            update_desc[:desired_locations] = locations
          end

          if @config['authorized_networks'] and @config['authorized_networks'].size > 0
            desired = @config['authorized_networks'].map { |n|
              MU::Cloud::Google.container(:CidrBlock).new(
                cidr_block: n['ip_block'],
                display_name: n['label']
              )
            }
            if !me.master_authorized_networks_config or
               !me.master_authorized_networks_config.enabled or
               !me.master_authorized_networks_config.cidr_blocks or
               me.master_authorized_networks_config.cidr_blocks.map {|n| n.cidr_block+n.display_name }.sort != desired.map {|n| n.cidr_block+n.display_name }.sort
              update_desc[:desired_master_authorized_networks_config ] = MU::Cloud::Google.container(:MasterAuthorizedNetworksConfig).new(
                enabled: true,
                cidr_blocks: desired
              )
            end
          elsif me.master_authorized_networks_config and
                me.master_authorized_networks_config.enabled
            update_desc[:desired_master_authorized_networks_config ] = MU::Cloud::Google.container(:MasterAuthorizedNetworksConfig).new(
              enabled: false
            )
          end

          if @config['kubernetes'] and @config['kubernetes']['version']
            if MU.version_sort(@config['kubernetes']['version'], me.current_master_version) > 0
              update_desc[:desired_master_version] = @config['kubernetes']['version']
            end
          end

          if @config['kubernetes'] and @config['kubernetes']['nodeversion']
            if MU.version_sort(@config['kubernetes']['nodeversion'], me.current_node_version) > 0
              update_desc[:desired_node_version] = @config['kubernetes']['nodeversion']
            end
          end

          if update_desc.size > 0
            update_desc.each_pair { |key, value|
              requestobj = MU::Cloud::Google.container(:UpdateClusterRequest).new(
                :name => @cloud_id,
                :update => MU::Cloud::Google.container(:ClusterUpdate).new(
                  { key =>value }
                )
              )
              MU.log "Updating GKE Cluster #{@mu_name.downcase} '#{key.to_s}'", MU::NOTICE, details: value
              begin
                MU::Cloud::Google.container(credentials: @config['credentials']).update_project_location_cluster(
                  @cloud_id,
                  requestobj
                )
              rescue ::Google::Apis::ClientError => e
                MU.log e.message, MU::WARN
              end
            }
            me = cloud_desc(use_cache: false)
          end

          if @config['preferred_maintenance_window'] and
             (!me.maintenance_policy.window or
              !me.maintenance_policy.window.daily_maintenance_window or
              me.maintenance_policy.window.daily_maintenance_window.start_time != @config['preferred_maintenance_window'])
            MU.log "Setting GKE Cluster #{@mu_name.downcase} maintenance time to #{@config['preferred_maintenance_window']}", MU::NOTICE
            MU::Cloud::Google.container(credentials: @config['credentials']).set_project_location_cluster_maintenance_policy(
              @cloud_id,
              MU::Cloud::Google.container(:SetMaintenancePolicyRequest).new(
                maintenance_policy: MU::Cloud::Google.container(:MaintenancePolicy).new(
                  window: MU::Cloud::Google.container(:MaintenanceWindow).new(
                    daily_maintenance_window: MU::Cloud::Google.container(:DailyMaintenanceWindow).new(
                      start_time: @config['preferred_maintenance_window']
                    )
                  )
                )
              )
            )
          elsif !@config['preferred_maintenance_window'] and me.maintenance_policy.window
            MU.log "Unsetting GKE Cluster #{@mu_name.downcase} maintenance time to #{@config['preferred_maintenance_window']}", MU::NOTICE
            MU::Cloud::Google.container(credentials: @config['credentials']).set_project_location_cluster_maintenance_policy(
              @cloud_id,
              nil
            )
          end


          kube_conf = writeKubeConfig

          if @config['kubernetes_resources']
            MU::Master.applyKubernetesResources(
              @config['name'], 
              @config['kubernetes_resources'],
              kubeconfig: kube_conf,
              outputdir: @deploy.deploy_dir
            )
          end

          MU.log %Q{How to interact with your Kubernetes cluster\nkubectl --kubeconfig "#{kube_conf}" get events --all-namespaces\nkubectl --kubeconfig "#{kube_conf}" get all\nkubectl --kubeconfig "#{kube_conf}" create -f some_k8s_deploy.yml\nkubectl --kubeconfig "#{kube_conf}" get nodes}, MU::SUMMARY

#          labelCluster # XXX need newer API release

          # desired_*:
          # addons_config
          # image_type
          # locations
          # monitoring_service
          # node_pool_autoscaling
          # node_pool_id
           # XXX do all the kubernetes stuff like we do in AWS
        end

        def writeKubeConfig
          kube_conf = @deploy.deploy_dir+"/kubeconfig-#{@config['name']}"
          client_binding = @deploy.deploy_dir+"/k8s-client-user-admin-binding.yaml"
          @endpoint = "https://"+cloud_desc.endpoint
          @cacert = cloud_desc.master_auth.cluster_ca_certificate
          @cluster = cloud_desc.name
          @clientcert = cloud_desc.master_auth.client_certificate
          @clientkey = cloud_desc.master_auth.client_key
          if cloud_desc.master_auth.username
            @username = cloud_desc.master_auth.username
          end
          if cloud_desc.master_auth.password
            @password = cloud_desc.master_auth.password
          end

          kube = ERB.new(File.read(MU.myRoot+"/cookbooks/mu-tools/templates/default/kubeconfig-gke.erb"))
          File.open(kube_conf, "w"){ |k|
            k.puts kube.result(binding)
          }

          # Take this opportunity to ensure that the 'client' service account
          # used by certificate authentication exists and has appropriate
          # privilege
          if @username and @password
            File.open(client_binding, "w"){ |k|
              k.puts <<-EOF
kind: ClusterRoleBinding 
apiVersion: rbac.authorization.k8s.io/v1
metadata: 
  name: client-binding
  namespace: kube-system
roleRef: 
  kind: ClusterRole 
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
subjects: 
- kind: User
  name: client
  namespace: kube-system
              EOF
            }
            bind_cmd = %Q{#{MU::Master.kubectl} create serviceaccount client --namespace=kube-system --kubeconfig "#{kube_conf}" ; #{MU::Master.kubectl} --kubeconfig "#{kube_conf}" apply -f #{client_binding}}
            MU.log bind_cmd
            system(bind_cmd)
          end
          # unset the variables we set just for ERB
          [:@endpoint, :@cacert, :@cluster, :@clientcert, :@clientkey, :@username, :@password].each { |var|
            begin
              remove_instance_variable(var)
            rescue NameError
            end
          }

          kube_conf
        end

        # Locate an existing ContainerCluster or ContainerClusters and return an array containing matching GCP resource descriptors for those that match.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching ContainerClusters
        def self.find(**args)
          args[:project] ||= args[:habitat]
          args[:project] ||= MU::Cloud::Google.defaultProject(args[:credentials])
          found = {}

          if args[:cloud_id]
            resp = MU::Cloud::Google.container(credentials: args[:credentials]).get_project_location_cluster(args[:cloud_id])
            found[args[:cloud_id]] = resp if resp
          else
            resp = MU::Cloud::Google.container(credentials: args[:credentials]).list_project_location_clusters("projects/#{args[:project]}/locations/-")
            if resp and resp.clusters and !resp.clusters.empty?
              resp.clusters.each { |c|
                found[c.self_link.sub(/.*?\/projects\//, 'projects/')] = c
              }
            end
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
            "version" => cloud_desc.current_master_version,
            "nodeversion" => cloud_desc.current_node_version
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

          if cloud_desc.private_cluster_config
            if cloud_desc.private_cluster_config.enable_private_nodes?
              bok["private_cluster"] ||= {}
              bok["private_cluster"]["private_nodes"] = true
            end
            if cloud_desc.private_cluster_config.enable_private_endpoint?
              bok["private_cluster"] ||= {}
              bok["private_cluster"]["private_master"] = true
            end
          end

          MU.log @cloud_id, MU::NOTICE, details: cloud_desc
          MU.log bok['name'], MU::NOTICE, details: bok

          bok
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
            "private_cluster" => {
              "description" => "Set a GKE cluster to be private, that is segregated into its own hidden VPC.",
              "type" => "object",
              "properties" => {
                "private_nodes" => {
                  "type" => "boolean",
                  "default" => true,
                  "description" => "Whether GKE worker nodes have internal IP addresses only."
                },
                "private_master" => {
                  "type" => "boolean",
                  "default" => false,
                  "description" => "Whether the GKE Kubernetes master's internal IP address is used as the cluster endpoint."
                },
                "master_ip_block" => {
                  "type" => "string",
                  "pattern" => MU::Config::CIDR_PATTERN,
                  "default" => "172.20.0.0/28",
                  "description" => "The private IP address range to use for the GKE master's network"
                }
              }
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
            "min_size" => {
              "description" => "In GKE, this is the minimum number of nodes *per availability zone*, when scaling is enabled. Setting +min_size+ and +max_size+ enables scaling."
            },
            "max_size" => {
              "description" => "In GKE, this is the maximum number of nodes *per availability zone*, when scaling is enabled. Setting +min_size+ and +max_size+ enables scaling."
            },
            "instance_count" => {
              "description" => "In GKE, this value is ignored if +min_size+ and +max_size+ are set."
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
              "enum" => defaults.valid_image_types,
              "description" => "The image type to use for workers. Note that for a given image type, the latest version of it will be used.",
              "default" => defaults.default_image_type
            },
            "availability_zone" => {
              "type" => "string",
              "description" => "Target a specific availability zone for this cluster"
            },
            "preferred_maintenance_window" => {
              "type" => "string",
              "description" => "The preferred daily time to perform node maintenance. Time format should be in [RFC3339](http://www.ietf.org/rfc/rfc3339.txt) format +HH:MM+ GMT.",
              "pattern" => '^\d\d:\d\d$'
            },
            "kubernetes" => {
              "properties" => {
                "version" => {
                  "type" => "string"
                },
                "nodeversion" => {
                  "type" => "string",
                  "description" => "The version of Kubernetes to install on GKE worker nodes."
                }
              }
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
            },
            "master_user" => {
              "type" => "string",
              "description" => "Enables Basic Auth for a GKE cluster with string as the master username"
            },
            "authorized_networks" => {
              "type" => "array",
              "items" => {
                "description" => "GKE's Master authorized networks functionality",
                "type" => "object",
                "ip_block" => {
                  "type" => "string",
                  "description" => "CIDR block to allow",
                  "pattern" => MU::Config::CIDR_PATTERN,
                },
                "label" =>{
                  "description" => "Label for this CIDR block",
                  "type" => "string",
                }
              }
            },
            "master_az" => {
              "type" => "string",
              "description" => "Target a specific Availability Zone for the GKE master. If not set, we will choose one which has the most current versions of Kubernetes available."
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

          cluster['master_az'] ||= cluster['availability_zone']

          # If we haven't been asked for plant the master in a specific AZ, pick
          # the one (or one of the ones) that supports the most recent versions
          # of Kubernetes.
          if !cluster['master_az']
            best_version = nil
            best_az = nil
            MU::Cloud::Google.listAZs(cluster['region']).shuffle.each { |az|
              best_in_az = defaults(az: az).valid_master_versions.sort { |a, b| MU.version_sort(a, b) }.last
              best_version ||= best_in_az
              best_az ||= az
              if MU.version_sort(best_in_az, best_version) > 0
                best_version = best_in_az
                best_az = az
              end
            }
            cluster['master_az'] = best_az
          end

          # If we've enabled master authorized networks, make sure our Mu
          # Master is one of the things allowed in.
          if cluster['authorized_networks']
            found_me = false
            my_cidr = NetAddr::IPv4.parse(MU.mu_public_ip)
            cluster['authorized_networks'].each { |block|
              cidr_obj = NetAddr::IPv4Net.parse(block['ip_block'])
              if cidr_obj.contains(my_cidr)
                found_me = true
                break
              end
            }
            if !found_me
              cluster['authorized_networks'] << {
                "ip_block" => MU.mu_public_ip+"/32",
                "label" => "Mu Master #{$MU_CFG['hostname']}"
              }
            end
          end

          master_versions = defaults(az: cluster['master_az']).valid_master_versions.sort { |a, b| MU.version_sort(a, b) }
          if cluster['kubernetes'] and cluster['kubernetes']['version']
            if cluster['kubernetes']['version'] == "latest"
              cluster['kubernetes']['version'] = master_versions.last
            elsif !master_versions.include?(cluster['kubernetes']['version'])
              match = false
              master_versions.each { |v|
                if v.match(/^#{Regexp.quote(cluster['kubernetes']['version'])}/)
                  match = true
                  break
                end
              }
              if !match
                MU.log "Failed to find a GKE master version matching #{cluster['kubernetes']['version']} among available versions in #{cluster['master_az']}.", MU::ERR, details: master_versions
                ok = false
              end
            end
          end

          node_versions = defaults(az: cluster['master_az']).valid_node_versions.sort { |a, b| MU.version_sort(a, b) }

          if cluster['kubernetes'] and cluster['kubernetes']['nodeversion']
            if cluster['kubernetes']['nodeversion'] == "latest"
              cluster['kubernetes']['nodeversion'] = node_versions.last
            elsif !node_versions.include?(cluster['kubernetes']['nodeversion'])
              match = false
              node_versions.each { |v|
                if v.match(/^#{Regexp.quote(cluster['kubernetes']['nodeversion'])}/)
                  match = true
                  break
                end
              }
              if !match
                MU.log "Failed to find a GKE node version matching #{cluster['kubernetes']['nodeversion']} among available versions in #{cluster['master_az']}.", MU::ERR, details: node_versions
                ok = false
              end
            end
          end

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

        @@server_config = {}
        def self.defaults(credentials = nil, az: nil)
          az ||= MU::Cloud::Google.listAZs.sample
          @@server_config[credentials] ||= {}
          if @@server_config[credentials][az]
            return @@server_config[credentials][az]
          end

          parent_arg = "projects/"+MU::Cloud::Google.defaultProject(credentials)+"/locations/"+az

          @@server_config[credentials][az] = MU::Cloud::Google.container(credentials: credentials).get_project_location_server_config(parent_arg)
          @@server_config[credentials][az]
        end


      end #class
    end #class
  end
end #module
