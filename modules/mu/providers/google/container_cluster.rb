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


          sa = MU::Config::Ref.get(@config['service_account'])
          if sa.name and @deploy.findLitterMate(name: sa.name, type: "users")
            @service_acct = @deploy.findLitterMate(name: sa.name, type: "users").cloud_desc
          else
            if !sa or !sa.kitten or !sa.kitten.cloud_desc
              raise MuError, "Failed to get service account cloud id from #{@config['service_account'].to_s}"
            end
            @service_acct = sa.kitten.cloud_desc
          end
          if !@config['scrub_mu_isms']
            MU::Cloud::Google.grantDeploySecretAccess(@service_acct.email, credentials: @config['credentials'])
          end

          @config['ssh_user'] ||= "muadmin"


          nodeobj = if @config['min_size'] and @config['max_size']
            MU::Cloud::Google.container(:NodePool).new(
              name: @mu_name.downcase,
              initial_node_count: @config['instance_count'] || @config['min_size'],
              autoscaling: MU::Cloud::Google.container(:NodePoolAutoscaling).new(
                enabled: true,
                min_node_count: @config['min_size'],
                max_node_count: @config['max_size'],
              ),
              management: MU::Cloud::Google.container(:NodeManagement).new(
                auto_upgrade: @config['auto_upgrade'],
                auto_repair: @config['auto_repair']
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
          master_pw = Password.pronounceable(18)

          desc = {
            :name => @mu_name.downcase,
            :description => @deploy.deploy_id,
            :network => @vpc.url,
            :enable_tpu => @config['tpu'],
            :resource_labels => labels,
            :locations => locations,
            :master_auth => MU::Cloud::Google.container(:MasterAuth).new(
              :client_certificate_config => MU::Cloud::Google.container(:ClientCertificateConfig).new(
                :issue_client_certificate => true
              ),
              :username => master_user,
              :password => master_pw
            ),
          }


          if @config['kubernetes']
            desc[:addons_config] = MU::Cloud::Google.container(:AddonsConfig).new(
              horizontal_pod_autoscaling: MU::Cloud::Google.container(:HorizontalPodAutoscaling).new(
                disabled: !@config['kubernetes']['horizontal_pod_autoscaling']
              ),
              http_load_balancing: MU::Cloud::Google.container(:HttpLoadBalancing).new(
                disabled: !@config['kubernetes']['http_load_balancing']
              ),
              kubernetes_dashboard: MU::Cloud::Google.container(:KubernetesDashboard).new(
                disabled: !@config['kubernetes']['dashboard']
              ),
              network_policy_config: MU::Cloud::Google.container(:NetworkPolicyConfig).new(
                disabled: !@config['kubernetes']['network_policy_addon']
              )
            )
          end

          # Pick an existing subnet from our VPC, if we're not going to create
          # one.
          if !@config['custom_subnet']
            @vpc.subnets.each { |s|
              if s.az == @config['region']
                desc[:subnetwork] = s.cloud_id
                break
              end
            }
          end


          if @config['log_facility'] == "kubernetes"
            desc[:logging_service] = "logging.googleapis.com/kubernetes"
            desc[:monitoring_service] = "monitoring.googleapis.com/kubernetes"
          elsif @config['log_facility'] == "basic"
            desc[:logging_service] = "logging.googleapis.com"
            desc[:monitoring_service] = "monitoring.googleapis.com"
          else
            desc[:logging_service] = "none"
            desc[:monitoring_service] = "none"
          end

          if nodeobj.is_a?(::Google::Apis::ContainerV1::NodeConfig)
            desc[:node_config] = nodeobj
            desc[:initial_node_count] = @config['instance_count']
          else
            desc[:node_pools] = [nodeobj]
          end

          if @config['kubernetes']
            if @config['kubernetes']['version']
              desc[:initial_cluster_version] = @config['kubernetes']['version']
            end
            if @config['kubernetes']['alpha']
              desc[:enable_kubernetes_alpha] = @config['kubernetes']['alpha']
            end
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


          if @config['ip_aliases'] or @config['custom_subnet'] or
             @config['services_ip_block'] or @config['services_ip_block_name'] or
             @config['pod_ip_block'] or @config['pod_ip_block_name'] or
             @config['tpu_ip_block']
            alloc_desc = { :use_ip_aliases => @config['ip_aliases'] }

            if @config['custom_subnet']
              alloc_desc[:create_subnetwork] = true
              alloc_desc[:subnetwork_name] = if @config['custom_subnet']['name']
                @config['custom_subnet']['name']
              else
                @mu_name.downcase
              end

              if @config['custom_subnet']['node_ip_block']
                alloc_desc[:node_ipv4_cidr_block] = @config['custom_subnet']['node_ip_block']
              end
            else
              if @config['pod_ip_block_name']
                alloc_desc[:cluster_secondary_range_name] = @config['pod_ip_block_name']
              end
              if @config['services_ip_block_name']
                alloc_desc[:services_secondary_range_name] = @config['services_ip_block_name']
              end
            end

            if @config['services_ip_block']
              if @vpc.project_id != @project_id
                alloc_desc[:services_secondary_range_name] ||= @config['name']+"-services"
                @vpc.addSecondaryRange(desc[:subnetwork], @config['services_ip_block'], alloc_desc[:services_secondary_range_name])

              end
              alloc_desc[:services_ipv4_cidr_block] = @config['services_ip_block']
            end
            if @config['tpu_ip_block']
              alloc_desc[:tpu_ipv4_cidr_block] = @config['tpu_ip_block']
            end
            if @config['pod_ip_block']
              if @vpc.project_id != @project_id
                alloc_desc[:cluster_secondary_range_name] ||= @config['name']+"-pods"
                @vpc.addSecondaryRange(desc[:subnetwork], @config['pod_ip_block'], alloc_desc[:cluster_secondary_range_name])

              end
              alloc_desc[:cluster_ipv4_cidr_block] = @config['pod_ip_block']
            end

            desc[:ip_allocation_policy] = MU::Cloud::Google.container(:IpAllocationPolicy).new(alloc_desc)
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

          if @config['kubernetes'] and @config['kubernetes']['max_pods'] and
             @config['ip_aliases']
            desc[:default_max_pods_constraint] = MU::Cloud::Google.container(:MaxPodsConstraint).new(
              max_pods_per_node: @config['kubernetes']['max_pods']
            )
          end

          requestobj = MU::Cloud::Google.container(:CreateClusterRequest).new(
            :cluster => MU::Cloud::Google.container(:Cluster).new(desc),
          )

          MU.log "Creating GKE cluster #{@mu_name.downcase}", details: requestobj
          @config['master_az'] = @config['region']
          parent_arg = "projects/"+@config['project']+"/locations/"+@config['master_az']

          MU::Cloud::Google.container(credentials: @config['credentials']).create_project_location_cluster(
            parent_arg,
            requestobj
          )
          @cloud_id = parent_arg+"/clusters/"+@mu_name.downcase

          resp = nil
          begin
            resp = MU::Cloud::Google.container(credentials: @config['credentials']).get_project_location_cluster(@cloud_id)
            if resp.status == "ERROR"
              MU.log "GKE cluster #{@cloud_id} failed", MU::ERR, details: resp.status_message
              raise MuError, "GKE cluster #{@cloud_id} failed: #{resp.status_message}"
            end
            sleep 30 if resp.status != "RUNNING"
          end while resp.nil? or resp.status != "RUNNING"

          writeKubeConfig

        end


        # Called automatically by {MU::Deploy#createResources}
        def groom
          labelCluster 

          me = cloud_desc

          # Enable/disable basic auth
          authcfg = {}

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
          updates = []

          locations = if @config['availability_zone']
            [@config['availability_zone']]
          else
            MU::Cloud::Google.listAZs(@config['region'])
          end
          if me.locations != locations
            updates << { :desired_locations => locations }
          end

          if @config['min_size'] and @config['max_size'] and
             (me.node_pools.first.autoscaling.min_node_count != @config['min_size'] or
             me.node_pools.first.autoscaling.max_node_count != @config['max_size'])
            updates << {
              :desired_node_pool_autoscaling => MU::Cloud::Google.container(:NodePoolAutoscaling).new(
                enabled: true,
                max_node_count: @config['max_size'],
                min_node_count: @config['min_size']
              )
            }
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
              updates << { :desired_master_authorized_networks_config => MU::Cloud::Google.container(:MasterAuthorizedNetworksConfig).new(
                enabled: true,
                cidr_blocks: desired
              )}
            end
          elsif me.master_authorized_networks_config and
                me.master_authorized_networks_config.enabled
            updates << { :desired_master_authorized_networks_config => MU::Cloud::Google.container(:MasterAuthorizedNetworksConfig).new(
              enabled: false
            )}
          end

          if @config['log_facility'] == "kubernetes" and me.logging_service != "logging.googleapis.com/kubernetes"
            updates << {
              :desired_logging_service => "logging.googleapis.com/kubernetes",
              :desired_monitoring_service => "monitoring.googleapis.com/kubernetes"
            }
          elsif @config['log_facility'] == "basic" and me.logging_service != "logging.googleapis.com"
            updates << {
              :desired_logging_service => "logging.googleapis.com",
              :desired_monitoring_service => "monitoring.googleapis.com"
            }
          elsif @config['log_facility'] == "none" and me.logging_service != "none"
            updates << {
              :desired_logging_service => "none",
              :desired_monitoring_service => "none"
            }
          end

          # map from GKE Kuberentes addon parameter names to our BoK equivalent
          # fields so we can check all these programmatically
          addon_map = {
            :horizontal_pod_autoscaling => 'horizontal_pod_autoscaling',
            :http_load_balancing => 'http_load_balancing',
            :kubernetes_dashboard => 'dashboard',
            :network_policy_config => 'network_policy_addon'
          }

          if @config['kubernetes']
            have_changes = false
            addon_map.each_pair { |param, bok_param|
              if (me.addons_config.send(param).disabled and @config['kubernetes'][bok_param]) or
                 (!me.addons_config.send(param) and !@config['kubernetes'][bok_param])
                have_changes = true
              end
            }
            if have_changes
              updates << { :desired_addons_config => MU::Cloud::Google.container(:AddonsConfig).new(
                horizontal_pod_autoscaling: MU::Cloud::Google.container(:HorizontalPodAutoscaling).new(
                  disabled: !@config['kubernetes']['horizontal_pod_autoscaling']
                ),
                http_load_balancing: MU::Cloud::Google.container(:HttpLoadBalancing).new(
                  disabled: !@config['kubernetes']['http_load_balancing']
                ),
                kubernetes_dashboard: MU::Cloud::Google.container(:KubernetesDashboard).new(
                  disabled: !@config['kubernetes']['dashboard']
                ),
                network_policy_config: MU::Cloud::Google.container(:NetworkPolicyConfig).new(
                  disabled: !@config['kubernetes']['network_policy_addon']
                )
              )}
            end 
          end

          if @config['kubernetes'] and @config['kubernetes']['version']
            if MU.version_sort(@config['kubernetes']['version'], me.current_master_version) > 0
              updates << {  :desired_master_version => @config['kubernetes']['version'] }
            end
          end

          if @config['kubernetes'] and @config['kubernetes']['nodeversion']
            if MU.version_sort(@config['kubernetes']['nodeversion'], me.current_node_version) > 0
              updates << { :desired_node_version => @config['kubernetes']['nodeversion'] }
            end
          end

          if updates.size > 0
            updates.each { |mapping|
              requestobj = MU::Cloud::Google.container(:UpdateClusterRequest).new(
                :name => @cloud_id,
                :update => MU::Cloud::Google.container(:ClusterUpdate).new(
                  mapping
                )
              )
              MU.log "Updating GKE Cluster #{@mu_name.downcase}", MU::NOTICE, details: mapping
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

          MU.log %Q{How to interact with your GKE cluster\nkubectl --kubeconfig "#{kube_conf}" get events --all-namespaces\nkubectl --kubeconfig "#{kube_conf}" get all\nkubectl --kubeconfig "#{kube_conf}" create -f some_k8s_deploy.yml\nkubectl --kubeconfig "#{kube_conf}" get nodes}, MU::SUMMARY
        end

        # Locate an existing ContainerCluster or ContainerClusters and return an array containing matching GCP resource descriptors for those that match.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching ContainerClusters
        def self.find(**args)
          args = MU::Cloud::Google.findLocationArgs(args)

          found = {}

          if args[:cloud_id]
            resp = begin
              MU::Cloud::Google.container(credentials: args[:credentials]).get_project_location_cluster(args[:cloud_id])
            rescue ::Google::Apis::ClientError => e
              raise e if !e.message.match(/forbidden:/)
            end
            found[args[:cloud_id]] = resp if resp
          else
            resp = begin
              MU::Cloud::Google.container(credentials: args[:credentials]).list_project_location_clusters("projects/#{args[:project]}/locations/#{args[:location]}")
            rescue ::Google::Apis::ClientError => e
              raise e if !e.message.match(/forbidden:/)
            end
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
        def toKitten(**_args)

          bok = {
            "cloud" => "Google",
            "project" => @config['project'],
            "credentials" => @config['credentials'],
            "cloud_id" => @cloud_id,
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
            habitat: MU::Config::Ref.get(
              id: vpc_proj,
              cloud: "Google",
              credentials: @credentials,
              type: "habitats"
            ),
            credentials: @config['credentials'],
            type: "vpcs"
          )


          bok['kubernetes'] = {
            "version" => cloud_desc.current_master_version,
            "nodeversion" => cloud_desc.current_node_version
          }
          if cloud_desc.default_max_pods_constraint and
             cloud_desc.default_max_pods_constraint.max_pods_per_node
            bok['kubernetes']['max_pods'] = cloud_desc.default_max_pods_constraint.max_pods_per_node
          end

          if cloud_desc.addons_config.horizontal_pod_autoscaling and
             cloud_desc.addons_config.horizontal_pod_autoscaling.disabled
            bok['kubernetes']['horizontal_pod_autoscaling'] = false
          end
          if cloud_desc.addons_config.http_load_balancing and
             cloud_desc.addons_config.http_load_balancing.disabled
            bok['kubernetes']['http_load_balancing'] = false
          end
          if !cloud_desc.addons_config.kubernetes_dashboard or
             !cloud_desc.addons_config.kubernetes_dashboard.disabled
            bok['kubernetes']['dashboard'] = true
          end
          if !cloud_desc.addons_config.network_policy_config or
             !cloud_desc.addons_config.network_policy_config.disabled
            bok['kubernetes']['network_policy_addon'] = true
          end

          if cloud_desc.ip_allocation_policy
            if cloud_desc.ip_allocation_policy.use_ip_aliases
              bok['ip_aliases'] = true
            end
            if cloud_desc.ip_allocation_policy.cluster_ipv4_cidr_block
              bok['pod_ip_block'] = cloud_desc.ip_allocation_policy.cluster_ipv4_cidr_block
            end
            if cloud_desc.ip_allocation_policy.services_ipv4_cidr_block
              bok['services_ip_block'] = cloud_desc.ip_allocation_policy.services_ipv4_cidr_block
            end

            if cloud_desc.ip_allocation_policy.create_subnetwork
              bok['custom_subnet'] = {
                "name" => (cloud_desc.ip_allocation_policy.subnetwork_name || cloud_desc.subnetwork)
              }
              if cloud_desc.ip_allocation_policy.node_ipv4_cidr_block
                bok['custom_subnet']['node_ip_block'] = cloud_desc.ip_allocation_policy.node_ipv4_cidr_block
              end
            end
          end

          bok['log_facility'] = if cloud_desc.logging_service == "logging.googleapis.com"
            "basic"
          elsif cloud_desc.logging_service == "logging.googleapis.com/kubernetes"
            "kubernetes"
          else
            "none"
          end

          if cloud_desc.master_auth and cloud_desc.master_auth.username
            bok['master_user'] = cloud_desc.master_auth.username
          end

          if cloud_desc.maintenance_policy and
             cloud_desc.maintenance_policy.window and
             cloud_desc.maintenance_policy.window.daily_maintenance_window and
             cloud_desc.maintenance_policy.window.daily_maintenance_window.start_time
            bok['preferred_maintenance_window'] = cloud_desc.maintenance_policy.window.daily_maintenance_window.start_time
          end

          if cloud_desc.enable_tpu
            bok['tpu'] = true
          end
          if cloud_desc.enable_kubernetes_alpha
            bok['kubernetes'] ||= {}
            bok['kubernetes']['alpha'] = true
          end

          if cloud_desc.node_pools and cloud_desc.node_pools.size > 0
            pool = cloud_desc.node_pools.first # we don't really support multiples atm
            bok["instance_type"] = pool.config.machine_type
            bok["instance_count"] = pool.initial_node_count
            bok['scopes'] = pool.config.oauth_scopes
            if pool.config.metadata
              bok["metadata"] = pool.config.metadata.keys.map { |k|
                { "key" => k, "value" => pool.config.metadata[k] }
              }
            end
            if pool.autoscaling and pool.autoscaling.enabled
              bok['max_size'] = pool.autoscaling.max_node_count
              bok['min_size'] = pool.autoscaling.min_node_count
            end
            bok['auto_repair'] = false
            bok['auto_upgrade'] = false
            if pool.management
              bok['auto_repair'] = true if pool.management.auto_repair
              bok['auto_upgrade'] = true if pool.management.auto_upgrade
            end
            [:local_ssd_count, :min_cpu_platform, :image_type, :disk_size_gb, :preemptible, :service_account].each { |field|
              if pool.config.respond_to?(field)
                bok[field.to_s] = pool.config.method(field).call
                bok.delete(field.to_s) if bok[field.to_s].nil?
              end
            }
          else
            bok["instance_type"] = cloud_desc.node_config.machine_type
            bok['scopes'] = cloud_desc.node_config.oauth_scopes
            if cloud_desc.node_config.metadata
              bok["metadata"] = cloud_desc.node_config.metadata.keys.map { |k|
                { "key" => k, "value" => pool.config.metadata[k] }
              }
            end
            [:local_ssd_count, :min_cpu_platform, :image_type, :disk_size_gb, :preemptible, :service_account].each { |field|
              if cloud_desc.node_config.respond_to?(field)
                bok[field.to_s] = cloud_desc.node_config.method(field).call
                bok.delete(field.to_s) if bok[field.to_s].nil?
              end
            }
          end

          if bok['service_account']
            found = MU::Cloud.resourceClass("Google", "User").find(
              credentials: bok['credentials'],
              project: bok['project'],
              cloud_id: bok['service_account']
            )
            if found and found.size == 1
              sa = found.values.first
              # Ignore generic Mu service accounts
              if cloud_desc.resource_labels and
                 cloud_desc.resource_labels["mu-id"] and 
                 sa.description and
                 cloud_desc.resource_labels["mu-id"].downcase == sa.description.downcase
                bok.delete("service_account")
              else
                bok['service_account'] = MU::Config::Ref.get(
                  id: found.values.first.name,
                  cloud: "Google",
                  credentials: @config['credentials'],
                  type: "users"
                )
              end
            else
              bok.delete("service_account")
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
            if cloud_desc.private_cluster_config.master_ipv4_cidr_block
              bok["private_cluster"] ||= {}
              bok["private_cluster"]["master_ip_block"] = cloud_desc.private_cluster_config.master_ipv4_cidr_block
            end
          end

          if cloud_desc.master_authorized_networks_config and
             cloud_desc.master_authorized_networks_config.cidr_blocks and
             cloud_desc.master_authorized_networks_config.cidr_blocks.size > 0
            bok['authorized_networks'] = []
            cloud_desc.master_authorized_networks_config.cidr_blocks.each { |c|
              bok['authorized_networks'] << {
                "ip_block" => c.cidr_block,
                "label" => c.display_name
              }
            }
          end

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
          MU::Cloud::RELEASE
        end

        # Called by {MU::Cleanup}. Locates resources that were created by the
        # currently-loaded deployment, and purges them.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region in which to operate
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})

          flags["habitat"] ||= MU::Cloud::Google.defaultProject(credentials)
          return if !MU::Cloud.resourceClass("Google", "Habitat").isLive?(flags["habitat"], credentials)
          clusters = []

          # Make sure we catch regional *and* zone clusters
          found = MU::Cloud::Google.container(credentials: credentials).list_project_location_clusters("projects/#{flags['habitat']}/locations/#{region}")
          clusters.concat(found.clusters) if found and found.clusters
          MU::Cloud::Google.listAZs(region).each { |az|
            found = MU::Cloud::Google.container(credentials: credentials).list_project_location_clusters("projects/#{flags['habitat']}/locations/#{az}")
            clusters.concat(found.clusters) if found and found.clusters
          }

          clusters.uniq.each { |cluster|
            if !cluster.resource_labels or (
                 !cluster.name.match(/^#{Regexp.quote(MU.deploy_id)}\-/i) and
                 (cluster.resource_labels['mu-id'] != MU.deploy_id.downcase or
                  (!ignoremaster and cluster.resource_labels['mu-master-ip'] != MU.mu_public_ip.gsub(/\./, "_"))
                 )
               )
              next
            end
            MU.log "Deleting GKE cluster #{cluster.name}"
            if !noop
              cloud_id = cluster.self_link.sub(/.*?\/projects\//, 'projects/')
              retries = 0
              begin
                MU::Cloud::Google.container(credentials: credentials).delete_project_location_cluster(cloud_id)
                MU::Cloud::Google.container(credentials: credentials).get_project_location_cluster(cloud_id)
                sleep 60
              rescue ::Google::Apis::ClientError => e
                if e.message.match(/notFound: /)
                  MU.log cloud_id, MU::WARN, details: e.inspect
                  break
                elsif e.message.match(/failedPrecondition: /)
                  if (retries % 5) == 0
                    MU.log "Waiting to delete GKE cluster #{cluster.name}: #{e.message}", MU::NOTICE
                  end
                  sleep 60
                  retries += 1
                  retry
                else
                  MU.log cloud_id, MU::WARN, details: e.inspect
                  raise e
                end
              end while true
            end
          }

        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          gke_defaults = defaults
          schema = {
            "auto_upgrade" => {
              "type" => "boolean",
              "description" => "Automatically upgrade worker nodes during maintenance windows",
              "default" => true
            },
            "auto_repair" => {
              "type" => "boolean",
              "description" => "Automatically replace worker nodes which fail health checks",
              "default" => true
            },
            "local_ssd_count" => {
              "type" => "integer",
              "description" => "The number of local SSD disks to be attached to workers. See https://cloud.google.com/compute/docs/disks/local-ssd#local_ssd_limits"
            },
            "ssh_user" => MU::Cloud.resourceClass("Google", "Server").schema(config)[1]["ssh_user"],
            "metadata" => MU::Cloud.resourceClass("Google", "Server").schema(config)[1]["metadata"],
            "service_account" => MU::Cloud.resourceClass("Google", "Server").schema(config)[1]["service_account"],
            "scopes" => MU::Cloud.resourceClass("Google", "Server").schema(config)[1]["scopes"],
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
            "custom_subnet" => {
              "type" => "object",
              "description" => "If set, GKE will create a new subnetwork specifically for this cluster",
              "properties" => {
                "name" => {
                  "type" => "string",
                  "description" => "Set a custom name for the generated subnet"
                },
                "node_ip_block" => {
                  "type" => "string",
                  "pattern" => MU::Config::CIDR_PATTERN,
                  "description" => "The IP address range of the worker nodes in this cluster, in CIDR notation"
                }
              }
            },
            "pod_ip_block" => {
              "type" => "string",
              "pattern" => MU::Config::CIDR_PATTERN,
              "description" => "The IP address range of the container pods in this cluster, in CIDR notation"
            },
            "pod_ip_block_name" => {
              "type" => "string",
              "description" => "The name of the secondary range to be used for the pod CIDR block"
            },
            "services_ip_block" => {
              "type" => "string",
              "pattern" => MU::Config::CIDR_PATTERN,
              "description" => "The IP address range of the services in this cluster, in CIDR notation"
            },
            "services_ip_block_name" => {
              "type" => "string",
              "description" => "The name of the secondary range to be used for the services CIDR block"
            },
            "ip_aliases" => {
              "type" => "boolean",
              "description" => "Whether alias IPs will be used for pod IPs in the cluster. Will be automatically enabled for functionality, such as +private_cluster+, which requires it."
            },
            "tpu_ip_block" => {
              "type" => "string",
              "pattern" => MU::Config::CIDR_PATTERN,
              "description" => "The IP address range of any Cloud TPUs in this cluster, in CIDR notation"
            },
            "disk_size_gb" => {
              "type" => "integer",
              "description" => "Size of the disk attached to each worker, specified in GB. The smallest allowed disk size is 10GB",
              "default" => 100
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
              "enum" => gke_defaults ? gke_defaults.valid_image_types : ["COS"],
              "description" => "The image type to use for workers. Note that for a given image type, the latest version of it will be used.",
              "default" => gke_defaults ? gke_defaults.default_image_type : "COS"
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
              "description" => "Kubernetes-specific options",
              "properties" => {
                "version" => {
                  "type" => "string"
                },
                "nodeversion" => {
                  "type" => "string",
                  "description" => "The version of Kubernetes to install on GKE worker nodes."
                },
                "alpha" => {
                  "type" => "boolean",
                  "default" => false,
                  "description" => "Enable alpha-quality Kubernetes features on this cluster"
                },
                "dashboard" => {
                  "type" => "boolean",
                  "default" => false,
                  "description" => "Enable the Kubernetes Dashboard"
                },
                "horizontal_pod_autoscaling" => {
                  "type" => "boolean",
                  "default" => true,
                  "description" => "Increases or decreases the number of replica pods a replication controller has based on the resource usage of the existing pods."
                },
                "http_load_balancing" => {
                  "type" => "boolean",
                  "default" => true,
                  "description" => "HTTP (L7) load balancing controller addon, which makes it easy to set up HTTP load balancers for services in a cluster."
                },
                "network_policy_addon" => {
                  "type" => "boolean",
                  "default" => false,
                  "description" => "Enable the Network Policy addon"
                }
              }
            },
            "pod_ip_range" => {
              "type" => "string",
              "pattern" => MU::Config::CIDR_PATTERN,
              "description" => "The IP address range of the container pods in this cluster, in CIDR notation"
            },
            "tpu" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Enable the ability to use Cloud TPUs in this cluster."
            },
            "log_facility" => {
              "type" => "string",
              "default" => "kubernetes",
              "description" => "The +logging.googleapis.com+ and +monitoring.googleapis.com+ facilities that this cluster should use to write logs and metrics.",
              "enum" => ["basic", "kubernetes", "none"]
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
          cluster['project'] ||= MU::Cloud::Google.defaultProject(cluster['credentials'])

          cluster['master_az'] ||= cluster['availability_zone'] if cluster['availability_zone']

          if cluster['private_cluster'] or cluster['custom_subnet'] or
             cluster['services_ip_block'] or cluster['services_ip_block_name'] or
             cluster['pod_ip_block'] or cluster['pod_ip_block_name'] or
             cluster['tpu_ip_block']
            cluster['ip_aliases'] = true
          end

          # try to stake out some nice /21s for our networking config
          if cluster['ip_aliases'] and cluster["vpc"] and cluster["vpc"]["id"]
            habarg = if cluster["vpc"]["habitat"] and cluster["vpc"]["habitat"]["id"]
              cluster["vpc"]["habitat"]["id"]
            else
              cluster["project"]
            end
            found = MU::MommaCat.findStray("Google", "vpcs", cloud_id: cluster["vpc"]["id"], credentials: cluster["credentials"], habitats: [habarg], dummy_ok: true)
            if found and found.size == 1
              myvpc = found.first
# XXX this might not make sense with custom_subnet
              cluster['pod_ip_block'] ||= myvpc.getUnusedAddressBlock(max_bits: 21)
              cluster['services_ip_block'] ||= myvpc.getUnusedAddressBlock(exclude: [cluster['pod_ip_block']], max_bits: 21)
              if cluster['tpu']
                cluster['tpu_ip_block'] ||= myvpc.getUnusedAddressBlock(exclude: [cluster['pod_ip_block'], cluster['services_ip_block']], max_bits: 21)
              end
            end
          end

          if cluster['service_account']
            cluster['service_account']['cloud'] = "Google"
            cluster['service_account']['habitat'] ||= MU::Config::Ref.get(
              id: cluster['project'],
              cloud: "Google",
              credentials: cluster['credentials'],
              type: "habitats"
            )
            if cluster['service_account']['name'] and
               !cluster['service_account']['id'] and
               !cluster['service_account']['deploy_id']
              MU::Config.addDependency(cluster, cluster['service_account']['name'], "user")
            end
            found = MU::Config::Ref.get(cluster['service_account'])
            # XXX verify that found.kitten fails when it's supposed to
            if cluster['service_account']['id'] and !found.kitten
              MU.log "GKE cluster #{cluster['name']} failed to locate service account #{cluster['service_account']} in project #{cluster['project']}", MU::ERR
              ok = false
            end
          else
            cluster = MU::Cloud.resourceClass("Google", "User").genericServiceAccount(cluster, configurator)
          end

          if cluster['dependencies']
            cluster['dependencies'].each { |dep|
              if dep['type'] == "vpc"
                dep['phase'] = "groom"
              end
            }
          end

          if (cluster['pod_ip_block_name'] or cluster['services_ip_block_name']) and
             cluster['custom_subnet']
            MU.log "GKE cluster #{cluster['name']} cannot specify pod_ip_block_name or services_ip_block_name when using a custom subnet", MU::ERR
            ok = false
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
                MU.log "No version matching #{cluster['kubernetes']['version']} available, will try floating minor revision", MU::WARN
                cluster['kubernetes']['version'].sub!(/^(\d+\.\d+)\..*/i, '\1')
                master_versions.each { |v|
                  if v.match(/^#{Regexp.quote(cluster['kubernetes']['version'])}/)
                    match = true
                    break
                  end
                }
                if !match
                  MU.log "Failed to find a GKE master version matching #{cluster['kubernetes']['version']} among available versions in #{cluster['master_az'] || cluster['region']}.", MU::ERR, details: master_versions
                  ok = false
                end
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
                MU.log "No version matching #{cluster['kubernetes']['nodeversion']} available, will try floating minor revision", MU::WARN
                cluster['kubernetes']['nodeversion'].sub!(/^(\d+\.\d+\.).*/i, '\1')
                node_versions.each { |v|
                  if v.match(/^#{Regexp.quote(cluster['kubernetes']['nodeversion'])}/)
                    match = true
                    break
                  end
                }
                if !match
                  MU.log "Failed to find a GKE node version matching #{cluster['kubernetes']['nodeversion']} among available versions in #{cluster['master_az'] || cluster['region']}.", MU::ERR, details: node_versions
                  ok = false
                end
              end
            end
          end

          cluster['instance_type'] = MU::Cloud.resourceClass("Google", "Server").validateInstanceType(cluster["instance_type"], cluster["region"], project: cluster['project'], credentials: cluster['credentials'])
          ok = false if cluster['instance_type'].nil?

          if !MU::Master.kubectl
            MU.log "Since I can't find a kubectl executable, you will have to handle all service account, user, and role bindings manually!", MU::WARN
          end

          ok
        end

        private

        def node_desc
          labels = Hash[@tags.keys.map { |k|
            [k.downcase, @tags[k].downcase.gsub(/[^-_a-z0-9]/, '-')] }
          ]
          labels["name"] = MU::Cloud::Google.nameStr(@mu_name)
          desc = {
            :machine_type => @config['instance_type'],
            :preemptible => @config['preemptible'],
            :disk_size_gb => @config['disk_size_gb'],
            :labels => labels,
            :tags => [@mu_name.downcase],
            :service_account => @service_acct.email,
            :oauth_scopes => @config['scopes']
          }
          desc[:metadata] = {}
          deploykey = @config['ssh_user']+":"+@deploy.ssh_public_key
          if @config['metadata']
            desc[:metadata] = Hash[@config['metadata'].map { |m|
              [m["key"], m["value"]]
            }]
          end
          if desc[:metadata]["ssh-keys"]
            desc[:metadata]["ssh-keys"] += "\n"+deploykey
          else
            desc[:metadata]["ssh-keys"] = deploykey
          end
          [:local_ssd_count, :min_cpu_platform, :image_type].each { |field|
            if @config[field.to_s]
              desc[field] = @config[field.to_s]
            end
          }
          desc
        end

        def labelCluster
          labels = Hash[@tags.keys.map { |k|
            [k.downcase, @tags[k].downcase.gsub(/[^-_a-z0-9]/, '-')] }
          ]
          labels["name"] = MU::Cloud::Google.nameStr(@mu_name)

          labelset = MU::Cloud::Google.container(:SetLabelsRequest).new(
            resource_labels: labels,
            label_fingerprint: cloud_desc.label_fingerprint
          )
          MU::Cloud::Google.container(credentials: @config['credentials']).set_project_location_cluster_resource_labels(@cloud_id, labelset)
        end

        @@server_config = {}
        def self.defaults(credentials = nil, az: nil)
          az ||= MU::Cloud::Google.listAZs.sample
          return nil if az.nil?
          @@server_config[credentials] ||= {}
          if @@server_config[credentials][az]
            return @@server_config[credentials][az]
          end

          parent_arg = "projects/"+MU::Cloud::Google.defaultProject(credentials)+"/locations/"+az

          @@server_config[credentials][az] = MU::Cloud::Google.container(credentials: credentials).get_project_location_server_config(parent_arg)
          @@server_config[credentials][az]
        end
        private_class_method :defaults

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
          if @username and @password and MU::Master.kubectl
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

      end #class
    end #class
  end
end #module
