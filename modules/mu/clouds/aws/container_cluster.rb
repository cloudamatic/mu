# Copyright:: Copyright (c) 2018 eGlobalTech, Inc., all rights reserved
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
    class AWS
      # A ContainerCluster as configured in {MU::Config::BasketofKittens::container_clusters}
      class ContainerCluster < MU::Cloud::ContainerCluster
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        @cloudformation_data = {}
        attr_reader :cloudformation_data
        # Return the list of regions where we know EKS is supported.
        def self.EKSRegions
          # XXX would prefer to query service API for this
          ["us-east-1", "us-west-2", "eu-west-1"]
        end

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::container_clusters}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          if @config['flavor'] == "EKS"
            subnet_ids = []
            @config["vpc"]["subnets"].each { |subnet|
              subnet_obj = @vpc.getSubnet(cloud_id: subnet["subnet_id"].to_s, name: subnet["subnet_name"].to_s)
              raise MuError, "Couldn't find a live subnet matching #{subnet} in #{@vpc} (#{@vpc.subnets})" if subnet_obj.nil?
              subnet_ids << subnet_obj.cloud_id
            }

            role_arn = @deploy.findLitterMate(name: @config['name']+"controlplane", type: "roles").cloudobj.arn

            security_groups = []
            if @dependencies.has_key?("firewall_rule")
              @dependencies['firewall_rule'].values.each { |sg|
                security_groups << sg.cloud_id
              }
            end

            resp = nil
            begin
              params = {
                :name => @mu_name,
                :version => @config['kubernetes']['version'],
                :role_arn => role_arn,
                :resources_vpc_config => {
                  :security_group_ids => security_groups,
                  :subnet_ids => subnet_ids
                }
              }
              if @config['logging'] and @config['logging'].size > 0
                params[:logging] = {
                  :cluster_logging => [
                    {
                      :types => @config['logging'],
                      :enabled => true
                    }
                  ]
                }
              end

              MU.log "Creating EKS cluster #{@mu_name}", details: params
              resp = MU::Cloud::AWS.eks(region: @config['region'], credentials: @config['credentials']).create_cluster(params)
            rescue Aws::EKS::Errors::UnsupportedAvailabilityZoneException => e
              # this isn't the dumbest thing we've ever done, but it's up there
              if e.message.match(/because (#{Regexp.quote(@config['region'])}[a-z]), the targeted availability zone, does not currently have sufficient capacity/)
                bad_az = Regexp.last_match(1)
                deletia = nil
                subnet_ids.each { |subnet|
                  subnet_obj = @vpc.getSubnet(cloud_id: subnet)
                  if subnet_obj.az == bad_az
                    deletia = subnet
                    break
                  end
                }
                raise e if deletia.nil?
                MU.log "#{bad_az} does not have EKS capacity. Dropping #{deletia} from ContainerCluster '#{@config['name']}' and retrying.", MU::NOTICE
                subnet_ids.delete(deletia)
                retry
              end
            rescue Aws::EKS::Errors::InvalidParameterException => e
              if e.message.match(/role with arn: #{Regexp.quote(role_arn)}.*?(could not be assumed|does not exist)/)
                sleep 5
                retry
              else
                MU.log e.message, MU::WARN, details: role_arn
                sleep 5
                retry
                puts e.message
              end
            end

            status = nil
            retries = 0
            begin
              resp = MU::Cloud::AWS.eks(region: @config['region'], credentials: @config['credentials']).describe_cluster(
                name: @mu_name
              )
              status = resp.cluster.status
              if retries > 0 and (retries % 3) == 0 and status != "ACTIVE"
                MU.log "Waiting for EKS cluster #{@mu_name} to become active (currently #{status})", MU::NOTICE
              end
              sleep 30
              retries += 1
            rescue Aws::EKS::Errors::ResourceNotFoundException => e
              if retries < 30
                if retries > 0 and (retries % 3) == 0
                  MU.log "Got #{e.message} trying to describe EKS cluster #{@mu_name}, waiting and retrying", MU::WARN, details: resp
                end
                sleep 30
                retries += 1
                retry
              else
                raise e
              end
            end while status != "ACTIVE"

            MU.log "Creation of EKS cluster #{@mu_name} complete"
          else
            MU::Cloud::AWS.ecs(region: @config['region'], credentials: @config['credentials']).create_cluster(
              cluster_name: @mu_name
            )

          end
          @cloud_id = @mu_name
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom

          serverpool = @deploy.findLitterMate(type: "server_pools", name: @config["name"]+"workers")
          resource_lookup = MU::Cloud::AWS.listInstanceTypes(@config['region'])[@config['region']]

          if @config["flavor"] == "EKS"
            kube = ERB.new(File.read(MU.myRoot+"/cookbooks/mu-tools/templates/default/kubeconfig.erb"))
            configmap = ERB.new(File.read(MU.myRoot+"/extras/aws-auth-cm.yaml.erb"))
            tagme = [@vpc.cloud_id]
            tagme_elb = []
            @vpc.subnets.each { |s|
              tagme << s.cloud_id
              tagme_elb << s.cloud_id if !s.private?
            }
            rtbs = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).describe_route_tables(
              filters: [ { name: "vpc-id", values: [@vpc.cloud_id] } ]
            ).route_tables
            tagme.concat(rtbs.map { |r| r.route_table_id } )
            main_sg = @deploy.findLitterMate(type: "firewall_rules", name: "server_pool#{@config['name']}workers")
            tagme << main_sg.cloud_id
            MU.log "Applying kubernetes.io tags to VPC resources", details: tagme
            MU::Cloud::AWS.createTag("kubernetes.io/cluster/#{@mu_name}", "shared", tagme, credentials: @config['credentials'])
            MU::Cloud::AWS.createTag("kubernetes.io/cluster/elb", @mu_name, tagme_elb, credentials: @config['credentials'])

            me = cloud_desc
            @endpoint = me.endpoint
            @cacert = me.certificate_authority.data
            @cluster = @mu_name
            resp = MU::Cloud::AWS.iam(credentials: @config['credentials']).get_role(role_name: @mu_name+"WORKERS")
            @worker_role_arn = resp.role.arn
            kube_conf = @deploy.deploy_dir+"/kubeconfig-#{@config['name']}"
            eks_auth = @deploy.deploy_dir+"/eks-auth-cm-#{@config['name']}.yaml"
            gitlab_helper = @deploy.deploy_dir+"/gitlab-eks-helper-#{@config['name']}.sh"
            
            File.open(kube_conf, "w"){ |k|
              k.puts kube.result(binding)
            }
            File.open(eks_auth, "w"){ |k|
              k.puts configmap.result(binding)
            }
            gitlab = ERB.new(File.read(MU.myRoot+"/extras/gitlab-eks-helper.sh.erb"))
            File.open(gitlab_helper, "w"){ |k|
              k.puts gitlab.result(binding)
            }

            authmap_cmd = %Q{/opt/mu/bin/kubectl --kubeconfig "#{kube_conf}" apply -f "#{eks_auth}"}
            MU.log "Configuring Kubernetes <=> IAM mapping for worker nodes", MU::NOTICE, details: authmap_cmd
# maybe guard this mess
            %x{#{authmap_cmd}}

# and this one
            admin_user_cmd = %Q{/opt/mu/bin/kubectl --kubeconfig "#{kube_conf}" apply -f "#{MU.myRoot}/extras/admin-user.yaml"}
            admin_role_cmd = %Q{/opt/mu/bin/kubectl --kubeconfig "#{kube_conf}" apply -f "#{MU.myRoot}/extras/admin-role-binding.yaml"}
            MU.log "Configuring Kubernetes admin-user and role", MU::NOTICE, details: admin_user_cmd+"\n"+admin_role_cmd
            %x{#{admin_user_cmd}}
            %x{#{admin_role_cmd}}

            if @config['kubernetes_resources']
              count = 0
              @config['kubernetes_resources'].each { |blob|
                blobfile = @deploy.deploy_dir+"/k8s-resource-#{count.to_s}-#{@config['name']}"
                File.open(blobfile, "w") { |f|
                  f.puts blob.to_yaml
                }
                %x{/opt/mu/bin/kubectl --kubeconfig "#{kube_conf}" get -f #{blobfile} > /dev/null 2>&1}
                arg = $?.exitstatus == 0 ? "replace" : "create"
                cmd = %Q{/opt/mu/bin/kubectl --kubeconfig "#{kube_conf}" #{arg} -f #{blobfile}}
                MU.log "Applying Kubernetes resource #{count.to_s} with kubectl #{arg}", details: cmd
                output = %x{#{cmd} 2>&1}
                if $?.exitstatus == 0
                  MU.log "Kuberentes resource #{count.to_s} #{arg} was successful: #{output}", details: blob.to_yaml
                else
                  MU.log "Kuberentes resource #{count.to_s} #{arg} failed: #{output}", MU::WARN, details: blob.to_yaml
                end
                count += 1
              }
            end

            MU.log %Q{How to interact with your Kubernetes cluster\nkubectl --kubeconfig "#{kube_conf}" get all\nkubectl --kubeconfig "#{kube_conf}" create -f some_k8s_deploy.yml\nkubectl --kubeconfig "#{kube_conf}" get nodes}, MU::SUMMARY
          elsif @config['flavor'] != "Fargate"
            resp = MU::Cloud::AWS.ecs(region: @config['region'], credentials: @config['credentials']).list_container_instances({
              cluster: @mu_name
            })
            existing = {}
            if resp
              uuids = []
              resp.container_instance_arns.each { |arn|
                uuids << arn.sub(/^.*?:container-instance\//, "")
              }
              if uuids.size > 0
                resp = MU::Cloud::AWS.ecs(region: @config['region'], credentials: @config['credentials']).describe_container_instances({
                  cluster: @mu_name,
                  container_instances: uuids
                })
                resp.container_instances.each { |i|
                  existing[i.ec2_instance_id] = i
                }
              end
            end
  
            serverpool.listNodes.each { |node|
              resources = resource_lookup[node.cloud_desc.instance_type]
              t = Thread.new {
                ident_doc = nil
                ident_doc_sig = nil
                if !node.windows?
                  session = node.getSSHSession(10, 30)
                  ident_doc = session.exec!("curl -s http://169.254.169.254/latest/dynamic/instance-identity/document/")
                  ident_doc_sig = session.exec!("curl -s http://169.254.169.254/latest/dynamic/instance-identity/signature/")
                else
                  begin
                    session = node.getWinRMSession(1, 60)
                  rescue Exception # XXX
                    session = node.getSSHSession(1, 60)
                  end
                end
                MU.log "Identity document for #{node}", MU::DEBUG, details: ident_doc
                MU.log "Identity document signature for #{node}", MU::DEBUG, details: ident_doc_sig
                params = {
                  :cluster => @mu_name,
                  :instance_identity_document => ident_doc,
                  :instance_identity_document_signature => ident_doc_sig,
                  :total_resources => [
                    {
                      :name => "CPU",
                      :type => "INTEGER",
                      :integer_value => resources["vcpu"].to_i
                    },
                    {
                      :name => "MEMORY",
                      :type => "INTEGER",
                      :integer_value => (resources["memory"]*1024*1024).to_i
                    }
                  ]
                }
                if !existing.has_key?(node.cloud_id)
                  MU.log "Registering ECS instance #{node} in cluster #{@mu_name}", details: params
                else
                  params[:container_instance_arn] = existing[node.cloud_id].container_instance_arn
                  MU.log "Updating ECS instance #{node} in cluster #{@mu_name}", MU::NOTICE, details: params
                end
                MU::Cloud::AWS.ecs(region: @config['region'], credentials: @config['credentials']).register_container_instance(params)
  
              }
            }
          end

          if @config['flavor'] != "EKS" and @config['containers']

            security_groups = []
            if @dependencies.has_key?("firewall_rule")
              @dependencies['firewall_rule'].values.each { |sg|
                security_groups << sg.cloud_id
              }
            end

            tasks_registered = 0
            retries = 0
            svc_resp = begin
              MU::Cloud::AWS.ecs(region: @config['region'], credentials: @config['credentials']).list_services(
                cluster: arn
              )
            rescue Aws::ECS::Errors::ClusterNotFoundException => e
              if retries < 10
                sleep 5
                retries += 1
                retry
              else
                raise e
              end
            end
            existing_svcs = svc_resp.service_arns.map { |s|
              s.gsub(/.*?:service\/(.*)/, '\1')
            }

            # Reorganize things so that we have services and task definitions
            # mapped to the set of containers they must contain
            tasks = {}
            created_generic_loggroup = false

            @config['containers'].each { |c|
              service_name = c['service'] ? @mu_name+"-"+c['service'].upcase : @mu_name
              tasks[service_name] ||= []
              tasks[service_name] << c
            }

            tasks.each_pair { |service_name, containers|
              launch_type = @config['flavor'] == "ECS" ? "EC2" : "FARGATE"
              cpu_total = 0
              mem_total = 0
              role_arn = nil
              lbs = []

              container_definitions = containers.map { |c|
                container_name = @mu_name+"-"+c['name'].upcase
                cpu_total += c['cpu']
                mem_total += c['memory']

                if c["role"] and !role_arn
                  found = MU::MommaCat.findStray(
                    @config['cloud'],
                    "role",
                    cloud_id: c["role"]["id"],
                    name: c["role"]["name"],
                    deploy_id: c["role"]["deploy_id"] || @deploy.deploy_id,
                    dummy_ok: false
                  )
                  if found
                    found = found.first
                    if found and found.cloudobj
                      role_arn = found.cloudobj.arn
                    end
                  else
                    raise MuError, "Unable to find execution role from #{c["role"]}"
                  end
                end
                
                if c['loadbalancers'] != []
                  c['loadbalancers'].each {|lb|
                    found = @deploy.findLitterMate(name: lb['name'], type: "loadbalancer")
                    if found
                      MU.log "Mapping LB #{found.mu_name} to service #{c['name']}", MU::INFO
                      if found.cloud_desc.type != "classic"
                        elb_groups = MU::Cloud::AWS.elb2(region: @config['region'], credentials: @config['credentials']).describe_target_groups({
                            load_balancer_arn: found.cloud_desc.load_balancer_arn
                          })
                          matching_target_groups = []
                          elb_groups.target_groups.each { |tg|
                            if tg.port.to_i == lb['container_port'].to_i
                              matching_target_groups << {
                                arn: tg['target_group_arn'],
                                name: tg['target_group_name']
                              }
                            end 
                          }
                          if matching_target_groups.length >= 1
                            MU.log "#{matching_target_groups.length} matching target groups found. Mapping #{container_name} to target group #{matching_target_groups.first['name']}", MU::INFO
                            lbs << {
                              container_name: container_name,
                              container_port: lb['container_port'],
                              target_group_arn: matching_target_groups.first[:arn]
                            }
                          else
                            raise MuError, "No matching target groups found"
                          end
                      elsif @config['flavor'] == "Fargate" && found.cloud_desc.type == "classic"
                        raise MuError, "Classic Load Balancers are not supported with Fargate."
                      else
                        MU.log "Mapping Classic LB #{found.mu_name} to service #{container_name}", MU::INFO
                        lbs << {
                          container_name: container_name,
                          container_port: lb['container_port'],
                          load_balancer_name: found.mu_name
                        }
                      end
                    else
                      raise MuError, "Unable to find loadbalancers from #{c["loadbalancers"].first['name']}"
                    end
                  }
                end

                params = {
                  name: @mu_name+"-"+c['name'].upcase,
                  image: c['image'],
                  memory: c['memory'],
                  cpu: c['cpu']
                }
                if !@config['vpc']
                  c['hostname'] ||= @mu_name+"-"+c['name'].upcase
                end
                [:essential, :hostname, :start_timeout, :stop_timeout, :user, :working_directory, :disable_networking, :privileged, :readonly_root_filesystem, :interactive, :pseudo_terminal, :links, :entry_point, :command, :dns_servers, :dns_search_domains, :docker_security_options, :port_mappings, :repository_credentials, :mount_points, :environment, :volumes_from, :secrets, :depends_on, :extra_hosts, :docker_labels, :ulimits, :system_controls, :health_check, :resource_requirements].each { |param|
                  if c.has_key?(param.to_s)
                    params[param] = if !c[param.to_s].nil? and (c[param.to_s].is_a?(Hash) or c[param.to_s].is_a?(Array))
                      MU.strToSym(c[param.to_s])
                    else
                      c[param.to_s]
                    end
                  end
                }
                if @config['vpc']
                  [:hostname, :dns_servers, :dns_search_domains, :links].each { |param|
                    if params[param]
                      MU.log "Container parameter #{param.to_s} not supported in VPC clusters, ignoring", MU::WARN
                      params.delete(param)
                    end
                  }
                end
                if @config['flavor'] == "Fargate"
                  [:privileged, :docker_security_options].each { |param|
                    if params[param]
                      MU.log "Container parameter #{param.to_s} not supported in Fargate clusters, ignoring", MU::WARN
                      params.delete(param)
                    end
                  }
                end
                if c['log_configuration']
                  log_obj = @deploy.findLitterMate(name: c['log_configuration']['options']['awslogs-group'], type: "logs")
                  if log_obj
                    c['log_configuration']['options']['awslogs-group'] = log_obj.mu_name
                  end
                  params[:log_configuration] = MU.strToSym(c['log_configuration'])
                end
                params
              }

              cpu_total = 2 if cpu_total == 0
              mem_total = 2 if mem_total == 0

              task_params = {
                family: @deploy.deploy_id,
                container_definitions: container_definitions,
                requires_compatibilities: [launch_type]
              }

              if @config['volumes']
                task_params[:volumes] = []
                @config['volumes'].each { |v|
                  vol = { :name => v['name'] }
                  if v['type'] == "host"
                    vol[:host] = {}
                    if v['host_volume_source_path']
                      vol[:host][:source_path] = v['host_volume_source_path']
                    end
                  elsif v['type'] == "docker"
                    vol[:docker_volume_configuration] = MU.strToSym(v['docker_volume_configuration'])
                  else
                    raise MuError, "Invalid volume type '#{v['type']}' specified in ContainerCluster '#{@mu_name}'"
                  end
                  task_params[:volumes] << vol
                }
              end

              if role_arn
                task_params[:execution_role_arn] = role_arn
                task_params[:task_role_arn] = role_arn
              end
              if @config['flavor'] == "Fargate"
                task_params[:network_mode] = "awsvpc"
                task_params[:cpu] = cpu_total.to_i.to_s
                task_params[:memory] = mem_total.to_i.to_s
              end

              tasks_registered += 1
              MU.log "Registering task definition #{service_name} with #{container_definitions.size.to_s} containers"

# XXX this helpfully keeps revisions, but let's compare anyway and avoid cluttering with identical ones
              resp = MU::Cloud::AWS.ecs(region: @config['region'], credentials: @config['credentials']).register_task_definition(task_params)

              task_def = resp.task_definition.task_definition_arn
              service_params = {
                :cluster => @mu_name,
                :desired_count => @config['instance_count'], # XXX this makes no sense
                :service_name => service_name,
                :launch_type => launch_type,
                :task_definition => task_def,
                :load_balancers => lbs
              }
              if @config['vpc']
                subnet_ids = []
                all_public = true
                subnet_names = @config['vpc']['subnets'].map { |s| s.values.first }
                @vpc.subnets.each { |subnet_obj|
                  next if !subnet_names.include?(subnet_obj.config['name'])
                  subnet_ids << subnet_obj.cloud_id
                  all_public = false if subnet_obj.private?
                }
                service_params[:network_configuration] = {
                  :awsvpc_configuration => {
                    :subnets => subnet_ids,
                    :security_groups => security_groups,
                    :assign_public_ip => all_public ? "ENABLED" : "DISABLED"
                  }
                }
              end

              if !existing_svcs.include?(service_name)
                MU.log "Creating Service #{service_name}"

                resp = MU::Cloud::AWS.ecs(region: @config['region'], credentials: @config['credentials']).create_service(service_params)
              else
                service_params[:service] = service_params[:service_name].dup
                service_params.delete(:service_name)
                service_params.delete(:launch_type)
                MU.log "Updating Service #{service_name}", MU::NOTICE, details: service_params

                resp = MU::Cloud::AWS.ecs(region: @config['region'], credentials: @config['credentials']).update_service(service_params)
              end
              existing_svcs << service_name 
            }

            max_retries = 10
            retries = 0
            if tasks_registered > 0
              retry_me = false
              begin
                retry_me = !MU::Cloud::AWS::ContainerCluster.tasksRunning?(@mu_name, log: (retries > 0), region: @config['region'], credentials: @config['credentials'])
                retries += 1
                sleep 15 if retry_me
              end while retry_me and retries < max_retries
              tasks = nil

              if retry_me
                MU.log "Not all tasks successfully launched in cluster #{@mu_name}", MU::WARN
              end
            end

          end

        end

        # Returns true if all tasks in the given ECS/Fargate cluster are in the
        # RUNNING state.
        # @param cluster [String]: The cluster to check
        # @param log [Boolean]: Output the state of each task to Mu's logger facility
        # @param region [String]
        # @param credentials [String]
        # @return [Boolean]
        def self.tasksRunning?(cluster, log: true, region: MU.myRegion, credentials: nil)
          services = MU::Cloud::AWS.ecs(region: region, credentials: credentials).list_services(
            cluster: cluster
          ).service_arns.map { |s| s.sub(/.*?:service\/([^\/:]+?)$/, '\1') }
          
          tasks_defined = []

          begin
            listme = services.slice!(0, (services.length >= 10 ? 10 : services.length))
            if services.size > 0
              tasks_defined.concat(
                tasks = MU::Cloud::AWS.ecs(region: region, credentials: credentials).describe_services(
                  cluster: cluster,
                  services: listme
                ).services.map { |s| s.task_definition }
              )
            end
          end while services.size > 0

          containers = {}

          tasks_defined.each { |t|
            taskdef = MU::Cloud::AWS.ecs(region: region, credentials: credentials).describe_task_definition(
              task_definition: t.sub(/^.*?:task-definition\/([^\/:]+)$/, '\1')
            )
            taskdef.task_definition.container_definitions.each { |c|
              containers[c.name] = {}
            }
          }

          tasks = MU::Cloud::AWS.ecs(region: region, credentials: credentials).list_tasks(
            cluster: cluster,
            desired_status: "RUNNING"
          ).task_arns

          tasks.concat(MU::Cloud::AWS.ecs(region: region, credentials: credentials).list_tasks(
            cluster: cluster,
            desired_status: "STOPPED"
          ).task_arns)

          begin
            sample = tasks.slice!(0, (tasks.length >= 100 ? 100 : tasks.length))
            break if sample.size == 0
            task_ids = sample.map { |task_arn|
              task_arn.sub(/^.*?:task\/([a-f0-9\-]+)$/, '\1')
            }

            MU::Cloud::AWS.ecs(region: region, credentials: credentials).describe_tasks(
              cluster: cluster,
              tasks: task_ids
            ).tasks.each { |t|
              task_name = t.task_definition_arn.sub(/^.*?:task-definition\/([^\/:]+)$/, '\1')
              t.containers.each { |c|
                containers[c.name] ||= {}
                containers[c.name][t.desired_status] ||= {
                  "reasons" => []
                }
                [t.stopped_reason, c.reason].each { |r|
                  next if r.nil?
                  containers[c.name][t.desired_status]["reasons"] << r
                }
                containers[c.name][t.desired_status]["reasons"].uniq!
                if !containers[c.name][t.desired_status]['time'] or
                   t.created_at > containers[c.name][t.desired_status]['time']
MU.log c.name, MU::NOTICE, details: t
                  containers[c.name][t.desired_status] = {
                    "time" => t.created_at,
                    "status" => c.last_status,
                    "reasons" => containers[c.name][t.desired_status]["reasons"]
                  }
                end
              }
            }
          end while tasks.size > 0

          to_return = true
          containers.each_pair { |name, states|
            if !states["RUNNING"] or states["RUNNING"]["status"] != "RUNNING"
              to_return = false
              if states["STOPPED"] and states["STOPPED"]["status"]
                MU.log "Container #{name} has failures", MU::WARN, details: states["STOPPED"] if log
              elsif states["RUNNING"] and states["RUNNING"]["status"]
                MU.log "Container #{name} not currently running", MU::NOTICE, details: states["RUNNING"] if log
              else
                MU.log "Container #{name} in unknown state", MU::WARN, details: states["STOPPED"] if log
              end
            else
              MU.log "Container #{name} running", details: states["RUNNING"] if log
            end
          }

          to_return
        end

        # Return the cloud layer descriptor for this EKS/ECS/Fargate cluster
        # @return [OpenStruct]
        def cloud_desc
          if @config['flavor'] == "EKS"
            resp = MU::Cloud::AWS.eks(region: @config['region'], credentials: @config['credentials']).describe_cluster(
              name: @mu_name
            )
            resp.cluster
          else
            resp = MU::Cloud::AWS.ecs(region: @config['region'], credentials: @config['credentials']).describe_clusters(
              clusters: [@mu_name]
            )
            resp.clusters.first
          end
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          if @config['flavor'] == "EKS"
            cloud_desc.arn
          else
            cloud_desc.cluster_arn
          end
        end

        # Return the metadata for this ContainerCluster
        # @return [Hash]
        def notify
          deploy_struct = MU.structToHash(cloud_desc)
          deploy_struct['cloud_id'] = @mu_name
          deploy_struct["region"] = @config['region']
          if @config['flavor'] == "EKS"
            deploy_struct["max_pods"] = @config['kubernetes']['max_pods'].to_s
          end
          return deploy_struct
        end

        # Use the AWS SSM API to fetch the current version of the Amazon Linux
        # ECS-optimized AMI, so we can use it as a default AMI for ECS deploys.
        # @param flavor [String]: ECS or EKS
        def self.getECSImageId(flavor = "ECS", region = MU.myRegion)
          if flavor == "ECS"
            resp = MU::Cloud::AWS.ssm(region: region).get_parameters(
              names: ["/aws/service/#{flavor.downcase}/optimized-ami/amazon-linux/recommended"]
            )
            if resp and resp.parameters and resp.parameters.size > 0
              image_details = JSON.parse(resp.parameters.first.value)
              return image_details['image_id']
            end
          elsif flavor == "EKS"
            # XXX this is absurd, but these don't appear to be available from an API anywhere
            # Here's their Packer build, should just convert to Chef: https://github.com/awslabs/amazon-eks-ami
            amis = {
              "us-east-1" => "ami-0abcb9f9190e867ab",
              "us-east-2" => "ami-04ea7cb66af82ae4a",
              "us-west-2" => "ami-0923e4b35a30a5f53",
              "eu-west-1" => "ami-08716b70cac884aaa",
              "eu-west-2" => "ami-0c7388116d474ee10",
              "eu-west-3" => "ami-0560aea042fec8b12",
              "ap-northeast-1" => "ami-0bfedee6a7845c26d",
              "ap-northeast-2" => "ami-0a904348b703e620c",
              "ap-south-1" => "ami-09c3eb35bb3be46a4",
              "ap-southeast-1" => "ami-07b922b9b94d9a6d2",
              "ap-southeast-2" => "ami-0f0121e9e64ebd3dc"
            }
            return amis[region]
          end
          nil
        end

        # Use the AWS SSM API to fetch the current version of the Amazon Linux
        # EKS-optimized AMI, so we can use it as a default AMI for EKS deploys.
        def self.getEKSImageId(region = MU.myRegion)
          resp = MU::Cloud::AWS.ssm(region: region).get_parameters(
            names: ["/aws/service/ekss/optimized-ami/amazon-linux/recommended"]
          )
          if resp and resp.parameters and resp.parameters.size > 0
            image_details = JSON.parse(resp.parameters.first.value)
            return image_details['image_id']
          end
          nil
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

        # Remove all container_clusters associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          resp = MU::Cloud::AWS.ecs(credentials: credentials, region: region).list_clusters

          if resp and resp.cluster_arns and resp.cluster_arns.size > 0
            resp.cluster_arns.each { |arn|
              if arn.match(/:cluster\/(#{MU.deploy_id}[^:]+)$/)
                cluster = Regexp.last_match[1]

                svc_resp = MU::Cloud::AWS.ecs(region: region, credentials: credentials).list_services(
                  cluster: arn
                )
                if svc_resp and svc_resp.service_arns
                  svc_resp.service_arns.each { |svc_arn|
                    svc_name = svc_arn.gsub(/.*?:service\/(.*)/, '\1')
                    MU.log "Deleting Service #{svc_name} from ECS Cluster #{cluster}"
                    if !noop
                      MU::Cloud::AWS.ecs(region: region, credentials: credentials).delete_service(
                        cluster: arn,
                        service: svc_name,
                        force: true # man forget scaling up and down if we're just deleting the cluster
                      )
                    end
                  }
                end

                instances = MU::Cloud::AWS.ecs(credentials: credentials, region: region).list_container_instances({
                  cluster: cluster
                })
                if instances
                  instances.container_instance_arns.each { |arn|
                    uuid = arn.sub(/^.*?:container-instance\//, "")
                    MU.log "Deregistering instance #{uuid} from ECS Cluster #{cluster}"
                    if !noop
                      resp = MU::Cloud::AWS.ecs(credentials: credentials, region: region).deregister_container_instance({
                        cluster: cluster,
                        container_instance: uuid,
                        force: true, 
                      })
                    end
                  }
                end
                MU.log "Deleting ECS Cluster #{cluster}"
                if !noop
# TODO de-register container instances
                  begin
                  deletion = MU::Cloud::AWS.ecs(credentials: credentials, region: region).delete_cluster(
                    cluster: cluster
                  )
                  rescue Aws::ECS::Errors::ClusterContainsTasksException => e
                    sleep 5
                    retry
                  end
                end
              end
            }
          end

          tasks = MU::Cloud::AWS.ecs(region: region, credentials: credentials).list_task_definitions(
            family_prefix: MU.deploy_id
          )
          if tasks and tasks.task_definition_arns
            tasks.task_definition_arns.each { |arn|
              MU.log "Deregistering Fargate task definition #{arn}"
              if !noop
                MU::Cloud::AWS.ecs(region: region, credentials: credentials).deregister_task_definition(
                  task_definition: arn
                )
              end
            }
          end

          return if !MU::Cloud::AWS::ContainerCluster.EKSRegions.include?(region)


          resp = MU::Cloud::AWS.eks(credentials: credentials, region: region).list_clusters

          if resp and resp.clusters
            resp.clusters.each { |cluster|
              if cluster.match(/^#{MU.deploy_id}-/)

                desc = MU::Cloud::AWS.eks(credentials: credentials, region: region).describe_cluster(
                  name: cluster
                ).cluster

                untag = []
                untag << desc.resources_vpc_config.vpc_id
                subnets = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_subnets(
                  filters: [ { name: "vpc-id", values: [desc.resources_vpc_config.vpc_id] } ]
                ).subnets

                # subnets
                untag.concat(subnets.map { |s| s.subnet_id } )
                rtbs = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_route_tables(
                  filters: [ { name: "vpc-id", values: [desc.resources_vpc_config.vpc_id] } ]
                ).route_tables
                untag.concat(rtbs.map { |r| r.route_table_id } )
                untag.concat(desc.resources_vpc_config.subnet_ids)
                untag.concat(desc.resources_vpc_config.security_group_ids)
                MU.log "Removing Kubernetes tags from VPC resources for #{cluster}", details: untag
                if !noop
                  MU::Cloud::AWS.removeTag("kubernetes.io/cluster/#{cluster}", "shared", untag)
                  MU::Cloud::AWS.removeTag("kubernetes.io/cluster/elb", cluster, untag)
                end
                MU.log "Deleting EKS Cluster #{cluster}"
                if !noop
                  MU::Cloud::AWS.eks(credentials: credentials, region: region).delete_cluster(
                    name: cluster
                  )
                  begin
                    status = nil
                    retries = 0
                    begin
                      deletion = MU::Cloud::AWS.eks(credentials: credentials, region: region).describe_cluster(
                        name: cluster
                      )
                      status = deletion.cluster.status
                      if retries > 0 and (retries % 3) == 0
                        MU.log "Waiting for EKS cluster #{cluster} to finish deleting (status #{status})", MU::NOTICE
                      end
                      retries += 1
                      sleep 30
                    end while status
                  rescue Aws::EKS::Errors::ResourceNotFoundException
                    # this is what we want
                  end
#                  MU::Cloud::AWS::Server.removeIAMProfile(cluster)
                end
              end
            }
          end
        end

        # Locate an existing container_clusters.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching container_clusters.
        def self.find(cloud_id: nil, region: MU.curRegion, credentials: nil, flags: {})
          MU.log cloud_id, MU::WARN, details: flags
          MU.log region, MU::WARN
          resp = MU::Cloud::AWS.ecs(region: region, credentials: credentials).list_clusters
          resp = MU::Cloud::AWS.eks(region: region, credentials: credentials).list_clusters
# XXX uh, this ain't complete
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "flavor" => {
              "enum" => ["ECS", "EKS", "Fargate"],
              "default" => "ECS"
            },
            "kubernetes" => {
              "default" => { "version" => "1.11" }
            },
            "platform" => {
              "description" => "The platform to choose for worker nodes. Will default to Amazon Linux for ECS, CentOS 7 for everything else. Only valid for EKS and ECS flavors.",
              "default" => "centos7"
            },
            "ami_id" => {
              "type" => "string",
              "description" => "The Amazon EC2 AMI on which to base this cluster's container hosts. Will use the default appropriate for the platform, if not specified. Only valid for EKS and ECS flavors."
            },
            "run_list" => {
              "type" => "array",
              "items" => {
                  "type" => "string",
                  "description" => "An extra Chef run list entry, e.g. role[rolename] or recipe[recipename]s, to be run on worker nodes. Only valid for EKS and ECS flavors."
              }
            },
            "ingress_rules" => {
              "type" => "array",
              "items" => MU::Config::FirewallRule.ruleschema,
              "default" => [
                {
                  "egress" => true,
                  "port" => 443,
                  "hosts" => [ "0.0.0.0/0" ]
                }
              ]
            },
            "logging" => {
              "type" => "array",
              "default" => ["authenticator", "api"],
              "items" => {
                "type" => "string",
                "description" => "Cluster CloudWatch logs to enable for EKS clusters.",
                "enum" => ["api", "audit", "authenticator", "controllerManager", "scheduler"]
              }
            },
            "volumes" => {
              "type" => "array",
              "items" => {
                "description" => "Define one or more volumes which can then be referenced by the +mount_points+ parameter inside +containers+. +docker+ volumes are not valid for Fargate clusters. See also https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_data_volumes.html",
                "type" => "object",
                "required" => ["name", "type"],
                "properties" => {
                  "name" => {
                    "type" => "string",
                    "description" => "Name this volume so it can be referenced by containers."
                  },
                  "type" => {
                    "type" => "string",
                    "enum" => ["docker", "host"]
                  },
                  "docker_volume_configuration" => {
                    "type" => "object",
                    "default" => {
                      "autoprovision" => true,
                      "driver" => "local"
                    },
                    "description" => "This parameter is specified when you are using +docker+ volumes. Docker volumes are only supported when you are using the EC2 launch type. To use bind mounts, specify a +host+ volume instead.",
                    "properties" => {
                      "autoprovision" => {
                        "type" => "boolean",
                        "description" => "Create the Docker volume if it does not already exist.",
                        "default" => true
                      },
                      "driver" => {
                        "type" => "string",
                        "description" => "The Docker volume driver to use. Note that Windows containers can only use the +local+ driver. This parameter maps to +Driver+ in the Create a volume section of the Docker Remote API and the +xxdriver+ option to docker volume create."
                      },
                      "labels" => {
                        "description" => "Custom metadata to add to your Docker volume.",
                        "type" => "object"
                      },
                      "driver_opts" => {
                        "description" => "A map of Docker driver-specific options passed through. This parameter maps to +DriverOpts+ in the Create a volume section of the Docker Remote API and the +xxopt+ option to docker volume create .",
                        "type" => "object"
                      },
                    }
                  },
                  "host_volume_source_path" => {
                    "type" => "string",
                    "description" => "If specified, and the +type+ of this volume is +host+, data will be stored in the container host in this location and will persist after containers associated with it stop running."
                  }
                }
              }
            },
            "containers" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "description" => "A container image to run on this cluster.",
                "required" => ["name", "image"],
                "properties" => {
                  "name" => {
                    "type" => "string",
                    "description" => "The name of a container. If you are linking multiple containers together in a task definition, the name of one container can be entered in the +links+ of another container to connect the containers. This parameter maps to +name+ in the Create a container section of the Docker Remote API and the +--name+ option to docker run."
                  },
                  "service" => {
                    "type" => "string",
                    "description" => "The Service of which this container will be a component. Default behavior, if unspecified, is to create a service with the name of this container definition and assume they map 1:1."
                  },
                  "image" => {
                    "type" => "string",
                    "description" => "A Docker image to run, as a shorthand name for a public Dockerhub image or a full URL to a private container repository (+repository-url/image:tag+ or <tt>repository-url/image@digest</tt>). See +repository_credentials+ to specify authentication for a container repository.",
                  },
                  "cpu" => {
                    "type" => "integer",
                    "default" => 256,
                    "description" => "CPU to allocate for this container/task. This parameter maps to +CpuShares+ in the Create a container section of the Docker Remote API and the +--cpu-shares+ option to docker run. Not all +cpu+ and +memory+ combinations are valid, particularly when using Fargate, see https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html"
                  },
                  "memory" => {
                    "type" => "integer",
                    "default" => 512,
                    "description" => "Hard limit of memory to allocate for this container/task. Not all +cpu+ and +memory+ combinations are valid, particularly when using Fargate, see https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html"
                  },
                  "memory_reservation" => {
                    "type" => "integer",
                    "default" => 512,
                    "description" => "Soft limit of memory to allocate for this container/task. This parameter maps to +MemoryReservation+ in the Create a container section of the Docker Remote API and the +--memory-reservation+ option to docker run."
                  },
                  "role" => MU::Config::Role.reference,
                  "essential" => {
                    "type" => "boolean",
                    "description" => "Flag this container as essential or non-essential to its parent task. If the container fails and is marked essential, the parent task will also be marked as failed.",
                    "default" => true
                  },
                  "hostname" => {
                    "type" => "string",
                    "description" => "Set this container's local hostname. If not specified, will inherit the name of the parent task. Not valid for Fargate clusters. This parameter maps to +Hostname+ in the Create a container section of the Docker Remote API and the +--hostname+ option to docker run."
                  },
                  "user" => {
                    "type" => "string",
                    "description" => "The system-level user to use when executing commands inside this container"
                  },
                  "working_directory" => {
                    "type" => "string",
                    "description" => "The working directory in which to run commands inside the container."
                  },
                  "disable_networking" => {
                    "type" => "boolean",
                    "description" => "This parameter maps to +NetworkDisabled+ in the Create a container section of the Docker Remote API."
                  },
                  "privileged" => {
                    "type" => "boolean",
                    "description" => "When this parameter is true, the container is given elevated privileges on the host container instance (similar to the root user). This parameter maps to +Privileged+ in the Create a container section of the Docker Remote API and the +--privileged+ option to docker run. Not valid for Fargate clusters."
                  },
                  "readonly_root_filesystem" => {
                    "type" => "boolean",
                    "description" => "This parameter maps to +ReadonlyRootfs+ in the Create a container section of the Docker Remote API and the +--read-only+ option to docker run."
                  },
                  "interactive" => {
                    "type" => "boolean",
                    "description" => "When this parameter is +true+, this allows you to deploy containerized applications that require +stdin+ or a +tty+ to be allocated. This parameter maps to +OpenStdin+ in the Create a container section of the Docker Remote API and the +--interactive+ option to docker run."
                  },
                  "pseudo_terminal" => {
                    "type" => "boolean",
                    "description" => "When this parameter is true, a TTY is allocated. This parameter maps to +Tty+ in the Create a container section of the Docker Remote API and the +--tty+ option to docker run."
                  },
                  "start_timeout" => {
                    "type" => "integer",
                    "description" => "Time duration to wait before giving up on containers which have been specified with +depends_on+ for this one."
                  },
                  "stop_timeout" => {
                    "type" => "integer",
                    "description" => "Time duration to wait before the container is forcefully killed if it doesn't exit normally on its own."
                  },
                  "links" => {
                    "type" => "array",
                    "items" => {
                      "description" => "The +link+ parameter allows containers to communicate with each other without the need for port mappings. Only supported if the network mode of a task definition is set to +bridge+. The +name:internalName+ construct is analogous to +name:alias+ in Docker links.",
                      "type" => "string"
                    }
                  },
                  "entry_point" => {
                    "type" => "array",
                    "items" => {
                      "type" => "string",
                      "description" => "The entry point that is passed to the container. This parameter maps to +Entrypoint+ in the Create a container section of the Docker Remote API and the +--entrypoint+ option to docker run."
                    }
                  },
                  "command" => {
                    "type" => "array",
                    "items" => {
                      "type" => "string",
                      "description" => "This parameter maps to +Cmd+ in the Create a container section of the Docker Remote API and the +COMMAND+ parameter to docker run."
                    }
                  },
                  "dns_servers" => {
                    "type" => "array",
                    "items" => {
                      "type" => "string",
                      "description" => "A list of DNS servers that are presented to the container. This parameter maps to +Dns+ in the Create a container section of the Docker Remote API and the +--dns+ option to docker run."
                    }
                  },
                  "dns_search_domains" => {
                    "type" => "array",
                    "items" => {
                      "type" => "string",
                      "description" => "A list of DNS search domains that are presented to the container. This parameter maps to +DnsSearch+ in the Create a container section of the Docker Remote API and the +--dns-search+ option to docker run."
                    }
                  },
                  "linux_parameters" => {
                    "type" => "object",
                    "description" => "Linux-specific options that are applied to the container, such as Linux KernelCapabilities.",
                    "properties" => {
                      "init_process_enabled" => {
                        "type" => "boolean",
                        "description" => "Run an +init+ process inside the container that forwards signals and reaps processes. This parameter maps to the +--init+ option to docker run."
                      },
                      "shared_memory_size" => {
                        "type" => "integer",
                        "description" => "The value for the size (in MiB) of the +/dev/shm+ volume. This parameter maps to the +--shm-size+ option to docker run. Not valid for Fargate clusters."
                      },
                      "capabilities" => {
                        "type" => "object",
                        "description" => "The Linux capabilities for the container that are added to or dropped from the default configuration provided by Docker.",
                        "properties" => {
                          "add" => {
                            "type" => "array",
                            "items" => {
                              "type" => "string",
                              "description" => "This parameter maps to +CapAdd+ in the Create a container section of the Docker Remote API and the +--cap-add+ option to docker run. Not valid for Fargate clusters.",
                              "enum" => ["ALL", "AUDIT_CONTROL", "AUDIT_WRITE", "BLOCK_SUSPEND", "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "IPC_LOCK", "IPC_OWNER", "KILL", "LEASE", "LINUX_IMMUTABLE", "MAC_ADMIN", "MAC_OVERRIDE", "MKNOD", "NET_ADMIN", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_ADMIN", "SYS_BOOT", "SYS_CHROOT", "SYS_MODULE", "SYS_NICE", "SYS_PACCT", "SYS_PTRACE", "SYS_RAWIO", "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "SYSLOG", "WAKE_ALARM"]
                            }
                          },
                          "drop" => {
                            "type" => "array",
                            "items" => {
                              "type" => "string",
                              "description" => "This parameter maps to +CapDrop+ in the Create a container section of the Docker Remote API and the +--cap-drop+ option to docker run.",
                              "enum" => ["ALL", "AUDIT_CONTROL", "AUDIT_WRITE", "BLOCK_SUSPEND", "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "IPC_LOCK", "IPC_OWNER", "KILL", "LEASE", "LINUX_IMMUTABLE", "MAC_ADMIN", "MAC_OVERRIDE", "MKNOD", "NET_ADMIN", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_ADMIN", "SYS_BOOT", "SYS_CHROOT", "SYS_MODULE", "SYS_NICE", "SYS_PACCT", "SYS_PTRACE", "SYS_RAWIO", "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "SYSLOG", "WAKE_ALARM"]
                            }
                          }
                        }
                      },
                      "devices" => {
                        "type" => "array",
                        "items" => {
                          "type" => "object",
                          "description" => "Host devices to expose to the container.",
                          "properties" => {
                            "host_path" => {
                              "type" => "string",
                              "description" => "The path for the device on the host container instance."
                            },
                            "container_path" => {
                              "type" => "string",
                              "description" => "The path inside the container at which to expose the host device."
                            },
                            "permissions" => {
                              "type" => "array",
                              "items" => {
                                "description" => "The explicit permissions to provide to the container for the device. By default, the container has permissions for +read+, +write+, and +mknod+ for the device.",
                                "type" => "string"
                              }
                            }
                          }
                        }
                      },
                      "tmpfs" => {
                        "type" => "array",
                        "items" => {
                          "type" => "object",
                          "description" => "A tmpfs device to expost to the container. This parameter maps to the +--tmpfs+ option to docker run. Not valid for Fargate clusters.",
                          "properties" => {
                            "container_path" => {
                              "type" => "string",
                              "description" => "The absolute file path where the tmpfs volume is to be mounted."
                            },
                            "size" => {
                              "type" => "integer",
                              "description" => "The size (in MiB) of the tmpfs volume."
                            },
                            "mount_options" => {
                              "type" => "array",
                              "items" => {
                                "description" => "tmpfs volume mount options",
                                "type" => "string",
                                "enum" => ["defaults", "ro", "rw", "suid", "nosuid", "dev", "nodev", "exec", "noexec", "sync", "async", "dirsync", "remount", "mand", "nomand", "atime", "noatime", "diratime", "nodiratime", "bind", "rbind", "unbindable", "runbindable", "private", "rprivate", "shared", "rshared", "slave", "rslave", "relatime", "norelatime", "strictatime", "nostrictatime", "mode", "uid", "gid", "nr_inodes", "nr_blocks", "mpol"]
                              }
                            }
                          }
                        }
                      }
                    }
                  },
                  "docker_labels" => {
                    "type" => "object",
                    "description" => "A key/value map of labels to add to the container. This parameter maps to +Labels+ in the Create a container section of the Docker Remote API and the +--label+ option to docker run."
                  },
                  "docker_security_options" => {
                    "type" => "array",
                    "items" => {
                      "type" => "string",
                      "description" => "A list of strings to provide custom labels for SELinux and AppArmor multi-level security systems. This field is not valid for containers in tasks using the Fargate launch type. This parameter maps to +SecurityOpt+ in the Create a container section of the Docker Remote API and the +--security-opt+ option to docker run."
                    }
                  },
                  "health_check" => {
                    "type" => "object",
                    "required" => ["command"],
                    "description" => "The health check command and associated configuration parameters for the container. This parameter maps to +HealthCheck+ in the Create a container section of the Docker Remote API and the +HEALTHCHECK+ parameter of docker run.",
                    "properties" => {
                      "command" => {
                        "type" => "array",
                        "items" => {
                          "type" => "string",
                          "description" => "A string array representing the command that the container runs to determine if it is healthy."
                        }
                      },
                      "interval" => {
                        "type" => "integer",
                        "description" => "The time period in seconds between each health check execution."
                      },
                      "timeout" => {
                        "type" => "integer",
                        "description" => "The time period in seconds to wait for a health check to succeed before it is considered a failure."
                      },
                      "retries" => {
                        "type" => "integer",
                        "description" => "The number of times to retry a failed health check before the container is considered unhealthy."
                      },
                      "start_period" => {
                        "type" => "integer",
                        "description" => "The optional grace period within which to provide containers time to bootstrap before failed health checks count towards the maximum number of retries."
                      }
                    }
                  },
                  "environment" => {
                    "type" => "array",
                    "items" => {
                      "type" => "object",
                      "description" => "The environment variables to pass to a container. This parameter maps to +Env+ in the Create a container section of the Docker Remote API and the +--env+ option to docker run.",
                      "properties" => {
                        "name" => {
                          "type" => "string"
                        },
                        "value" => {
                          "type" => "string"
                        }
                      }
                    }
                  },
                  "resource_requirements" => {
                    "type" => "array",
                    "items" => {
                      "type" => "object",
                      "description" => "Special requirements for this container. As of this writing, +GPU+ is the only valid option.",
                      "required" => ["type", "value"],
                      "properties" => {
                        "type" => {
                          "type" => "string",
                          "enum" => ["GPU"],
                          "description" => "Special requirements for this container. As of this writing, +GPU+ is the only valid option."
                        },
                        "value" => {
                          "type" => "string",
                          "description" => "The number of physical GPUs the Amazon ECS container agent will reserve for the container."
                        }
                      }
                    }
                  },
                  "system_controls" => {
                    "type" => "array",
                    "items" => {
                      "type" => "object",
                      "description" => "A list of namespaced kernel parameters to set in the container. This parameter maps to +Sysctls+ in the Create a container section of the Docker Remote API and the +--sysctl+ option to docker run.",
                      "properties" => {
                        "namespace" => {
                          "type" => "string",
                          "description" => "The namespaced kernel parameter for which to set a +value+."
                        },
                        "value" => {
                          "type" => "string",
                          "description" => "The value for the namespaced kernel parameter specified in +namespace+."
                        }
                      }
                    }
                  },
                  "ulimits" => {
                    "type" => "array",
                    "items" => {
                      "type" => "object",
                      "description" => "This parameter maps to +Ulimits+ in the Create a container section of the Docker Remote API and the +--ulimit+ option to docker run.",
                      "required" => ["name", "soft_limit", "hard_limit"],
                      "properties" => {
                        "name" => {
                          "type" => "string",
                          "description" => "The ulimit parameter to set.",
                          "enum" => ["core", "cpu", "data", "fsize", "locks", "memlock", "msgqueue", "nice", "nofile", "nproc", "rss", "rtprio", "rttime", "sigpending", "stack"]
                        },
                        "soft_limit" => {
                          "type" => "integer",
                          "description" => "The soft limit for the ulimit type."
                        },
                        "hard_limit" => {
                          "type" => "integer",
                          "description" => "The hard limit for the ulimit type."
                        },
                      }
                    }
                  },
                  "extra_hosts" => {
                    "type" => "array",
                    "items" => {
                      "type" => "object",
                      "description" => "A list of hostnames and IP address mappings to append to the +/etc/hosts+ file on the container. This parameter maps to ExtraHosts in the +Create+ a container section of the Docker Remote API and the +--add-host+ option to docker run.",
                      "required" => ["hostname", "ip_address"],
                      "properties" => {
                        "hostname" => {
                          "type" => "string"
                        },
                        "ip_address" => {
                          "type" => "string"
                        }
                      }
                    }
                  },
                  "secrets" => {
                    "type" => "array",
                    "items" => {
                      "type" => "object",
                      "description" => "See https://docs.aws.amazon.com/AmazonECS/latest/developerguide/specifying-sensitive-data.html",
                      "required" => ["name", "value_from"],
                      "properties" => {
                        "name" => {
                          "type" => "string",
                          "description" => "The value to set as the environment variable on the container."
                        },
                        "value_from" => {
                          "type" => "string",
                          "description" => "The secret to expose to the container."
                        }
                      }
                    }
                  },
                  "depends_on" => {
                    "type" => "array",
                    "items" => {
                      "type" => "object",
                      "required" => ["container_name", "condition"],
                      "description" => "The dependencies defined for container startup and shutdown. A container can contain multiple dependencies. When a dependency is defined for container startup, for container shutdown it is reversed.",
                      "properties" => {
                        "container_name" => {
                          "type" => "string"
                        },
                        "condition" => {
                          "type" => "string",
                          "enum" => ["START", "COMPLETE", "SUCCESS", "HEALTHY"]
                        }
                      }
                    }
                  },
                  "mount_points" => {
                    "type" => "array",
                    "items" => {
                      "type" => "object",
                      "description" => "The mount points for data volumes in your container. This parameter maps to +Volumes+ in the Create a container section of the Docker Remote API and the +--volume+ option to docker run.",
                      "properties" => {
                        "source_volume" => {
                          "type" => "string",
                          "description" => "The name of the +volume+ to mount, defined under the +volumes+ section of our parent +container_cluster+ (if the volume is not defined, an ephemeral bind host volume will be allocated)."
                        },
                        "container_path" => {
                          "type" => "string",
                          "description" => "The container-side path where this volume must be mounted"
                        },
                        "read_only" => {
                          "type" => "boolean",
                          "default" => false,
                          "description" => "Mount the volume read-only"
                        }
                      }
                    }
                  },
                  "volumes_from" => {
                    "type" => "array",
                    "items" => {
                      "type" => "object",
                      "description" => "Data volumes to mount from another container. This parameter maps to +VolumesFrom+ in the Create a container section of the Docker Remote API and the +--volumes-from+ option to docker run.",
                      "properties" => {
                        "source_container" => {
                          "type" => "string",
                          "description" => "The name of another container within the same task definition from which to mount volumes."
                        },
                        "read_only" => {
                          "type" => "boolean",
                          "default" => false,
                          "description" => "If this value is +true+, the container has read-only access to the volume."
                        }
                      }
                    }
                  },
                  "repository_credentials" => {
                    "type" => "object",
                    "description" => "The Amazon Resource Name (ARN) of a secret containing the private repository credentials.",
                    "properties" => {
                      "credentials_parameter" => {
                        "type" => "string",
                        # XXX KMS? Secrets Manager? This documentation is vague.
                        "description" => "The Amazon Resource Name (ARN) of a secret containing the private repository credentials."
                      }
                    }
                  },
                  "port_mappings" => {
                    "type" => "array",
                    "items" => {
                      "description" => "Mappings of ports between the container instance and the host instance. This parameter maps to +PortBindings+ in the Create a container section of the Docker Remote API and the +--publish+ option to docker run.",
                      "type" => "object",
                      "properties" => {
                        "container_port" => {
                          "type" => "integer",
                          "description" => "The port number on the container that is bound to the user-specified or automatically assigned host port."
                        },
                        "host_port" => {
                          "type" => "integer",
                          "description" => "The port number on the container instance to reserve for your container. This should not be specified for Fargate clusters, nor for ECS clusters deployed into VPCs."
                        },
                        "protocol" => {
                          "type" => "string",
                          "description" => "The protocol used for the port mapping.",
                          "enum" => ["tcp", "udp"],
                          "default" => "tcp"
                        },
                      }
                    }
                  },
                  "log_configuration" => {
                    "type" => "object",
                    "description" => "Where to send container logs. If not specified, Mu will create a CloudWatch Logs output channel. See also: https://docs.aws.amazon.com/sdkforruby/api/Aws/ECS/Types/ContainerDefinition.html#log_configuration-instance_method",
                    "default" => {
                      "log_driver" => "awslogs"
                    },
                    "required" => ["log_driver"],
                    "properties" => {
                      "log_driver" => {
                        "type" => "string",
                        "description" => "Type of logging facility to use for container logs.",
                        "enum" => ["json-file", "syslog", "journald", "gelf", "fluentd", "awslogs", "splunk"]
                      },
                      "options" => {
                        "type" => "object",
                        "description" => "Per-driver configuration options. See also: https://docs.aws.amazon.com/sdkforruby/api/Aws/ECS/Types/ContainerDefinition.html#log_configuration-instance_method"
                      }
                    }
                  },
                  "loadbalancers" => {
                    "type" => "array",
                    "description" => "Array of loadbalancers to associate with this container servvice See also: https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/ECS/Client.html#create_service-instance_method",
                    "default" => [],
                    "items" => {
                      "description" => "Load Balancers to associate with the container services",
                      "type" => "object",
                      "properties" => {
                        "name" => {
                          "type" => "string",
                          "description" => "Name of the loadbalancer to associate"
                        },
                        "container_port" => {
                          "type" => "integer",
                          "description" => "container port to map to the loadbalancer"
                        }
                      }
                    }
                  }
                }
              }
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

          cluster['size'] = MU::Cloud::AWS::Server.validateInstanceType(cluster["instance_type"], cluster["region"])
          ok = false if cluster['size'].nil?

          if cluster["flavor"] == "ECS" and cluster["kubernetes"] and !MU::Cloud::AWS.isGovCloud?(cluster["region"])
            cluster["flavor"] = "EKS"
            MU.log "Setting flavor of ContainerCluster '#{cluster['name']}' to EKS ('kubernetes' stanza was specified)", MU::NOTICE
          end

          if cluster["flavor"] == "EKS" and !MU::Cloud::AWS::ContainerCluster.EKSRegions.include?(cluster['region'])
            MU.log "EKS is only available in some regions", MU::ERR, details: MU::Cloud::AWS::ContainerCluster.EKSRegions
            ok = false
          end

          if cluster["volumes"]
            cluster["volumes"].each { |v|
              if v["type"] == "docker"
                if cluster["flavor"] == "Fargate"
                  MU.log "ContainerCluster #{cluster['name']}: Docker volumes are not supported in Fargate clusters (volume '#{v['name']}' is not valid)", MU::ERR
                  ok = false
                end
              end
            }
          end

          if cluster["flavor"] != "EKS" and cluster["containers"]
            cluster.delete("kubernetes")
            created_generic_loggroup = false
            cluster['containers'].each { |c|
              if c['log_configuration'] and
                 c['log_configuration']['log_driver'] == "awslogs" and
                 (!c['log_configuration']['options'] or !c['log_configuration']['options']['awslogs-group'])

                logname = cluster["name"]+"-svclogs"
                rolename = cluster["name"]+"-logrole"
                c['log_configuration']['options'] ||= {}
                c['log_configuration']['options']['awslogs-group'] = logname
                c['log_configuration']['options']['awslogs-region'] = cluster["region"]
                c['log_configuration']['options']['awslogs-stream-prefix'] ||= c['name']
                if c['mount_points']
                  cluster['volumes'] ||= []
                  volnames = cluster['volumes'].map { |v| v['name'] }
                  c['mount_points'].each { |m|
                    if !volnames.include?(m['source_volume'])
                      cluster['volumes'] << {
                        "name" => m['source_volume'],
                        "type" => "host"
                      }
                    end
                  }
                end

                if !created_generic_loggroup
                  cluster["dependencies"] << { "type" => "log", "name" => logname }
                  logdesc = {
                    "name" => logname,
                    "region" => cluster["region"],
                    "cloud" => cluster["cloud"]
                  }
                  configurator.insertKitten(logdesc, "logs")

                  if !c['role']
                    roledesc = {
                      "name" => rolename,
                      "cloud" => cluster["cloud"],
                      "can_assume" => [
                        {
                          "entity_id" => "ecs-tasks.amazonaws.com",
                          "entity_type" => "service"
                        }
                      ],
                      "policies" => [
                        {
                          "name" => "ECSTaskLogPerms",
                          "permissions" => [
                            "logs:CreateLogStream",
                            "logs:DescribeLogGroups",
                            "logs:DescribeLogStreams",
                            "logs:PutLogEvents"
                          ],
                          "import" => [
                            ""
                          ],
                          "targets" => [
                            {
                              "type" => "log",
                              "identifier" => logname
                            }
                          ]
                        }
                      ],
                      "dependencies" => [{ "type" => "log", "name" => logname }]
                    }
                    configurator.insertKitten(roledesc, "roles")

                    cluster["dependencies"] << {
                      "type" => "role",
                      "name" => rolename
                    }
                  end

                  created_generic_loggroup = true
                end
                c['role'] ||= { 'name' => rolename }
              end
            }
          end

          if MU::Cloud::AWS.isGovCloud?(cluster["region"]) and cluster["flavor"] == "EKS"
            MU.log "AWS GovCloud does not support #{cluster["flavor"]} yet", MU::ERR
            ok = false
          end

          if cluster["flavor"] == "EKS" and !cluster["vpc"]
            if !MU::Cloud::AWS.hosted?
              MU.log "EKS cluster #{cluster['name']} must declare a VPC", MU::ERR
              ok = false
            else
              cluster["vpc"] = {
                "vpc_id" => MU.myVPC,
                "subnet_pref" => "all_private"
              }
            end
          end

          if ["ECS", "EKS"].include?(cluster["flavor"])
            std_ami = getECSImageId(cluster["flavor"], cluster['region'])
            cluster["host_image"] ||= std_ami
            if cluster["host_image"] != std_ami
              if cluster["flavor"] == "ECS"
                MU.log "You have specified a non-standard AMI for ECS container hosts. This can work, but you will need to install Docker and the ECS Agent yourself, ideally through a Chef recipes. See AWS documentation for details.", MU::WARN, details: "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/manually_update_agent.html"
              elsif cluster["flavor"] == "EKS"
                MU.log "You have specified a non-standard AMI for EKS worker hosts. This can work, but you will need to install Docker and configure Kubernetes yourself, ideally through a Chef recipes. See AWS documentation for details.", MU::WARN, details: "https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html"
              end
            else
              cluster["host_ssh_user"] = "ec2-user"
              cluster.delete("platform")
            end
          end

          if cluster["flavor"] == "Fargate" and !cluster['vpc']
            if MU.myVPC
              cluster["vpc"] = {
                "vpc_id" => MU.myVPC,
                "subnet_pref" => "all_private"
              }
              MU.log "Fargate cluster #{cluster['name']} did not specify a VPC, inserting into private subnets of #{MU.myVPC}", MU::NOTICE
            else
              MU.log "Fargate cluster #{cluster['name']} must specify a VPC", MU::ERR
              ok = false
            end

          end

          cluster['ingress_rules'] ||= []
          if cluster['flavor'] == "ECS"
            cluster['ingress_rules'] << {
              "sgs" => ["server_pool#{cluster['name']}workers"],
              "port" => 443
            }
          end
          fwname = "container_cluster#{cluster['name']}"

          acl = {
            "name" => fwname,
            "credentials" => cluster["credentials"],
            "rules" => cluster['ingress_rules'],
            "region" => cluster['region'],
            "optional_tags" => cluster['optional_tags']
          }
          acl["tags"] = cluster['tags'] if cluster['tags'] && !cluster['tags'].empty?
          acl["vpc"] = cluster['vpc'].dup if cluster['vpc']

          ok = false if !configurator.insertKitten(acl, "firewall_rules")
          cluster["add_firewall_rules"] = [] if cluster["add_firewall_rules"].nil?
          cluster["add_firewall_rules"] << {"rule_name" => fwname}
          cluster["dependencies"] << {
            "name" => fwname,
            "type" => "firewall_rule",
          }

          if ["ECS", "EKS"].include?(cluster["flavor"])

            worker_pool = {
              "name" => cluster["name"]+"workers",
              "credentials" => cluster["credentials"],
              "region" => cluster['region'],
              "min_size" => cluster["instance_count"],
              "max_size" => cluster["instance_count"],
              "wait_for_nodes" => cluster["instance_count"],
              "ssh_user" => cluster["host_ssh_user"],
              "role_strip_path" => true,
              "basis" => {
                "launch_config" => {
                  "name" => cluster["name"]+"workers",
                  "size" => cluster["instance_type"]
                }
              }
            }
            if cluster["flavor"] == "EKS"
              worker_pool["ingress_rules"] = [
                "sgs" => ["container_cluster#{cluster['name']}"],
                "port_range" => "1-65535"
              ]
              worker_pool["application_attributes"] ||= {}
              worker_pool["application_attributes"]["skip_recipes"] ||= []
              worker_pool["application_attributes"]["skip_recipes"] << "set_local_fw"
            end
            if cluster["vpc"]
              worker_pool["vpc"] = cluster["vpc"].dup
              worker_pool["vpc"]["subnet_pref"] = cluster["instance_subnet_pref"]
              worker_pool["vpc"].delete("subnets")
           end

            if cluster["host_image"]
              worker_pool["basis"]["launch_config"]["image_id"] = cluster["host_image"]
            end

            if cluster["flavor"] == "EKS"
              worker_pool["canned_iam_policies"] = [
                "AmazonEKSWorkerNodePolicy",
                "AmazonEKS_CNI_Policy",
                "AmazonEC2ContainerRegistryReadOnly"
              ]
              worker_pool["dependencies"] = [
                {
                  "type" => "container_cluster",
                  "name" => cluster['name']
                }
              ]
              worker_pool["run_list"] = ["mu-tools::eks"]
							worker_pool["run_list"].concat(cluster["run_list"]) if cluster["run_list"]
              MU::Config::Server.common_properties.keys.each { |k|
                if cluster[k] and !worker_pool[k]
                  worker_pool[k] = cluster[k]
                end
              }

            end

            configurator.insertKitten(worker_pool, "server_pools")

            if cluster["flavor"] == "ECS"
              cluster["dependencies"] << {
                "name" => cluster["name"]+"workers",
                "type" => "server_pool",
              }
            end

            if cluster["flavor"] == "EKS"
              role = {
                "name" => cluster["name"]+"controlplane",
                "credentials" => cluster["credentials"],
                "can_assume" => [
                  { "entity_id" => "eks.amazonaws.com", "entity_type" => "service" }
                ],
                "import" => ["AmazonEKSServicePolicy", "AmazonEKSClusterPolicy"]

              }
              role["tags"] = cluster["tags"] if !cluster["tags"].nil?
              role["optional_tags"] = cluster["optional_tags"] if !cluster["optional_tags"].nil?
              configurator.insertKitten(role, "roles")
              cluster['dependencies'] << {
                "type" => "role",
                "name" => cluster["name"]+"controlplane",
                "phase" => "groom"
              }
            end
          end

          ok
        end

      end
    end
  end
end
