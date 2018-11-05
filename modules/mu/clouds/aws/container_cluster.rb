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

        # Generate the generic EKS machine role that will be used by the
        # control plane.
        def self.createControlPlaneIAMRole(rolename)
          resp = MU::Cloud::AWS.iam.create_role(
            role_name: rolename,
            assume_role_policy_document: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["eks.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}'
          )
          arn = resp.role.arn
          MU.log "Created EKS control plane role #{rolename}"
          MU::Cloud::AWS.iam.attach_role_policy(
            policy_arn: "arn:aws:iam::aws:policy/AmazonEKSServicePolicy",
            role_name: rolename
          )
          MU::Cloud::AWS.iam.attach_role_policy(
            policy_arn: "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
            role_name: rolename
          )
          begin
            MU::Cloud::AWS.iam.get_role(role_name: rolename)
          rescue Aws::IAM::Errors::NoSuchEntity => e
            MU.log e.inspect, MU::WARN
            sleep 10
            retry
          end
          arn
        end

        # Generate the generic EKS Kubernetes admin role for use with 
        # aws-iam-authenticator
        def self.createK8SAdminRole(rolename)
          resp = MU::Cloud::AWS.iam.create_role(
            role_name: rolename,
            assume_role_policy_document: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'+MU.account_number+':root"},"Action":"sts:AssumeRole","Condition":{}}]}'
          )
          arn = resp.role.arn
          MU.log "Created EKS Kubernetes admin role #{rolename}"
          begin
            MU::Cloud::AWS.iam.get_role(role_name: rolename)
          rescue Aws::IAM::Errors::NoSuchEntity => e
            MU.log e.inspect, MU::WARN
            sleep 10
            retry
          end
          arn
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

            role_arn = MU::Cloud::AWS::ContainerCluster.createControlPlaneIAMRole(@mu_name)
            MU::Cloud::AWS::Server.createIAMProfile(@mu_name+"-WORKERS", canned_policies: ["AmazonEKSWorkerNodePolicy", "AmazonEKS_CNI_Policy", "AmazonEC2ContainerRegistryReadOnly"])
#            @config['k8s_admin_role'] = MU::Cloud::AWS::ContainerCluster.createK8SAdminRole(@mu_name+"-K8SADMIN")

            security_groups = []
            if @dependencies.has_key?("firewall_rule")
              @dependencies['firewall_rule'].values.each { |sg|
                security_groups << sg.cloud_id
              }
            end

            resp = nil
            begin
              MU.log "Creating EKS cluster #{@mu_name}"
              resp = MU::Cloud::AWS.eks(@config['region']).create_cluster(
                name: @mu_name,
                version: @config['kubernetes']['version'],
                role_arn: role_arn,
                resources_vpc_config: {
                  security_group_ids: security_groups,
                  subnet_ids: subnet_ids
                }
              )
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
              resp = MU::Cloud::AWS.eks(@config['region']).describe_cluster(
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
            MU::Cloud::AWS.ecs(@config['region']).create_cluster(
              cluster_name: @mu_name
            )
          end
          @cloud_id = @mu_name
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          serverpool = @deploy.findLitterMate(type: "server_pools", name: @config["name"]+"-"+@config["flavor"].downcase)
          resource_lookup = MU::Cloud::AWS.listInstanceTypes(@config['region'])[@config['region']]

          if @config['kubernetes']
            kube = ERB.new(File.read(MU.myRoot+"/cookbooks/mu-tools/templates/default/kubeconfig.erb"))
            configmap = ERB.new(File.read(MU.myRoot+"/extras/aws-auth-cm.yaml.erb"))
            tagme = [@vpc.cloud_id]
            tagme_elb = []
            @vpc.subnets.each { |s|
              tagme << s.cloud_id
              tagme_elb << s.cloud_id if !s.private?
            }
            rtbs = MU::Cloud::AWS.ec2(@config['region']).describe_route_tables(
              filters: [ { name: "vpc-id", values: [@vpc.cloud_id] } ]
            ).route_tables
            tagme.concat(rtbs.map { |r| r.route_table_id } )
            main_sg = @deploy.findLitterMate(type: "firewall_rules", name: "server_pool#{@config['name']}-workers")
            tagme << main_sg.cloud_id
            MU.log "Applying kubernetes.io tags to VPC resources", details: tagme
            MU::Cloud::AWS.createTag("kubernetes.io/cluster/#{@mu_name}", "shared", tagme)
            MU::Cloud::AWS.createTag("kubernetes.io/cluster/elb", @mu_name, tagme_elb)

            me = cloud_desc
            @endpoint = me.endpoint
            @cacert = me.certificate_authority.data
            @cluster = @mu_name
            resp = MU::Cloud::AWS.iam.get_role(role_name: @mu_name+"-WORKERS")
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
            MU.log "Configuring Kubernetes <=> IAM mapping for worker nodes", details: authmap_cmd
# maybe guard this mess
            %x{#{authmap_cmd}}

# and this one
            admin_user_cmd = %Q{/opt/mu/bin/kubectl --kubeconfig "#{kube_conf}" apply -f "#{MU.myRoot}/extras/admin-user.yaml"}
            admin_role_cmd = %Q{/opt/mu/bin/kubectl --kubeconfig "#{kube_conf}" apply -f "#{MU.myRoot}/extras/admin-role-binding.yaml"}
            MU.log "Configuring Kubernetes admin-user and role", details: admin_user_cmd+"\n"+admin_role_cmd
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

            MU.log %Q{How to interact with your Kubernetes cluster\nkubectl --kubeconfig "#{kube_conf}" get all\nkubectl --kubeconfig "#{kube_conf}" create -f some_k8s_deploy.yml}, MU::SUMMARY
          else
            resp = MU::Cloud::AWS.ecs(@config['region']).list_container_instances({
              cluster: @mu_name
            })
            existing = {}
            if resp
              uuids = []
              resp.container_instance_arns.each { |arn|
                uuids << arn.sub(/^.*?:container-instance\//, "")
              }
              if uuids.size > 0
                resp = MU::Cloud::AWS.ecs(@config['region']).describe_container_instances({
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
                MU::Cloud::AWS.ecs(@config['region']).register_container_instance(params)
  
              }
            }
          end
# launch_type: "EC2" only option in GovCloud
        end

        # Return the cloud layer descriptor for this EKS/ECS/Fargate cluster
        # @return [OpenStruct]
        def cloud_desc
          if @config['flavor'] == "EKS"
            resp = MU::Cloud::AWS.eks(@config['region']).describe_cluster(
              name: @mu_name
            )
            resp.cluster
          else
            resp = MU::Cloud::AWS.ecs(@config['region']).describe_clusters(
              clusters: [@mu_name]
            )
            resp.clusters.first
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
            resp = MU::Cloud::AWS.ssm(region).get_parameters(
              names: ["/aws/service/#{flavor.downcase}/optimized-ami/amazon-linux/recommended"]
            )
            if resp and resp.parameters and resp.parameters.size > 0
              image_details = JSON.parse(resp.parameters.first.value)
              return image_details['image_id']
            end
          elsif flavor == "EKS"
            # XXX this is absurd, but these don't appear to be available from an API anywhere
            # Here's their Packer build, should just convert to Chef: https://github.com/awslabs/amazon-eks-ami
            amis = { "us-east-1" => "ami-0440e4f6b9713faf6", "us-west-2" => "ami-0a54c984b9f908c81", "eu-west-1" => "ami-0c7a4976cb6fafd3a" }
            return amis[region]
          end
          nil
        end

        # Use the AWS SSM API to fetch the current version of the Amazon Linux
        # EKS-optimized AMI, so we can use it as a default AMI for EKS deploys.
        def self.getEKSImageId(region = MU.myRegion)
          resp = MU::Cloud::AWS.ssm(region).get_parameters(
            names: ["/aws/service/ekss/optimized-ami/amazon-linux/recommended"]
          )
          if resp and resp.parameters and resp.parameters.size > 0
            image_details = JSON.parse(resp.parameters.first.value)
            return image_details['image_id']
          end
          nil
        end

        # Remove all container_clusters associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          resp = MU::Cloud::AWS.ecs(region).list_clusters

          if resp and resp.cluster_arns and resp.cluster_arns.size > 0
            resp.cluster_arns.each { |arn|
              if arn.match(/:cluster\/(#{MU.deploy_id}[^:]+)$/)
                cluster = Regexp.last_match[1]
                instances = MU::Cloud::AWS.ecs(region).list_container_instances({
                  cluster: cluster
                })
                if instances
                  instances.container_instance_arns.each { |arn|
                    uuid = arn.sub(/^.*?:container-instance\//, "")
                    MU.log "Deregistering instance #{uuid} from ECS Cluster #{cluster}"
                    if !noop
                      resp = MU::Cloud::AWS.ecs(region).deregister_container_instance({
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
                  deletion = MU::Cloud::AWS.ecs(region).delete_cluster(
                    cluster: cluster
                  )
                end
              end
            }
          end
          return if !MU::Cloud::AWS::ContainerCluster.EKSRegions.include?(region)


          resp = MU::Cloud::AWS.eks(region).list_clusters

          if resp and resp.clusters
            resp.clusters.each { |cluster|
              if cluster.match(/^#{MU.deploy_id}-/)

                desc = MU::Cloud::AWS.eks(region).describe_cluster(
                  name: cluster
                ).cluster

                untag = []
                untag << desc.resources_vpc_config.vpc_id
                subnets = MU::Cloud::AWS.ec2(region).describe_subnets(
                  filters: [ { name: "vpc-id", values: [desc.resources_vpc_config.vpc_id] } ]
                ).subnets

                # subnets
                untag.concat(subnets.map { |s| s.subnet_id } )
                rtbs = MU::Cloud::AWS.ec2(region).describe_route_tables(
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
                  MU::Cloud::AWS.eks(region).delete_cluster(
                    name: cluster
                  )
                  begin
                    status = nil
                    retries = 0
                    begin
                      deletion = MU::Cloud::AWS.eks(region).describe_cluster(
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
                  MU::Cloud::AWS::Server.removeIAMProfile(cluster)
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
        def self.find(cloud_id: nil, region: MU.curRegion, flags: {})
          MU.log cloud_id, MU::WARN, details: flags
          MU.log region, MU::WARN
          resp = MU::Cloud::AWS.ecs(region).list_clusters
          resp = MU::Cloud::AWS.eks(region).list_clusters
          exit
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
            "platform" => {
              "description" => "The platform to choose for worker nodes. Will default to Amazon Linux for ECS, CentOS 7 for everything else",
              "default" => "centos7"
            },
            "ami_id" => {
              "type" => "string",
              "description" => "The Amazon EC2 AMI on which to base this cluster's container hosts. Will use the default appropriate for the platform, if not specified."
            },
            "run_list" => {
              "type" => "array",
              "items" => {
                  "type" => "string",
                  "description" => "An extra Chef run list entry, e.g. role[rolename] or recipe[recipename]s, to be run on worker nodes."
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

          if MU::Cloud::AWS.isGovCloud?(cluster["region"]) and cluster["flavor"] != "ECS"
            MU.log "AWS GovCloud does not support #{cluster["flavor"]} yet, just ECS", MU::ERR
            ok = false
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


          if ["ECS", "EKS"].include?(cluster["flavor"])

            worker_pool = {
              "name" => cluster["name"]+"-workers",
              "region" => cluster['region'],
              "min_size" => cluster["instance_count"],
              "max_size" => cluster["instance_count"],
              "wait_for_nodes" => cluster["instance_count"],
              "ssh_user" => cluster["host_ssh_user"],
              "ingress_rules" => [
                "sgs" => ["container_cluster#{cluster['name']}"],
                "port_range" => "1-65535"
              ],
              "basis" => {
                "launch_config" => {
                  "name" => cluster["name"]+"-workers",
                  "size" => cluster["instance_type"]
                }
              }
            }
            if cluster["vpc"]
              worker_pool["vpc"] = cluster["vpc"].dup
              worker_pool["vpc"]["subnet_pref"] = cluster["instance_subnet_pref"]
              worker_pool["vpc"].delete("subnets")
            end
            if cluster["flavor"] == "EKS"
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
            end

            configurator.insertKitten(worker_pool, "server_pools")

            if cluster["flavor"] == "ECS"
              cluster["dependencies"] << {
                "name" => cluster["name"]+"-workers",
                "type" => "server_pool",
              }
            elsif cluster["flavor"] == "EKS"
              cluster['ingress_rules'] ||= []
              cluster['ingress_rules'] << {
                "sgs" => ["server_pool#{cluster['name']}-workers"],
                "port" => 443
              }
              fwname = "container_cluster#{cluster['name']}"
              acl = {"name" => fwname, "rules" => cluster['ingress_rules'], "region" => cluster['region'], "optional_tags" => cluster['optional_tags'] }
              acl["tags"] = cluster['tags'] if cluster['tags'] && !cluster['tags'].empty?
              acl["vpc"] = cluster['vpc'].dup if cluster['vpc']

              ok = false if !configurator.insertKitten(acl, "firewall_rules")
              cluster["add_firewall_rules"] = [] if cluster["add_firewall_rules"].nil?
              cluster["add_firewall_rules"] << {"rule_name" => fwname}
              cluster["dependencies"] << {
                "name" => fwname,
                "type" => "firewall_rule",
              }
            end
          end

          ok
        end

      end
    end
  end
end
