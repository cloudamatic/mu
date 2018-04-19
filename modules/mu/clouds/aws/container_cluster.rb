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
          resp = MU::Cloud::AWS.ecs(@config['region']).create_cluster({
            cluster_name: @mu_name
          })
          pp resp
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          MU.log "IN GROOM FOR CONTAINERCLUSTER", MU::WARN
          serverpool = @deploy.findLitterMate(type: "server_pools", name: @config["name"]+"-"+@config["flavor"].downcase)
          resource_lookup = MU::Cloud::AWS.listInstanceTypes(@config['region'])[@config['region']]
          resp = MU::Cloud::AWS.ecs(@config['region']).list_container_instances({
            cluster: @mu_name
          })
          existing = {}
          if resp
            uuids = []
            resp.container_instance_arns.each { |arn|
              uuids << arn.sub(/^.*?:container-instance\//, "")
            }
            resp = MU::Cloud::AWS.ecs(@config['region']).describe_container_instances({
              cluster: @mu_name,
              container_instances: uuids
            })
            resp.container_instances.each { |i|
              existing[i.ec2_instance_id] = i
            }
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
              pp MU::Cloud::AWS.ecs(@config['region']).register_container_instance(params)
            }
          }
# launch_type: "EC2" only option in GovCloud
        end

        # Return the metadata for this ContainerCluster
        # @return [Hash]
        def notify
          deploy_struct = {
          }
          return deploy_struct
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
        end

        # Locate an existing container_clusters.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching container_clusters.
        def self.find(cloud_id: nil, region: MU.curRegion, flags: {})
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
            "ami_id" => {
              "type" => "string",
              "description" => "The Amazon EC2 AMI on which to base this cluster's container hosts. Will use the default appropriate for the platform, if not specified."
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

          if MU::Cloud::AWS.isGovCloud?(cluster["region"]) and cluster["flavor"] != "ECS"
            MU.log "AWS GovCloud does not support #{cluster["flavor"]} yet, just ECS", MU::ERR
            ok = false
          end

          if ["ECS", "EKS"].include?(cluster["flavor"])
            MU::Config::ContainerCluster.insert_host_pool(
              configurator,
              cluster["name"]+"-"+cluster["flavor"].downcase,
              cluster["instance_count"],
              cluster["instance_type"],
              cluster["vpc"],
              cluster["host_image"]
            )
            cluster["dependencies"] << {
              "name" => cluster["name"]+"-"+cluster["flavor"].downcase,
              "type" => "server_pool",
            }
          end

          ok
        end

      end
    end
  end
end
