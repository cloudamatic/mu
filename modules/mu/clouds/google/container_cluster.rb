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
            @mu_name ||=
              if @config and @config['engine'] and @config["engine"].match(/^sqlserver/)
                @deploy.getResourceName(@config["name"], max_length: 15)
              else
                @deploy.getResourceName(@config["name"], max_length: 63)
              end

            @mu_name.gsub(/(--|-$)/i, "").gsub(/(_)/, "-").gsub!(/^[^a-z]/i, "")
          end
        end


        # Called automatically by {MU::Deploy#createResources}
        # @return [String]: The cloud provider's identifier for this GKE instance.
        def create
          labels = {}
          MU::MommaCat.listStandardTags.each_pair { |name, value|
            if !value.nil?
              labels[name.downcase] = value.downcase.gsub(/[^a-z0-9\-\_]/i, "_")
            end
          }
          labels["name"] = MU::Cloud::Google.nameStr(@mu_name)

          subnet = nil
          @vpc.subnets.each { |s|
            if s.az == @config['region']
              subnet = s
              break
            end
          }

          desc = {
            :name => @mu_name.downcase,
            :network => @vpc.cloud_id,
            :subnetwork => subnet.cloud_id,
            :resource_labels => labels,
            :initial_cluster_version => @config['kubernetes']['version'],
            :initial_node_count => @config['instance_count'],
            :locations => MU::Cloud::Google.listAZs(@config['region'])
          }

          requestobj = MU::Cloud::Google.container(:CreateClusterRequest).new(
            :cluster => MU::Cloud::Google.container(:Cluster).new(desc)
          )

          cluster = MU::Cloud::Google.container.create_cluster(
            @config['project'],
            @config['availability_zone'],
            requestobj
          )

# XXX wait until the thing is ready
        end

        # Locate an existing ContainerCluster or ContainerClusters and return an array containing matching GCP resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @param flags [Hash]: Optional flags
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching ContainerClusters
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, flags: {})
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
           # XXX do all the kubernetes stuff like we do in AWS
        end

        # Register a description of this cluster instance with this deployment's metadata.
        def notify
          {}
        end

        # Called by {MU::Cleanup}. Locates resources that were created by the
        # currently-loaded deployment, and purges them.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region in which to operate
        # @return [void]
        def self.cleanup(skipsnapshots: false, noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject
          MU::Cloud::Google.listAZs(region).each { |az|
            found = MU::Cloud::Google.container.list_zone_clusters(flags["project"], az)
            if found and found.clusters
              found.clusters.each { |cluster|
                MU.log "Deleting GKE cluster #{cluster.name}"
                if !noop
                  MU::Cloud::Google.container.delete_zone_cluster(flags["project"], az, cluster.name)
                  begin
                    MU::Cloud::Google.container.get_zone_cluster(flags["project"], az, cluster.name)
                    sleep 10
                  rescue ::Google::Apis::ClientError => e
                    if !e.message.match(/notFound:/)
                      raise e
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
          schema = {}
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::container_clusters}, bare and unvalidated.
        # @param cluster [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(cluster, configurator)
          ok = true

          if !cluster['availability_zone']
            cluster['availability_zone'] = MU::Cloud::Google.listAZs(cluster['region']).sample
          end

          ok
        end

        private

      end #class
    end #class
  end
end #module
