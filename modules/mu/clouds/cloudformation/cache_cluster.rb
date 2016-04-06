# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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
    class CloudFormation
      # A load balancer as configured in {MU::Config::BasketofKittens::cache_clusters}
      class CacheCluster < MU::Cloud::CacheCluster

        @deploy = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        attr_reader :cfm_template
        attr_reader :cfm_name

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::loadbalancers}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          else
            @mu_name ||=
              if @config["create_replication_group"]
                @deploy.getResourceName(@config["name"], max_length: 16, need_unique_string: true)
              else
                @deploy.getResourceName(@config["name"], max_length: 20, need_unique_string: true)
              end

            @mu_name.gsub!(/(--|-$)/i, "")

          end
        end

        # Populate @cfm_template with a resource description for this cache
        # cluster in CloudFormation language.
        def create
          @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase(self.class.cfg_name, self, tags: @config['tags']) if @cfm_template.nil?
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "ClusterName", @mu_name)
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Engine", @config['engine'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "CacheNodeType", @config['size'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "NumCacheNodes", @config['node_count'].to_s)

          if !@config['vpc'].nil?
            subnets_name, subnets_template = MU::Cloud::CloudFormation.cloudFormationBase("cache_subnets", name: @mu_name)
            if !@config['vpc']['subnets'].nil?
              @config['vpc']['subnets'].each { |subnet|
                if !subnet["subnet_id"].nil?
                  MU::Cloud::CloudFormation.setCloudFormationProp(subnets_template[subnets_name], "SubnetIds", subnet["subnet_id"])
                elsif @dependencies.has_key?("vpc") and @dependencies["vpc"].has_key?(@config["vpc"]["vpc_name"])
                  @dependencies["vpc"][@config["vpc"]["vpc_name"]].subnets.each { |subnet_obj|
                    if subnet_obj.name == subnet['subnet_name']
                      MU::Cloud::CloudFormation.setCloudFormationProp(subnets_template[subnets_name], "DependsOn", subnet_obj.cfm_name)
                      MU::Cloud::CloudFormation.setCloudFormationProp(subnets_template[subnets_name], "SubnetIds", { "Ref" => subnet_obj.cfm_name } )
                    end
                  }
                end
              }
            end
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "CacheSubnetGroupName", { "Ref" => subnets_name } )
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", subnets_name)
            @cfm_template.merge!(subnets_template)
          end
        end

        # Return the metadata for this CacheCluster
        # @return [Hash]
        def notify
          {}
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def self.find(*args)
          MU.log "find() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def self.cleanup(*args)
          MU.log "cleanup() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end

      end
    end
  end
end
