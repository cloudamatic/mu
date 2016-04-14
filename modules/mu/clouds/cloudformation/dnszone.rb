# Copyright:: Copyright (c) 2016 eGlobalTech, Inc., all rights reserved
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
      # A log target as configured in {MU::Config::BasketofKittens::dnszones}
      class DNSZone < MU::Cloud::DNSZone

        @deploy = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        attr_reader :cfm_template
        attr_reader :cfm_name

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::dnszones}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          else
            @mu_name ||= @deploy.getResourceName(@config["name"])
          end
        end

        # Populate @cfm_template with a resource description for this dnszone
        # in CloudFormation language.
        def create
          @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase("dnszone", self)
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Name", @config['name'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "HostedZoneConfig", { "Comment" => MU.deploy_id })

          if @config['private']
            if @config['all_account_vpcs']
# XXX would need a way to add tails (CloudFormation paramaters, effectively) here in order to prompt the user for stuff like which pre-existing VPCs to plug in. Maybe we can have the config parser do that for is and pass it all in as @config['vpcs'], which would in turn be Refs to parameters? It'd need to know about the -c flag for AWS resources being converted on the fly.
#            MU::Config.getTail("#{parent_name}vpc_id", value: vpc_block["vpc_id"], prettyname: "#{parent_name} Target VPC",  cloud_type: "AWS::EC2::VPC::Id")
              raise MuError, "DNSZone parameter 'all_account_vpcs' currently not supported for CloudFormation targets"
            else
              raise MuError, "DNS Zone #{@config['name']} is flagged as private, you must either provide a VPC, or set 'all_account_vpcs' to true" if @config['vpcs'].nil? || @config['vpcs'].empty?
              @config['vpcs'].each { |vpc|
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "VPCs", { "VPCId" => vpc['vpc_id'], "VPCRegion" => vpc['region'] })
              }
            end
          end

          @config['records'].each { |dnsrec|
            realtarget =
              if dnsrec['mu_type'] == "loadbalancer"
                pp dnsrec
                pp @dependencies.keys

                if @dependencies.has_key?("loadbalancer") && dnsrec['deploy_id'].nil?
                  { "Fn::GetAtt" => [@dependencies["loadbalancer"][dnsrec['target']].cloudobj.cfm_name, "DNSZone"] }
                end
              end

            rec_name, rec_template = MU::Cloud::CloudFormation.cloudFormationBase("dnsrecord", name: dnsrec['target'])
            pp rec_template
          }
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
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def self.genericMuDNSEntry(*args)
          MU.log "find() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def self.createRecordsFromConfig(*args)
          MU.log "find() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end

      end
    end
  end
end
