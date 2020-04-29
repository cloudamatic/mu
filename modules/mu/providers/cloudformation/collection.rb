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
      # A Cloud Watch alarm as configured in {MU::Config::BasketofKittens::collections}
      class Collection < MU::Cloud::Collection

        @deploy = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        attr_reader :cfm_template
        attr_reader :cfm_name

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::collections}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name ||= @deploy.getResourceName(@config["name"])
          end
        end

        # Populate @cfm_template with a resource description for this alarm
        # in CloudFormation language.
        def create
          @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase(self.class.cfg_name, self, tags: @config['tags'], scrub_mu_isms: @config['scrub_mu_isms'])
          if @config["template_url"].nil?
            raise MuError, "You must specify template_url when creating a Collection and targeting CloudFormation (note: the template_file parameter is not supported when nesting CloudFormation templates)."
          end
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "TemplateURL", @config["template_url"])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "TimeoutInMinutes", @config["timeout"])
          if @config['cfm_deps']
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "TimeoutInMinutes", @config["timeout"])
          end
          # XXX Should do this for any resource that can depend on a VPC
          @config['dependencies'].each { |dep|
            if dep['type'] == "vpc"
              subnets = @dependencies["vpc"][dep['name']].cloudobj.subnets
              subnets.each { |subnet|
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", subnet.cfm_name)
              }
            end
          }

          parameters = Hash.new
          if !@config["parameters"].nil?
            @config["parameters"].each { |parameter|
              # Dumb old-school static string parameters. Nobody should use
              # these. Modern Mu parameters are vastly superior.
              parameters[parameter["parameter_key"]] = parameter["parameter_value"]
            }
          end
          if !@config["pass_deploy_key_as"].nil?
            parameters[@config["pass_deploy_key_as"]] = keypairname
          end

          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Parameters", parameters)
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

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          MU::Cloud.resourceClass("AWS", "Collection").schema(config)
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::servers}, bare and unvalidated.
        # @param server [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(server, configurator)
          MU::Cloud.resourceClass("AWS", "Collection").validateConfig(server, configurator)
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          MU::Cloud.resourceClass("AWS", "Collection").isGlobal?
        end

      end
    end
  end
end
