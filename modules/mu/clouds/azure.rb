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

require 'open-uri'
require 'json'
require 'timeout'

module MU
  class Cloud
    # Support for Microsoft Azure as a provisioning layer.
    class Azure
      @@is_in_azure = nil
      @@metadata = nil
      @@acct_to_profile_map = nil #WHAT EVEN IS THIS? 
      @@myRegion_var = nil

      # Alias for #{MU::Cloud::AWS.hosted?}
      def self.hosted
        MU::Cloud::Azure.hosted?
      end

      # Determine whether we (the Mu master, presumably) are hosted in Azure.
      # @return [Boolean]
      def self.hosted?
        if $MU_CFG and $MU_CFG.has_key?("azure_is_hosted")
          @@is_in_aws = $MU_CFG["azure_is_hosted"]
          return $MU_CFG["azure_is_hosted"]
        end


        if !@@is_in_azure.nil?
          return @@is_in_azure
        end

        begin
          metadata = get_metadata()
          if metadata['compute']['vmId']
            @@is_in_azure = true
            return true
          else
            return false
          end
        rescue
          # MU.log "Failed to get Azure MetaData. I assume I am not hosted in Azure", MU::DEBUG, details: resources
        end

        @@is_in_azure = false
        false
      end

      def self.hosted_config
        return nil if !hosted?
        region = get_metadata()['compute']['location']
        subscription = get_metadata()['compute']['subscriptionId']
        {
          "region" => region,
          "subscriptionId" => subscription
        }
      end

      # Any cloud-specific instance methods we require our resource implementations to have, above and beyond the ones specified by {MU::Cloud}
      # @return [Array<Symbol>]
      def self.required_instance_methods
        []
      end

      # Method that returns the default Azure region for this Mu Master
      # @return [string]
      def self.myRegion
        cfg = credConfig() #Get Azure configuration from the config file

        if cfg and cfg['region'] 
          @@myRegion_var = cfg['region'] # If region is defined in the config, return it

        elsif MU::Cloud::Azure.hosted? # IF WE ARE HOSTED IN AZURE CHECK FOR THE REGION OF THE INSTANCE
          metadata = get_metadata()
          zone = metadata['compute']['location']
          @@myRegion_var = zone
        end

        return @@myRegion_var
      end

      def self.listRegions(credentials = nil)
        #subscriptions_client = Azure::Subscriptions::Profiles::Latest::Mgmt::Client.new(options)
        []
      end

      def self.listAZs(region = nil)
        []
      end

      def self.config_example
        sample = hosted_config
        sample ||= {
          "region" => "eastus",
          "subscriptionId" => "b8f6ed82-98b5-4249-8d2f-681f636cd787",
        }

        sample["credentials_file"] = "~/.azure/credentials"
        sample["log_bucket_name"]  = "my-mu-s3-bucket"
        sample
      end

      def self.writeDeploySecret
        "TODO"
      end

      def self.listCredentials
        "TODO"
      end

      def self.credConfig (name = nil, name_only: false)
        # If there's nothing in mu.yaml (which is wrong), but we're running on a machine hosted in Azure, fake it with that machine's service account and hope for the best.
#         if !$MU_CFG['azure'] or !$MU_CFG['azure'].is_a?(Hash) or $MU_CFG['azure'].size == 0
#           return @@my_hosted_cfg if @@my_hosted_cfg

#           if hosted?
#             begin
# #              iam_data = JSON.parse(getAWSMetaData("iam/info"))
# #              if iam_data["InstanceProfileArn"] and !iam_data["InstanceProfileArn"].empty?
#                 @@my_hosted_cfg = hosted_config
#                 return name_only ? "#default" : @@my_hosted_cfg
# #              end
#             rescue JSON::ParserError => e
#             end
#           end

#           return nil
#         end

        if name.nil?
          $MU_CFG['azure'].each_pair { |name, cfg|
            if cfg['azure']
              return name_only ? name : cfg
            end
          }
        else
          if $MU_CFG['azure'][name]
            return name_only ? name : $MU_CFG['azure'][name]
          elsif @@acct_to_profile_map[name.to_s]
            return name_only ? name : @@acct_to_profile_map[name.to_s]
          end
# XXX whatever process might lead us to populate @@acct_to_profile_map with some mappings, like projectname -> account profile, goes here
          return nil
        end
      end

      def self.listInstanceTypes
        "TODO"
      end
      
      def self.adminBucketName(credentials = nil)
        "TODO"
      end

      def self.adminBucketUrl(credentials = nil)
        "TODO"
      end
      
      #END REQUIRED METHODS


      # Fetch (ALL) Azure instance metadata
      # @return [Hash, nil]
      def self.get_metadata()
        base_url = "http://169.254.169.254/metadata/instance"
        api_version = '2017-08-01'

        begin
          Timeout.timeout(2) do
            @@metadata ||= JSON.parse(open("#{base_url}/?api-version=#{ api_version }","Metadata"=>"true").read)
          end
          return @@metadata

        rescue Timeout::Error => e
          # MU.log "Timeout querying Azure Metadata"
          return nil
        rescue
          # MU.log "Failed to get Azure MetaData."
          return nil
        end
      end

    end
  end
end