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

module MU
  class Cloud
    # Support for Microsoft Azure as a provisioning layer.
    class Azure
      @@is_in_azure = nil

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

      def self.myRegion
        "TODO"
      end

      def self.listRegions(credentials = nil)
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

      def self.credConfig
        "TODO"
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


      # Fetch an Azure instance metadata parameter (example: public-ipv4).
      # @return [String, nil]
      def self.get_metadata()
        base_url = "http://169.254.169.254/metadata/instance"
        api_version = '2017-08-01'
        # begin
          response = nil
          
          response = JSON.parse(open("#{base_url}/?api-version=#{ api_version }","Metadata"=>"true").read)

          response
        # rescue
        #   MU.log "Failed to get Azure MetaData."
        # end
      end
    end
  end
end