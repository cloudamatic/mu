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
      @@default_subscription = nil
      @@regions = []


# UTILITY METHODS
      # Determine whether we (the Mu master, presumably) are hosted in Azure.
      # @return [Boolean]
      def self.hosted?
        if $MU_CFG and $MU_CFG.has_key?("azure_is_hosted")
          @@is_in_azure = $MU_CFG["azure_is_hosted"]
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

      # Alias for #{MU::Cloud::AWS.hosted?}
      def self.hosted
        return MU::Cloud::Azure.hosted?
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
        if  @@myRegion_var
          return @@myRegion_var
        end
        
        if $MU_CFG['azure']['Azure']['default_region']
          # MU.log "Found default region in mu.yml. Using that..."
          @@myRegion_var = $MU_CFG['azure']['Azure']['default_region']

        elsif MU::Cloud::Azure.hosted?
          # IF WE ARE HOSTED IN AZURE CHECK FOR THE REGION OF THE INSTANCE
          metadata = get_metadata()
          @@myRegion_var = metadata['compute']['location']

          # TODO: PERHAPS I SHOULD DEFAULT TO SOMETHING SENSIBLE?
        else
          #raise MuError, "Default Region was not found. Please run mu-configure to setup a region"
        end

        return @@myRegion_var
      end

      # lookup the default subscription that will be used by methods
      def self.default_subscription
        if @@default_subscription.nil?
          if $MU_CFG['azure']['Azure']['subscription']
            # MU.log "Found default subscription in mu.yml. Using that..."
            @@default_subscription = $MU_CFG['azure']['Azure']['subscription']

          elsif list_subscriptions().length == 1
            #MU.log "Found a single subscription on your account. Using that... (This may be incorrect)", MU::WARN, details: e.message
            @@default_subscription = list_subscriptions()[0]

          elsif MU::Cloud::Azure.hosted?
            #MU.log "Found a subscriptionID in my metadata. Using that... (This may be incorrect)", MU::WARN, details: e.message
            @@default_subscription = get_metadata()['compute']['subscriptionId']

          else
            raise MuError, "Default Subscription was not found. Please run mu-configure to setup a default subscription"
          end
        end

        return @@default_subscription
      end

      # LIST THE REGIONS FROM AZURE
      def self.listRegions(subscription: default_subscription())
        if  @@regions.length() > 0 && subscription == default_subscription()
          return @@regions
        end
        
        begin
          sdk_response = MU::Cloud::Azure.subscriptions().list_locations(subscription).value
        rescue
          #pp "Error Getting the list of regions from Azure" #TODO: SWITCH THIS TO MU LOG
          return @@regions
        end

        sdk_response.each do | region |
          @@regions.push(region.name)
        end

        return @@regions
      end

      def self.list_subscriptions()
        subscriptions = []

        sdk_response = MU::Cloud::Azure.subscriptions().list

        sdk_response.each do |subscription|
          subscriptions.push(subscription.subscription_id)
        end

        return subscriptions
      end

      def self.listAZs(region = nil)
        az_list = ['1', '2', '3']

        # Pulled from this chart: https://docs.microsoft.com/en-us/azure/availability-zones/az-overview#services-support-by-region
        az_enabled_regions = ['centralus', 'eastus', 'eastus2', 'westus2', 'francecentral', 'northeurope', 'uksouth', 'westeurope', 'japaneast', 'southeastasia'] 

        if not az_enabled_regions.include?(region)
          az_list = []
        end

        return az_list
      end

      def self.config_example
        sample = hosted_config
        sample ||= {
          "region" => "eastus",
          "subscriptionId" => "99999999-9999-9999-9999-999999999999",
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
        "TODO"
      end

      def self.listInstanceTypes
        return @@instance_types if @@instance_types and @@instance_types[region]
        if !MU::Cloud::Azure.default_subscription()
          return {}
        end

        @@instance_types ||= {}
        @@instance_types[region] ||= {}
        result = MU::Cloud::Google.compute.list_machine_types(MU::Cloud::Google.defaultProject, listAZs(region).first)
        result.items.each { |type|
          @@instance_types[region][type.name] ||= {}
          @@instance_types[region][type.name]["memory"] = sprintf("%.1f", type.memory_mb/1024.0).to_f
          @@instance_types[region][type.name]["vcpu"] = type.guest_cpus.to_f
          if type.is_shared_cpu
            @@instance_types[region][type.name]["ecu"] = "Variable"
          else
            @@instance_types[region][type.name]["ecu"] = type.guest_cpus
          end
        }
        @@instance_types
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

      def self.getSDKOptions
        file = File.open $MU_CFG['azure']['Azure']['credentials_file']
        credentials = JSON.load file
        options = {
          tenant_id: $MU_CFG['azure']['Azure']['directory_id'], # Really Directory ID
          client_id: credentials['client_id'], # Application ID in App Registrations
          client_secret: credentials['client_secret'], # Generated in App Registrations
          subscription_id: default_subscription()
        }
        return options
      end

# BEGIN SDK STUBS
      def self.subscriptions()
        require 'azure_mgmt_subscriptions'

        @@subscriptions_api ||= MU::Cloud::Azure::SDKClient.new(api: "Subscriptions")

        return @@subscriptions_api.subscriptions
      end

      def self.compute(api: "Compute")
        require 'azure_mgmt_compute'

        @@compute_api ||= MU::Cloud::Azure::SDKClient.new(api: "Compute")

        return @@compute_api
      end

      def self.network(api: "Network")
        require 'azure_mgmt_network'

        @@network_api ||= MU::Cloud::Azure::SDKClient.new(api: "Network")

        return @@network_api
      end

      def self.storage(api: "Storage")
        require 'azure_mgmt_storage'

        @@storage_api ||= MU::Cloud::Azure::SDKClient.new(api: "Storage")

        return @@storage_api
      end

# END SDK STUBS

# BEGIN SDK CLIENT
      private

      class SDKClient
        @api = nil
        @credentials = nil

        @@subscriptions_api = {}
        @@compute_api = {}
        @@container_api = {}
        @@storage_api = {}
        @@sql_api = {}
        @@iam_api = {}
        @@logging_api = {}
        @@resource_api = {}
        @@resource2_api = {}
        @@service_api = {}
        @@firestore_api = {}
        @@admin_directory_api = {}

        attr_reader :issuer

        def initialize(api: "Compute")

          @credentials = MU::Cloud::Azure.getSDKOptions()

          @api = Object.const_get("::Azure::#{api}::Profiles::Latest::Mgmt::Client").new(@credentials)
          
        end

        def method_missing(method_sym, *arguments)

          if !arguments.nil? and arguments.size == 1
            retval = @api.method(method_sym).call(arguments[0])
          elsif !arguments.nil? and arguments.size > 0
            retval = @api.method(method_sym).call(*arguments)
          else
            retval = @api.method(method_sym).call
          end

          return retval
        end
      end
# END SDK CLIENT
    end
  end
end