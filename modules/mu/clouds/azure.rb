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

require "net/http"
require 'net/https'
require 'multi_json'
require 'stringio'

module MU
  class Cloud
    # Support for Microsoft Azure as a provisioning layer.
    class Azure

      @@is_in_azure = nil

      # Alias for #{MU::Cloud::AWS.hosted?}
      def self.hosted
        MU::Cloud::Azure.hosted?
      end

      # Determine whether we (the Mu master, presumably) are hosted in this
      # cloud.
      # @return [Boolean]
      def self.hosted?
        if !@@is_in_azure.nil?
          return @@is_in_azure
        end

        puts getAzureMetaData("compute")
        exit
        

        # if getAzureMetaData("compute")
          
        #   @@is_in_azure = true
        #   return true
        # end
        # @@is_in_azure = false
        # false
      end

      # If we're running this cloud, return the $MU_CFG blob we'd use to
      # describe this environment as our target one.
      def self.hosted_config
        return nil if !hosted?
        region = getAzureMetaData("compute/location")
        subscription_id = getAzureMetaData("compute/subscription_id")
        acct_num.chomp!
        {
          "region" => region,
          "subscription" => subscription_id
        }
      end

      # Fetch an Azure instance metadata parameter (example: public-ipv4).
      # @param param [String]: The parameter name to fetch
      # @return [String, nil]
      def self.getAzureMetaData(param)
        base_url = "http://169.254.169.254/metadata/instance"
        api_version = '2017-12-01'
        begin
          response = nil
          Timeout.timeout(1) do
            response = open("#{base_url}/#{param}?api-version=#{ api_version }").read
          end

          response
        rescue OpenURI::HTTPError, Timeout::Error, SocketError, Errno::ENETUNREACH, Net::HTTPServerException, Errno::EHOSTUNREACH => e
          # This is normal on machines checking to see if they're AWS-hosted
          logger = MU::Logger.new
          logger.log "Failed metadata request #{base_url}/#{param}: #{e.inspect}", MU::DEBUG
          return nil
        end
      end

      # A non-working example configuration
      def self.config_example
        sample = hosted_config
        sample ||= {
          "region" => "eastus",
          "subscription" => "123456789012",
        }
        sample["credentials_file"] = "#{Etc.getpwuid(Process.uid).dir}/.azure/azure_credentials.json"
        sample["log_bucket_name"] = "my-azure-mu-storage-account"
        sample
      end

      # If we've configured Azure as a provider, or are simply hosted in Azure, 
      # decide what our default region is.
      def self.myRegion
        return @@myRegion_var if @@myRegion_var
        return nil if credConfig.nil? and !hosted?

        if $MU_CFG and (!$MU_CFG['azure'] or !subscription) and !hosted?
          return nil
        end

        if $MU_CFG and $MU_CFG['azure'] and $MU_CFG['azure']['region']
          @@myRegion_var ||= MU::Cloud::AWS.ec2(region: $MU_CFG['aws']['region']).describe_availability_zones.availability_zones.first.region_name
        elsif ENV.has_key?("EC2_REGION") and !ENV['EC2_REGION'].empty?
          @@myRegion_var ||= MU::Cloud::AWS.ec2(region: ENV['EC2_REGION']).describe_availability_zones.availability_zones.first.region_name
        else
          # hacky, but useful in a pinch
          az_str = MU::Cloud::AWS.getAWSMetaData("placement/availability-zone")
          @@myRegion_var = az_str.sub(/[a-z]$/i, "") if az_str
        end
      end

      # List all known Google Cloud Platform regions
      # @param us_only [Boolean]: Restrict results to United States only
      def self.listRegions(us_only = false, credentials: nil)
        if !MU::Cloud::Google.defaultProject
          return []
        end
        if @@regions.size == 0
          begin
            result = MU::Cloud::Google.compute.list_regions(MU::Cloud::Google.defaultProject)
          rescue ::Google::Apis::ClientError => e
            if e.message.match(/forbidden/)
              raise MuError, "Insufficient permissions to list Google Cloud region. The service account #{myServiceAccount} should probably have the project owner role."
            end
            raise e
          end

          regions = []
          result.items.each { |region|
            @@regions[region.name] = []
            region.zones.each { |az|
              @@regions[region.name] << az.sub(/^.*?\/([^\/]+)$/, '\1')
            }
          }
        end
        if us_only
          @@regions.keys.delete_if { |r| !r.match(/^us/) }
        else
          @@regions.keys
        end
      end

      # List the Availability Zones associated with a given Google Cloud
      # region. If no region is given, search the one in which this MU master
      # server resides (if it resides in this cloud provider's ecosystem).
      # @param region [String]: The region to search.
      # @return [Array<String>]: The Availability Zones in this region.
      def self.listAZs(region = MU.curRegion)
        MU::Cloud::Google.listRegions if !@@regions.has_key?(region)
        raise MuError, "No such Google Cloud region '#{region}'" if !@@regions.has_key?(region)
        @@regions[region]
      end

      @@instance_types = nil
      # Query the GCP API for the list of valid Compute instance types and some of
      # their attributes. We can use this in config validation and to help
      # "translate" machine types across cloud providers.
      # @param region [String]: Supported machine types can vary from region to region, so we look for the set we're interested in specifically
      # @return [Hash]
      def self.listInstanceTypes(region = myRegion)
        return @@instance_types if @@instance_types and @@instance_types[region]
        if !MU::Cloud::Google.defaultProject
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

      # Return the name strings of all known sets of credentials for this cloud
      # @return [Array<String>]
      def self.listCredentials
        if !$MU_CFG['google']
          return hosted? ? ["#default"] : nil
        end

        $MU_CFG['google'].keys
      end

      # If we've configured Google as a provider, or are simply hosted in GCP, 
      # decide what our default region is.
      def self.myRegion
        if $MU_CFG['google'] and $MU_CFG['google']['region']
          @@myRegion_var = $MU_CFG['google']['region']
        elsif MU::Cloud::Google.hosted?
          zone = MU::Cloud::Google.getGoogleMetaData("instance/zone")
          @@myRegion_var = zone.gsub(/^.*?\/|\-\d+$/, "")
        end
        @@myRegion_var
      end

      # Plant a Mu deploy secret into a storage bucket somewhere for so our kittens can consume it
      # @param deploy_id [String]: The deploy for which we're writing the secret
      # @param value [String]: The contents of the secret
      def self.writeDeploySecret(deploy_id, value)
        name = deploy_id+"-secret"
        begin
          MU.log "Writing #{name} to Cloud Storage bucket #{$MU_CFG['google']['log_bucket_name']}"
          f = Tempfile.new(name) # XXX this is insecure and stupid
          f.write value
          f.close
          objectobj = MU::Cloud::Google.storage(:Object).new(
            bucket: $MU_CFG['google']['log_bucket_name'],
            name: name
          )
          ebs_key = MU::Cloud::Google.storage.insert_object(
            $MU_CFG['google']['log_bucket_name'],
            objectobj,
            upload_source: f.path
          )
          f.unlink
        rescue ::Google::Apis::ClientError => e
# XXX comment for NCBI tests
#          raise MU::MommaCat::DeployInitializeError, "Got #{e.inspect} trying to write #{name} to #{$MU_CFG['google']['log_bucket_name']}"
        end
      end

      # Any cloud-specific instance methods we require our resource
      # implementations to have, above and beyond the ones specified by
      # {MU::Cloud}
      # @return [Array<Symbol>]
      def self.required_instance_methods
        []
      end

      # If we're running this cloud, return the $MU_CFG blob we'd use to
      # describe this environment as our target one.
      def self.hosted_config
        return nil if !hosted?
        getGoogleMetaData("instance/zone").match(/^projects\/[^\/]+\/zones\/([^\/]+)$/)
        zone = Regexp.last_match[1]
        {
          "project" => MU::Cloud::Google.getGoogleMetaData("project/project-id"),
          "region" => zone.sub(/-[a-z]$/, "")
        }
      end
    end
  end
end



