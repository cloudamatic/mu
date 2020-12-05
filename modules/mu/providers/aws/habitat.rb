# Copyright:: Copyright (c) 2019 eGlobalTech, Inc., all rights reserved
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
      # Creates an AWS account as configured in {MU::Config::BasketofKittens::habitats}
      class Habitat < MU::Cloud::Habitat

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"], max_length: 63)
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          if !@config['email']
            avail_chars = 62 - $MU_CFG['mu_admin_email'].size
            alias_str = @deploy.getResourceName(@config["name"], max_length: avail_chars, need_unique_string: true) 
            @config['email'] ||= $MU_CFG['mu_admin_email'].sub(/(\+.*?)?@/, "+"+alias_str+"@")
          end

          MU.log "Creating AWS account #{@mu_name} with contact email #{@config['email']}"
          resp = MU::Cloud::AWS.orgs(credentials: @credentials).create_account(
            account_name: @mu_name,
            email: @config['email']
          )

          createid = resp.create_account_status.id

          begin
            resp = MU::Cloud::AWS.orgs(credentials: @credentials).describe_create_account_status(
              create_account_request_id: createid
            )
            if !["SUCCEEDED", "IN_PROGRESS"].include?(resp.create_account_status.state)
              raise MuError, "Failed to create account #{@mu_name}: #{resp.create_account_status.failure_reason}"
            end
            if resp.create_account_status.state == "IN_PROGRESS"
              sleep 10
            end
          end while resp.create_account_status.state == "IN_PROGRESS"

          @cloud_id = resp.create_account_status.account_id

          MU.log "Creation of account #{@mu_name} (#{resp.create_account_status.account_id}) complete"
        end

        @cloud_desc_cache = nil
        # Return the cloud descriptor for the Habitat
        def cloud_desc(use_cache: true)
          return @cloud_desc_cache if @cloud_desc_cache and use_cache
          @cloud_desc_cache = MU::Cloud::AWS::Habitat.find(cloud_id: @cloud_id).values.first
          @cloud_desc_cache
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          nil
        end

        # Return the metadata for this account configuration
        # @return [Hash]
        def notify
          {
          }
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          true
        end

        # Remove all AWS accounts associated with the currently loaded deployment. Try to, anyway.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, credentials: nil, flags: {})
          return if !orgMasterCreds?(credentials)
          MU.log "AWS::Habitat.cleanup: need to support flags['known']", MU::DEBUG, details: flags
          MU.log "Placeholder: AWS Habitat artifacts do not support tags, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: ignoremaster

          resp = MU::Cloud::AWS.orgs(credentials: credentials).list_accounts

          if resp and resp.accounts
            resp.accounts.each { |acct|
              if acct.name.match(/^#{Regexp.quote(deploy_id)}/) or acct.name.match(/BUNS/)
                if !noop
                  pp acct
                end
                MU.log "AWS accounts cannot be deleted via the API. To delete #{acct.name}, you must sign in with its root user #{acct.email}, ensure that its signup process has been completed, then visit ", MU::NOTICE, details: ["https://console.aws.amazon.com/", acct.email, acct.id]
              end
            }
          end
        end

        # Locate an existing account
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching account
        def self.find(**_args)
          {}
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "email" => {
              "type" => "string",
              "description" => "AWS accounts require a unique contact email address. If not provided, Mu will generate an alias to the global mu_admin_email using the +foo SMTP mechanism."
            }
          }
          [toplevel_required, schema]
        end

        # @param _account_number [String]
        # @param _credentials [String]
        # @return [Boolean]
        def self.isLive?(_account_number, _credentials = nil)
          true
        end

        # Figure out what account we're calling from, and then figure out if
        # it's the organization's master account- the only place from which
        # we can create accounts, amongst other things.
        # @param credentials [String]
        # @return [Boolean]
        def self.orgMasterCreds?(credentials = nil)
          acct_num = MU::Cloud::AWS.iam(credentials:  credentials).list_users.users.first.arn.split(/:/)[4]

          parentorg = MU::Cloud.resourceClass("AWS", "Folder").find(credentials: credentials).values.first
          acct_num == parentorg.master_account_id
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::habitats}, bare and unvalidated.
        # @param habitat [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(habitat, _configurator)
          ok = true

          if !habitat["email"]
            MU.log "No email address specified in habitat #{habitat['name']}, and AWS requires a unique contact email. Will generate an alias to #{$MU_CFG['mu_admin_email']} at run time.", MU::NOTICE
          end

          if !orgMasterCreds?(habitat['credentials'])
            MU.log "The Organization master account for habitat #{habitat["name"]} is #{parentorg.master_account_id}, but my credentials (#{ habitat['credentials'] ?  habitat['credentials'] : "default"}) are for a non-master account (#{acct_num}). AWS accounts can only be created and managed with credentials from an Organization's master account.", MU::ERR
            ok = false
          end

          ok
        end

      end
    end
  end
end
