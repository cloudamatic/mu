# Copyright:: Copyright (c) 2020 eGlobalTech, Inc., all rights reserved
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
      # A scheduled task facility as configured in {MU::Config::BasketofKittens::jobs}
      class Job < MU::Cloud::Job

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          @cloud_id = @mu_name

          params = get_properties

          MU.log "Creating CloudWatch Event #{@mu_name}", MU::NOTICE, details: params

          MU::Cloud::AWS.cloudwatchevents(region: @config['region'], credentials: @credentials).put_rule(params)
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          new_props = get_properties
          current = MU.structToHash(cloud_desc(use_cache: false))
          params = {}
          new_props.each_pair { |k, v|
            next if k == :tags # doesn't seem to do anything
            if v != current[k]
              params[k] = v
            end
          }

          if params.size > 0
            MU.log "Updating CloudWatch Event #{@cloud_id}", MU::NOTICE, details: params
            MU::Cloud::AWS.cloudwatchevents(region: @config['region'], credentials: @credentials).put_rule(params)
          end
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc ? cloud_desc.arn : nil
        end

        # Return the metadata for this job
        # @return [Hash]
        def notify
          MU.structToHash(cloud_desc, stringify_keys: true)
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::BETA
        end

        # Remove all jobs associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          found = find(region: region, credentials: credentials)

          found.each_pair { |id, desc|
            if (desc.description and desc.description == deploy_id) or
               (flags and flags['known'] and flags['known'].include?(id))
              MU.log "Deleting CloudWatch Event #{id}"
              if !noop
                # XXX purge all targets first
                MU::Cloud::AWS.cloudwatchevents(region: region, credentials: credentials).delete_rule(
                  name: id,
                  event_bus_name: desc.event_bus_name
                )
              end
            end
          }
        end

        # Locate an existing event.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching CloudWatch Event
        def self.find(**args)
          found = {}

          MU::Cloud::AWS.cloudwatchevents(region: args[:region], credentials: args[:credentials]).list_rules.rules.each { |r|
            next if args[:cloud_id] and ![r.name, r.arn].include?(args[:cloud_id])
            found[r.name] = r
          }

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**_args)
          bok = {
            "cloud" => "AWS",
            "credentials" => @config['credentials'],
            "cloud_id" => @cloud_id,
            "region" => @config['region']
          }

          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end
          bok['name'] = cloud_desc.name
          if cloud_desc.description and !cloud_desc.description.empty?
            bok['description'] = cloud_desc.description
          end

          bok['disabled'] = true if cloud_desc.state == "DISABLED"

#          schedule_expression="cron(15 6 * * ? *)"
          if cloud_desc.schedule_expression
            if cloud_desc.schedule_expression.match(/cron\((\S+) (\S+) (\S+) (\S+) (\S+) (\S+)\)/)
              bok['schedule'] = {
                "minute" => Regexp.last_match[1],
                "hour" => Regexp.last_match[2],
                "day_of_month" => Regexp.last_match[3],
                "month" => Regexp.last_match[4],
                "day_of_week" => Regexp.last_match[5],
                "year" => Regexp.last_match[6]
              }
            else
              MU.log "HALP", MU::ERR, details: cloud_desc.schedule_expression
            end
          end

          if cloud_desc.role_arn
            shortname = cloud_desc.role_arn.sub(/.*?role\/([^\/]+)$/, '\1')
            bok['role'] = MU::Config::Ref.get(
              id: shortname,
              cloud: "AWS",
              type: "roles"
            )
          end

# XXX cloud_desc.event_pattern - what do we want to do with this?

          bok
        end


        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "disabled" => {
              "type" => "boolean",
              "description" => "Leave this job in place but disabled",
              "default" => false
            },
            "role" => MU::Config::Ref.schema(type: "roles", desc: "A sibling {MU::Config::BasketofKittens::roles} entry or the id of an existing IAM role to assign to this CloudWatch Event.", omit_fields: ["region", "tag"]),
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::jobs}, bare and unvalidated.
        # @param job [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(job, _configurator)
          ok = true

          ok
        end

        private

        def get_properties
          params = {
            name: @cloud_id,
            state: @config['disabled'] ? "DISABLED" : "ENABLED",
            event_bus_name: "default" # XXX expose, or create a deploy-specific one?
          }

          params[:description] = if @config['description'] and @config['scrub_mu_isms']
            @config['description']
          else
            @deploy.deploy_id
          end

          if @tags
            params[:tags] = @tags.each_key.map { |k| { :key => k, :value => @tags[k] } }
          end

          if @config['role']
            role_obj = MU::Config::Ref.get(@config['role']).kitten(@deploy, cloud: "AWS")
            raise MuError.new "Failed to fetch object from role reference", details: @config['role'].to_h if !role_obj
            params[:role_arn] = role_obj.arn
          end

          if @config['schedule']
            params[:schedule_expression] = "cron(" + ["minute", "hour", "day_of_month", "month", "day_of_week", "year"].map { |i| @config['schedule'][i] }.join(" ") +")"
          end

          params
        end

      end
    end
  end
end
