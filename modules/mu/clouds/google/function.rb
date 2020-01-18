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
    class Google
      # Creates an Google project as configured in {MU::Config::BasketofKittens::functions}
      class Function < MU::Cloud::Function

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config['name'])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          labels = Hash[@tags.keys.map { |k|
            [k.downcase, @tags[k].downcase.gsub(/[^-_a-z0-9]/, '-')] }
          ]
          labels["name"] = MU::Cloud::Google.nameStr(@mu_name)

          location = "projects/"+@config['project']+"/locations/"+@config['region']
          sa = nil
          retries = 0
          begin
            sa = MU::Config::Ref.get(@config['service_account'])
            if !sa or !sa.kitten or !sa.kitten.cloud_desc
              sleep 10
            end
          end while !sa or !sa.kitten or !sa.kitten.cloud_desc and retries < 5

          if !sa or !sa.kitten or !sa.kitten.cloud_desc
            raise MuError, "Failed to get service account cloud id from #{@config['service_account'].to_s}"
          end

          desc = {
            name: location+"/functions/"+@mu_name.downcase,
            runtime: @config['runtime'],
#            timeout: @config['timeout'].to_s+"s",
#            entry_point: @config['handler'],
#            description: @deploy.deploy_id,
#            service_account_email: sa.kitten.cloud_desc.email,
#            labels: labels,
#            available_memory_mb: @config['memory']
          }

          if @config['environment_variable']
            @config['environment_variable'].each { |var|
              desc[:environment_variables] ||= {}
              desc[:environment_variables][var["key"].to_s] = var["value"].to_s
            }
          end

          if @config['code']['gs_url']
            desc[:source_archive_url] = @config['code']['gs_url']
          else
            upload_obj = MU::Cloud::Google.function(credentials: @credentials).generate_function_upload_url(location, MU::Cloud::Google.function(:GenerateUploadUrlRequest).new)

            MU.log "Uploading #{@config['code']['zip_file']} to #{upload_obj.upload_url}"
            uri = URI(upload_obj.upload_url)
            req = Net::HTTP::Put.new(uri)
#            req.body = File.read(@config['code']['zip_file'], mode: "rb")
            req.set_content_type("application/zip")
            req["x-goog-content-length-range"] = "0,104857600"
            pp uri
            pp req
            http = Net::HTTP.new(uri.hostname, uri.port)
            http.set_debug_output($stdout)
            begin
              resp = http.request(req, File.read(@config['code']['zip_file'], mode: "rb"))
            rescue EOFError => e
              MU.log e.message, MU::ERR
            end
            desc[:source_upload_url] = upload_obj.upload_url
          end

          func_obj = MU::Cloud::Google.function(:CloudFunction).new(desc)


          MU.log "Creating Cloud Function #{@mu_name} in #{location}", MU::NOTICE, details: func_obj
          MU::Cloud::Google.function(credentials: @credentials).create_project_location_function(location, func_obj)

          raise MuError, "we out"
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
        end

        # Return the metadata for this project's configuration
        # @return [Hash]
        def notify
        {}
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
          MU::Cloud::ALPHA
        end

        # Remove all Google projects associated with the currently loaded deployment. Try to, anyway.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
        end

        # Locate an existing project
        # @return [Hash<OpenStruct>]: The cloud provider's complete descriptions of matching project
        def self.find(**args)
          args[:project] ||= args[:habitat]

          found = {}

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(rootparent: nil, billing: nil, habitats: nil)
          bok = {
            "cloud" => "Google",
            "credentials" => @config['credentials']
          }

          bok
        end


        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = ["runtime"]
          schema = {
            "service_account" => MU::Cloud::Google::Server.schema(config)[1]["service_account"],
            "runtime" => {
              "type" => "string",
              "enum" => %w{nodejs go python nodejs8 nodejs10 python37 go111 go113},
            },
            "code" => {
              "type" => "object",  
              "properties" => {  
                "gs_url" => {
                  "type" => "string",
                  "description" => "A Google Cloud Storage URL, starting with gs://, pointing to the zip archive which contains the function."
                }
              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::function}, bare and unvalidated.
        # @param function [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(function, configurator)
          ok = true
          function['project'] ||= MU::Cloud::Google.defaultProject(function['credentials'])
          function['region'] ||= MU::Cloud::Google.myRegion(function['credentials'])

          if !function['code'] or (!function['code']['zip_file'] and !function['code']['gs_url'])
            MU.log "Must specify a code source in Cloud Function #{function['name']}", MU::ERR
            ok = false
          end

          if function['runtime'] == "python"
            function['runtime'] = "python37"
          elsif function['runtime'] == "go"
            function['runtime'] = "go113"
          elsif function['runtime'] == "nodejs"
            function['runtime'] = "nodejs8"
          end

          if function['service_account']
            function['service_account']['cloud'] = "Google"
            function['service_account']['habitat'] ||= function['project']
            found = MU::Config::Ref.get(function['service_account'])
            if found.id and !found.kitten
              MU.log "Cloud Function #{function['name']} failed to locate service account #{function['service_account']} in project #{function['project']}", MU::ERR
              ok = false
            end
          else
            user = {
              "name" => function['name'],
              "cloud" => "Google",
              "project" => function["project"],
              "credentials" => function["credentials"],
              "type" => "service"
            }
            if user["name"].length < 6
              user["name"] += Password.pronounceable(6)
            end
            if function['roles']
              user['roles'] = function['roles'].dup
            end
            configurator.insertKitten(user, "users", true)
            function['dependencies'] ||= []
            function['service_account'] = MU::Config::Ref.get(
              type: "users",
              cloud: "Google",
              name: user["name"],
              project: user["project"],
              credentials: user["credentials"]
            )
            function['dependencies'] << {
              "type" => "user",
              "name" => user["name"]
            }
          end

#          siblings = configurator.haveLitterMate?(nil, "vpcs", has_multiple: true)
#          if siblings.size == 1
#            MU.log "ContainerCluster #{function['name']} did not declare a VPC. Inserting into sibling VPC #{siblings[0]['name']}.", MU::WARN
#            function["vpc"] = {
#              "name" => siblings[0]['name'],
#              "subnet_pref" => "all_private"
#            }
#          elsif MU::Cloud::Google.hosted? and MU::Cloud::Google.myVPCObj
#            cluster["vpc"] = {
#              "id" => MU.myVPC,
#              "subnet_pref" => "all_private"
#            }
#          else
#            MU.log "Cloud Function #{function['name']} must declare a VPC", MU::ERR
#            ok = false
#          end

          ok
        end

      end
    end
  end
end
