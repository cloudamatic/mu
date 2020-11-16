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
      # Creates a Google Cloud Function as configured in {MU::Config::BasketofKittens::functions}
      class Function < MU::Cloud::Function

        require 'zip'
        require 'tmpdir'

        # Known-good code blobs to upload when initially creating functions
        HELLO_WORLDS = {
          "nodejs" => {
            "index.js" => %Q{
/**
 * Responds to any HTTP request.
 *
 * @param {!express:Request} req HTTP request context.
 * @param {!express:Response} res HTTP response context.
 */
exports.hello_world = (req, res) => {
  let message = req.query.message || req.body.message || 'Hello World!';
  res.status(200).send(message);
};
},
          "package.json" => %Q{
{
  "name": "sample-http",
  "version": "0.0.1"
}
}
          },
          "python" => {
            "main.py" => %Q{
def hello_world(request):
    """Responds to any HTTP request.
    Args:
        request (flask.Request): HTTP request object.
    Returns:
        The response text or any set of values that can be turned into a
        Response object using
        `make_response <http://flask.pocoo.org/docs/1.0/api/#flask.Flask.make_response>`.
    """
    request_json = request.get_json()
    if request.args and 'message' in request.args:
        return request.args.get('message')
    elif request_json and 'message' in request_json:
        return request_json['message']
    else:
        return f'Hello World!'
},
            "requirements.txt" => "# put your modules here\n"
          },
          "go" => {
            "function.go" => %Q{
// Package p contains an HTTP Cloud Function.
package p

import (
  "encoding/json"
  "fmt"
  "html"
  "net/http"
)

// HelloWorld prints the JSON encoded "message" field in the body
// of the request or "Hello, World!" if there isn't one.
func hello_world(w http.ResponseWriter, r *http.Request) {
  var d struct {
    Message string `json:"message"`
  }
  if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
    fmt.Fprint(w, "Hello World!")
    return
  }
  if d.Message == "" {
    fmt.Fprint(w, "Hello World!")
    return
  }
  fmt.Fprint(w, html.EscapeString(d.Message))
}
},
          "go.mod" => %Q{
module example.com/cloudfunction
}
          }
        }

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config['name'])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create

          location = "projects/"+@config['project']+"/locations/"+@config['region']
          func_obj = buildDesc
          MU.log "Creating Cloud Function #{@mu_name} in #{location}", details: func_obj
          resp = MU::Cloud::Google.function(credentials: @credentials).create_project_location_function(location, func_obj)
          @cloud_id = resp.name
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          desc = {}
          labels = Hash[@tags.keys.map { |k|
            [k.downcase, @tags[k].downcase.gsub(/[^-_a-z0-9]/, '-')] }
          ]
          labels["name"] = MU::Cloud::Google.nameStr(@mu_name)

          if cloud_desc.labels != labels
            need_update = true
          end

          if cloud_desc.runtime != @config['runtime']
            need_update = true
          end
          if cloud_desc.timeout != @config['timeout'].to_s+"s"
            need_update = true
          end
          if cloud_desc.entry_point != @config['handler']
            need_update = true
          end
          if cloud_desc.available_memory_mb != @config['memory']
            need_update = true
          end
          if @config['environment_variable']
            @config['environment_variable'].each { |var|
              if !cloud_desc.environment_variables or
                 cloud_desc.environment_variables[var["key"].to_s] != var["value"].to_s
                need_update = true
              end
            }
          end
          if @config['triggers']
            if !cloud_desc.event_trigger or
               cloud_desc.event_trigger.event_type != @config['triggers'].first['event'] or
               cloud_desc.event_trigger.resource != @config['triggers'].first['resource']
              need_update = true
            end
          end

          current = Dir.mktmpdir(@mu_name+"-current") { |dir|
            MU::Cloud::Google::Function.downloadPackage(@cloud_id, dir+"/current.zip", credentials: @credentials)
            File.read("#{dir}/current.zip")
          }

          tempfile = nil
          new = if @config['code']['zip_file'] or @config['code']['path']
            if @config['code']['path']
              tempfile = Tempfile.new(["function", ".zip"])
              MU.log "#{@mu_name} using code at #{@config['code']['path']}"
              MU::Master.zipDir(@config['code']['path'], tempfile.path)
              @config['code']['zip_file'] = tempfile.path
            else
              MU.log "#{@mu_name} using code packaged at #{@config['code']['zip_file']}"
            end
#            @code_sha256 = Base64.encode64(Digest::SHA256.digest(zip)).chomp
            File.read(@config['code']['zip_file'])
          elsif @config['code']['gs_url']
            @config['code']['gs_url'].match(/^gs:\/\/([^\/]+)\/(.*)/)
            bucket = Regexp.last_match[1]
            path = Regexp.last_match[2]
            Dir.mktmpdir(@mu_name+"-new") { |dir|
              MU::Cloud::Google.storage(credentials: @credentials).get_object(bucket, path, download_dest: dir+"/new.zip")
              File.read(dir+"/new.zip")
            }
          end

          if @config['code']['gs_url'] and
             (@config['code']['gs_url'] != cloud_desc.source_archive_url or
             current != new)
            need_update = true
          elsif (@config['code']['zip_file'] or @config['code']['path']) and current != new
            need_update = true
            desc[:source_archive_url] = MU::Cloud::Google::Function.uploadPackage(@config['code']['zip_file'], @mu_name+"-cloudfunction.zip", credentials: @credentials)
          end

          if need_update
            func_obj = buildDesc
            MU.log "Updating Cloud Function #{@cloud_id}", MU::NOTICE, details: func_obj
            begin
              MU::Cloud::Google.function(credentials: @credentials).patch_project_location_function(
                @cloud_id, 
                func_obj
              )
            rescue ::Google::Apis::ClientError
              MU.log "Error updating Cloud Function #{@mu_name}.", MU::ERR
              if desc[:source_archive_url]
                main_file = nil
                HELLO_WORLDS.each_pair { |runtime, code|
                  if @config['runtime'].match(/^#{Regexp.quote(runtime)}/)
                    main_file = code.keys.first
                    break
                  end
                }
                MU.log "Verify that the specified code is compatible with the #{@config['runtime']} runtime and has an entry point named #{@config['handler']} in #{main_file}", MU::ERR, details: @config['code']
              end
            end
          end

#            service_account_email: sa.kitten.cloud_desc.email,
#            labels: labels,

          if tempfile
            tempfile.close
            tempfile.unlink
          end

        end

        # Return the metadata for this project's configuration
        # @return [Hash]
        def notify
          MU.structToHash(cloud_desc)
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

        # Remove all Google projects associated with the currently loaded deployment. Try to, anyway.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          flags["habitat"] ||= MU::Cloud::Google.defaultProject(credentials)
          return if !MU::Cloud.resourceClass("Google", "Habitat").isLive?(flags["habitat"], credentials)
          # Make sure we catch regional *and* zone functions
          found = MU::Cloud::Google::Function.find(credentials: credentials, region: region, project: flags["habitat"])
          found.each_pair { |cloud_id, desc|
            if (desc.description and desc.description == MU.deploy_id) or
               (desc.labels and desc.labels["mu-id"] == MU.deploy_id.downcase and (ignoremaster or desc.labels["mu-master-ip"] == MU.mu_public_ip.gsub(/\./, "_"))) or
               (flags["known"] and flags["known"].include?(cloud_id))
              MU.log "Deleting Cloud Function #{desc.name}"
              if !noop
                MU::Cloud::Google.function(credentials: credentials).delete_project_location_function(cloud_id)
              end
            end
          }

        end

        # Locate an existing project
        # @return [Hash<OpenStruct>]: The cloud provider's complete descriptions of matching project
        def self.find(**args)
          args = MU::Cloud::Google.findLocationArgs(args)

          found = {}

          if args[:cloud_id]
            resp = begin
              MU::Cloud::Google.function(credentials: args[:credentials]).get_project_location_function(args[:cloud_id])
            rescue ::Google::Apis::ClientError => e
              raise e if !e.message.match(/forbidden:/)
            end
            found[args[:cloud_id]] = resp if resp
          else
            resp = begin
              MU::Cloud::Google.function(credentials: args[:credentials]).list_project_location_functions("projects/#{args[:project]}/locations/#{args[:location]}")
            rescue ::Google::Apis::ClientError => e
              raise e if !e.message.match(/forbidden:/)
            end

            if resp and resp.functions and !resp.functions.empty?
              resp.functions.each { |f|
                found[f.name.sub(/.*?\/projects\//, 'projects/')] = f
              }
            end
          end

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**_args)
          bok = {
            "cloud" => "Google",
            "cloud_id" => @cloud_id,
            "credentials" => @credentials,
            "project" => @project
          }

          @cloud_id.match(/^projects\/([^\/]+)\/locations\/([^\/]+)\/functions\/(.*)/)
          bok["project"] ||= Regexp.last_match[1]
          bok["region"] = Regexp.last_match[2]
          bok["name"] = Regexp.last_match[3]
          bok["runtime"] = cloud_desc.runtime
          bok["memory"] = cloud_desc.available_memory_mb
          bok["handler"] = cloud_desc.entry_point
          bok["timeout"] = cloud_desc.timeout.gsub(/[^\d]/, '').to_i

          if cloud_desc.vpc_connector
            bok["vpc_connector"] = cloud_desc.vpc_connector
          elsif cloud_desc.network
            cloud_desc.network.match(/^projects\/(.*?)\/.*?\/networks\/([^\/]+)(?:$|\/)/)
            vpc_proj = Regexp.last_match[1]
            vpc_id = Regexp.last_match[2]
  
            bok['vpc'] = MU::Config::Ref.get(
              id: vpc_id,
              cloud: "Google",
              habitat: MU::Config::Ref.get(
                id: vpc_proj,
                cloud: "Google",
                credentials: @credentials,
                type: "habitats"
              ),
              credentials: @credentials,
              type: "vpcs"
            )
          end

          if cloud_desc.environment_variables and cloud_desc.environment_variables.size > 0
            bok['environment_variable'] = cloud_desc.environment_variables.keys.map { |k| { "key" => k, "value" => cloud_desc.environment_variables[k] } }
          end
          if cloud_desc.labels and cloud_desc.labels.size > 0
            bok['tags'] = cloud_desc.labels.keys.map { |k| { "key" => k, "value" => cloud_desc.labels[k] } }
          end

          if cloud_desc.event_trigger
            bok['triggers'] = [
              {
                "event" => cloud_desc.event_trigger.event_type,
                "resource" => cloud_desc.event_trigger.resource
              }
            ]
          end

          codefile = bok["project"]+"_"+bok["region"]+"_"+bok["name"]+".zip"
          return nil if !MU::Cloud::Google::Function.downloadPackage(@cloud_id, codefile, credentials: @config['credentials'])
          bok['code'] = {
            'zip_file' => codefile
          }

          bok
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = ["runtime"]
          schema = {
            "roles" => MU::Cloud.resourceClass("Google", "User").schema(config)[1]["roles"],
            "triggers" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "description" => "Trigger for Cloud Function",
                "required" => ["event", "resource"],
                "additionalProperties" => false,
                "properties" => {
                  "event" => {
                    "type" => "string",
                    "description" => "The type of event to observe, such as +providers/cloud.storage/eventTypes/object.change+ or +providers/cloud.pubsub/eventTypes/topic.publish+. Event types match pattern +providers//eventTypes/.*+"
                  },
                  "resource" => {
                    "type" => "string",
                    "description" => "The resource(s) from which to observe events, for example, +projects/_/buckets/myBucket+. Not all syntactically correct values are accepted by all services."
                  }
                }
              }
            },
            "service_account" => MU::Cloud.resourceClass("Google", "Server").schema(config)[1]["service_account"],
            "runtime" => {
              "type" => "string",
              "enum" => %w{nodejs go python nodejs8 nodejs10 python37 go111 go113},
            },
            "vpc_connector" => {
              "type" => "string",
              "description" => "+DEPRECATED+ VPC Connector to attach, of the form +projects/my-project/locations/some-region/connectors/my-connector+. This option will be removed once proper google-cloud-sdk support for VPC Connectors becomes available, at which point we will piggyback on the normal +vpc+ stanza and resolve connectors as needed."
            },
            "vpc_connector_allow_all_egress" => {
              "type" => "boolean",
              "default" => false,
              "description" => "+DEPRECATED+ Allow VPC connector egress traffic to any IP range, instead of just private IPs. This option will be removed once proper google-cloud-sdk support for VPC Connectors becomes available, at which point we will piggyback on the normal +vpc+ stanza and resolve connectors as needed."
            },
            "code" => {
              "type" => "object",  
              "description" => "Zipped deployment package to upload to our function.", 
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

        # Upload a zipfile to our admin Cloud Storage bucket, for use by
        # Cloud Functions
        # @param function_id [String]: The cloud_id of the Function, in the format ++
        # @param zipfile [String]: Target filename
        # @param credentials [String]
        def self.downloadPackage(function_id, zipfile, credentials: nil)
          cloud_desc = MU::Cloud::Google::Function.find(cloud_id: function_id, credentials: credentials).values.first
          if !cloud_desc
            raise MuError, "Couldn't find Cloud Function #{function_id}"
          end
          
          if cloud_desc.source_archive_url
            cloud_desc.source_archive_url.match(/^gs:\/\/([^\/]+)\/(.*)/)
            bucket = Regexp.last_match[1]
            path = Regexp.last_match[2]

            begin
              MU::Cloud::Google.storage(credentials: credentials).get_object(bucket, path, download_dest: zipfile)
            rescue ::Google::Apis::ClientError => e
              MU.log "Couldn't retrieve gs://#{bucket}/#{path} for #{function_id}", MU::WARN, details: e.inspect
              return false
            end
          elsif cloud_desc.source_upload_url
            resp = MU::Cloud::Google.function(credentials: credentials).generate_function_download_url(
              function_id
            )
            if resp and resp.download_url
              f = File.open(zipfile, "wb")
              f.write Net::HTTP.get(URI(resp.download_url))
              f.close
            end
          end
          true
        end

        # Upload a zipfile to our admin Cloud Storage bucket, for use by
        # Cloud Functions
        # @param zipfile [String]: Source file
        # @param filename [String]: Target filename
        # @param credentials [String]
        # @return [String]: The Cloud Storage URL to the result
        def self.uploadPackage(zipfile, filename, credentials: nil)
          bucket = MU::Cloud::Google.adminBucketName(credentials)
          obj_obj = MU::Cloud::Google.storage(:Object).new(
            content_type: "application/zip",
            name: filename
          )

          MU::Cloud::Google.storage(credentials: credentials).insert_object(
            bucket,
            obj_obj,
            upload_source: zipfile
          )
          return "gs://#{bucket}/#{filename}"
# XXX this is the canonical, correct way to do this, but it doesn't work.
# "Anonymous caller does not have storage.objects.create access to gcf-upload-us-east4-9068f7a1-7c08-4daa-8b83-d26e098e9c44/bcddc43c-f74d-46c0-bfdd-c215829a23f2.zip."
#
#          upload_obj = MU::Cloud::Google.function(credentials: credentials).generate_function_upload_url(location, MU::Cloud::Google.function(:GenerateUploadUrlRequest).new)
#          MU.log "Uploading #{zipfile} to #{upload_obj.upload_url}"
#          uri = URI(upload_obj.upload_url)
#          req = Net::HTTP::Put.new(uri.path, { "Content-Type" => "application/zip", "x-goog-content-length-range" => "0,104857600"})
#req["Content-Length"] = nil
#          req.body = File.read(zipfile, mode: "rb")
#          pp req
#          http = Net::HTTP.new(uri.hostname, uri.port)
#          http.set_debug_output($stdout)
#          resp = http.request(req)
#          upload_obj.upload_url
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::functions}, bare and unvalidated.
        # @param function [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(function, configurator)
          ok = true
          function['project'] ||= MU::Cloud::Google.defaultProject(function['credentials'])
          function['region'] ||= MU::Cloud::Google.myRegion(function['credentials'])
          if function['runtime'] == "python"
            function['runtime'] = "python37"
          elsif function['runtime'] == "go"
            function['runtime'] = "go113"
          elsif function['runtime'] == "nodejs"
            function['runtime'] = "nodejs8"
          end
# XXX list_project_locations

          if !function['code'] or (!function['code']['zip_file'] and !function['code']['gs_url'] and !function['code']['path'])
            MU.log "Must specify a code source in Cloud Function #{function['name']}", MU::ERR
            ok = false
          elsif function['code']['zip_file']
            z = Zip::File.open(function['code']['zip_file'])
            if function['runtime'].match(/^python/)
              begin
                z.get_entry("main.py")
              rescue Errno::ENOENT
                MU.log function['code']['zip_file']+" does not contain main.py, required for runtime #{function['runtime']}", MU::ERR
                ok = false
              end
            elsif function['runtime'].match(/^nodejs/)
              begin
                z.get_entry("index.js")
              rescue Errno::ENOENT
                begin
                  z.get_entry("function.js")
                rescue
                  MU.log function['code']['zip_file']+" does not contain function.js or index.js, at least one must be present for runtime #{function['runtime']}", MU::ERR
                  ok = false
                end
              end
            end
          end

          if function['service_account']
            if !function['service_account'].is_a?(MU::Config::Ref)
              function['service_account']['cloud'] = "Google"
              function['service_account']['habitat'] ||= function['project']
            end
            found = MU::Config::Ref.get(function['service_account'])
            if found.id and !found.kitten
              MU.log "Cloud Function #{function['name']} failed to locate service account #{function['service_account']} in project #{function['project']}", MU::ERR
              ok = false
            end
          else
            function = MU::Cloud.resourceClass("Google", "User").genericServiceAccount(function, configurator)
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

        private

        def buildDesc
          labels = Hash[@tags.keys.map { |k|
            [k.downcase, @tags[k].downcase.gsub(/[^-_a-z0-9]/, '-')] }
          ]
          labels["name"] = MU::Cloud::Google.nameStr(@mu_name)

          location = "projects/"+@config['project']+"/locations/"+@config['region']
          sa = nil
          retries = 0
          begin
            sa_ref = MU::Config::Ref.get(@config['service_account'])
            sa = @deploy.findLitterMate(name: sa_ref.name, type: "users")
            if !sa or !sa.cloud_desc
              sleep 10
            end
          rescue ::Google::Apis::ClientError => e
            if e.message.match(/notFound:/)
              sleep 10
              retries += 1
              retry
            end
          end while !sa or !sa.cloud_desc and retries < 5

          if !sa or !sa.cloud_desc
            raise MuError, "Failed to get service account cloud id from #{@config['service_account'].to_s}"
          end

          desc = {
            name: location+"/functions/"+@mu_name.downcase,
            runtime: @config['runtime'],
            timeout: @config['timeout'].to_s+"s",
#            entry_point: "hello_world",
            entry_point: @config['handler'],
            description: @deploy.deploy_id,
            service_account_email: sa.cloud_desc.email,
            labels: labels,
            available_memory_mb: @config['memory']
          }

          # XXX This network argument is deprecated in favor of using VPC
          # Connectors. Which would be fine, except there's no API support for
          # interacting with VPC Connectors. Can't create them, can't list them,
          # can't do anything except pass their ids into Cloud Functions or 
          # AppEngine and hope for the best.
          if @config['vpc_connector']
            desc[:vpc_connector] = @config['vpc_connector']
            desc[:vpc_connector_egress_settings] = @config['vpc_connector_allow_all_egress'] ? "ALL_TRAFFIC" : "PRIVATE_RANGES_ONLY"
            pp desc
          elsif @vpc
            desc[:network] = @vpc.url.sub(/^.*?\/projects\//, 'projects/')
          end

          if @config['triggers']
            desc[:event_trigger] = MU::Cloud::Google.function(:EventTrigger).new(
              event_type: @config['triggers'].first['event'],
              resource: @config['triggers'].first['resource']
            )
          else
            desc[:https_trigger] = MU::Cloud::Google.function(:HttpsTrigger).new
          end


          if @config['environment_variable']
            @config['environment_variable'].each { |var|
              desc[:environment_variables] ||= {}
              desc[:environment_variables][var["key"].to_s] = var["value"].to_s
            }
          end

#          hello_code = nil
#          HELLO_WORLDS.each_pair { |runtime, code|
#            if @config['runtime'].match(/^#{Regexp.quote(runtime)}/)
#              hello_code = code
#              break
#            end
#          }
          if @config['code']['gs_url']
            desc[:source_archive_url] = @config['code']['gs_url']
          elsif @config['code']['zip_file'] or @config['code']['path']
            tempfile = nil
            if @config['code']['path']
              tempfile = Tempfile.new(["function", ".zip"])
              MU.log "#{@mu_name} using code at #{@config['code']['path']}"
              MU::Master.zipDir(@config['code']['path'], tempfile.path)
              @config['code']['zip_file'] = tempfile.path
            else
              MU.log "#{@mu_name} using code packaged at #{@config['code']['zip_file']}"
            end
            desc[:source_archive_url] = MU::Cloud::Google::Function.uploadPackage(@config['code']['zip_file'], @mu_name+"-cloudfunction.zip", credentials: @credentials)

            if tempfile
              tempfile.close
              tempfile.unlink
            end
          end

#          Dir.mktmpdir(@mu_name) { |dir|
#            hello_code.each_pair { |file, contents|
#              f = File.open(dir+"/"+file, "w")
#              f.puts contents
#              f.close
#              Zip::File.open(dir+"/function.zip", Zip::File::CREATE) { |z|
#                z.add(file, dir+"/"+file)
#              }
#            }
#            desc[:source_archive_url] = MU::Cloud::Google::Function.uploadPackage(dir+"/function.zip", @mu_name+"-cloudfunction.zip", credentials: @credentials)
#          }
          MU::Cloud::Google.function(:CloudFunction).new(desc)
        end

      end
    end
  end
end
