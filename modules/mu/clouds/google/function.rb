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

        HELLO_WORLDS = {
          "nodejs" => {
            "index.json" => %Q{
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

        require 'zip'
        require 'tmpdir'

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
            timeout: @config['timeout'].to_s+"s",
            entry_point: "hello_world",
            description: @deploy.deploy_id,
            service_account_email: sa.kitten.cloud_desc.email,
            labels: labels,
            available_memory_mb: @config['memory']
          }

desc[:https_trigger] = MU::Cloud::Google.function(:HttpsTrigger).new
#desc[:event_trigger] = MU::Cloud::Google.function(:EventTrigger).new(
#  event_type:
#)

          if @config['environment_variable']
            @config['environment_variable'].each { |var|
              desc[:environment_variables] ||= {}
              desc[:environment_variables][var["key"].to_s] = var["value"].to_s
            }
          end

          hello_code = nil
          HELLO_WORLDS.each_pair { |runtime, code|
            if @config['runtime'].match(/^#{Regexp.quote(runtime)}/)
              hello_code = code
              break
            end
          }

          Dir.mktmpdir(@mu_name) { |dir|
            hello_code.each_pair { |file, contents|
              f = File.open(dir+"/"+file, "w")
              f.puts contents
              f.close
              Zip::File.open(dir+"/function.zip", Zip::File::CREATE) { |z|
                z.add(file, dir+"/"+file)
              }
            }
            desc[:source_archive_url] = MU::Cloud::Google::Function.uploadPackage(dir+"/function.zip", @mu_name+"-cloudfunction.zip", credentials: nil)
          }

          func_obj = MU::Cloud::Google.function(:CloudFunction).new(desc)

          MU.log "Creating Cloud Function #{@mu_name} in #{location}", details: func_obj
          resp = MU::Cloud::Google.function(credentials: @credentials).create_project_location_function(location, func_obj)
          @cloud_id = resp.name
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
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
          MU::Cloud::ALPHA
        end

        # Remove all Google projects associated with the currently loaded deployment. Try to, anyway.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)
          return if !MU::Cloud::Google::Habitat.isLive?(flags["project"], credentials)
          clusters = []

          # Make sure we catch regional *and* zone functions
          found = MU::Cloud::Google::Function.find(credentials: credentials, region: region, project: flags["project"])
          found.each_pair { |cloud_id, desc|
            if (desc.description and desc.description = MU.deploy_id) or
               (desc.labels and desc.labels["mu-id"] = MU.deploy_id.downcase) or
               flags["known"] and flags["known"].include?(cloud_id)
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
          args[:project] ||= args[:habitat]
          args[:project] ||= MU::Cloud::Google.defaultProject(args[:credentials])
          location = args[:region] || args[:availability_zone] || "-"

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
              MU::Cloud::Google.function(credentials: args[:credentials]).list_project_location_functions("projects/#{args[:project]}/locations/#{location}")
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
        def toKitten(rootparent: nil, billing: nil, habitats: nil)
          bok = {
            "cloud" => "Google",
            "credentials" => @config['credentials']
          }

          bok["name"] = @cloud_id.gsub(/.*\/([^\/]+)$/, '\1')
          bok["runtime"] = cloud_desc.runtime
          bok["memory"] = cloud_desc.available_memory_mb
          bok["handler"] = cloud_desc.entry_point
          bok["timeout"] = cloud_desc.timeout.gsub(/[^\d]/, '').to_i

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

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::function}, bare and unvalidated.
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

          HELLO_WORLDS.each_pair { |runtime, code|
            if function['runtime'].match(/^#{Regexp.quote(runtime)}/)
            end
          }

          if !function['code'] or (!function['code']['zip_file'] and !function['code']['gs_url'])
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
