# Copyright:: Copyright (c) 2021 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#	http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

module MU
  class Cloud
    class Azure
      # A Kubernetes cluster as configured in {MU::Config::BasketofKittens::databases}
      class Database < MU::Cloud::Database

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @config["groomer"] ||= MU::Config.defaultGroomer
          @groomclass = MU::Groomer.loadGroomer(@config["groomer"])


          # @mu_name = mu_name ? mu_name : @deploy.getResourceName(@config["name"])
          if !mu_name.nil?
            @mu_name = mu_name
            @cloud_id = Id.new(cloud_desc.id) if @cloud_id
          else
            @mu_name ||= @deploy.getResourceName(@config["name"], max_length: 31)
          end
        end


        # Called automatically by {MU::Deploy#createResources}
        # @return [String]: The cloud provider's identifier for this GKE instance.
        def create
          @config['master_user'] ||= (@config["name"]+@deploy.timestamp+MU.seed.downcase)[0..127].gsub!(/[^a-z0-9]/i, "")

          create_update
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          create_update

          if @config['init_databases']
            found = MU::Cloud::Azure.sql(credentials: @credentials).databases.list_by_server(@resource_group, @mu_name).map { |d| d.name }
            @config['init_databases'].each { |db|
              if !found.include?(db)
                db_obj = MU::Cloud::Azure.sql(:Database).new
                db_obj.location = @config['region']

                MU.log "Creating database #{db} in SQL instance #{@mu_name}"
                MU::Cloud::Azure.sql(credentials: @credentials).databases.create_or_update(@resource_group, @mu_name, db, db_obj)
              end
            }

          end
          MU.log "SQL Database #{@config['name']} is at #{cloud_desc.fully_qualified_domain_name}", MU::SUMMARY
        end

        # Locate and return cloud provider descriptors of this resource type
        # which match the provided parameters, or all visible resources if no
        # filters are specified. At minimum, implementations of +find+ must
        # honor +credentials+ and +cloud_id+ arguments. We may optionally
        # support other search methods, such as +tag_key+ and +tag_value+, or
        # cloud-specific arguments like +project+. See also {MU::MommaCat.findStray}.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching resources
        def self.find(**args)
          found = {}

          # Azure resources are namedspaced by resource group. If we weren't
          # told one, we may have to search all the ones we can see.
          resource_groups = if args[:resource_group]
            [args[:resource_group]]
          elsif args[:cloud_id] and args[:cloud_id].is_a?(MU::Cloud::Azure::Id)
            [args[:cloud_id].resource_group]
          else
            MU::Cloud::Azure.resources(credentials: args[:credentials]).resource_groups.list.map { |rg| rg.name }
          end

          if args[:cloud_id]
            id_str = args[:cloud_id].is_a?(MU::Cloud::Azure::Id) ? args[:cloud_id].name : args[:cloud_id]
            resource_groups.each { |rg|
              MU::Cloud::Azure.sql(credentials: args[:credentials]).servers.list_by_resource_group(args[:resource_group]).each { |db|
                id = Id.new(db.id)
                if [id, id.raw, id.name].include?(args[:cloud_id])
                  found[Id.new(db.id)] = db
                end
              }
           }
          else
            if args[:resource_group]
              MU::Cloud::Azure.sql(credentials: args[:credentials]).servers.list_by_resource_group(args[:resource_group]).each { |db|
                found[Id.new(db.id)] = db
              }
            else
              MU::Cloud::Azure.sql(credentials: args[:credentials]).servers.list.each { |db|
                found[Id.new(db.id)] = db
              }
            end
          end

          found
        end

        # Register a description of this cluster instance with this deployment's metadata.
        def notify
          base = MU.structToHash(cloud_desc)
          @cloud_id = Id.new(cloud_desc.id) if !@cloud_id.is_a?(Id)
          base["cloud_id"] = @cloud_id.name
base["passwowrd"] = "N][?JaGE]uu!CE"
          base.merge!(@config.to_h)
          base
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

        # Stub method. Azure resources are cleaned up by removing the parent
        # resource group.
        # @return [void]
        def self.cleanup(**args)
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "init_databases" => {
              "type" => "array",
              "description" => "Ensure the existence of one or more databases in this SQL instance",
              "items" => {
                "type" => "string"
              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::databases}, bare and unvalidated.
        # @param db [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(db, configurator)
          ok = true

          db['master_user'] ||= "sqladmin"

          ok
        end

        private

        def create_update
          getPassword(complex: true) # generate or retrieve from secure storage as applicable

          server_obj = MU::Cloud::Azure.sql(:Server).new
          server_obj.location = @region
          server_obj.administrator_login = @config["master_user"]
          server_obj.administrator_login_password = @config["password"]
          server_obj.version = "12.0"

          resp = MU::Cloud::Azure.sql(credentials: @credentials).servers.create_or_update(@resource_group, @mu_name, server_obj)
          @cloud_id = Id.new(resp.id)
        end

      end #class
    end #class
  end
end #module
