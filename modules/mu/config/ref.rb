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

  # Methods and structures for parsing Mu's configuration files. See also {MU::Config::BasketofKittens}.
  class Config

    # A wrapper class for resources to refer to other resources, whether they
    # be a sibling object in the current deploy, an object in another deploy,
    # or a plain cloud id from outside of Mu.
    class Ref
      attr_reader :name 
      attr_reader :type 
      attr_reader :cloud 
      attr_reader :deploy_id 
      attr_reader :region 
      attr_reader :credentials 
      attr_reader :habitat
      attr_reader :mommacat
      attr_reader :tag_key 
      attr_reader :tag_value
      attr_reader :obj 

      @@refs = []
      @@ref_semaphore = Mutex.new

      # Little bit of a factory pattern... given a hash of options for a {MU::Config::Ref} objects, first see if we have an existing one that matches our more immutable attributes (+cloud+, +id+, etc). If we do, return that. If we do not, create one, add that to our inventory, and return that instead.
      # @param cfg [Hash]: 
      # @return [MU::Config::Ref]
      def self.get(cfg)
        return cfg if cfg.is_a?(MU::Config::Ref)
        checkfields = cfg.keys.map { |k| k.to_sym }
        required = [:id, :type]

        @@ref_semaphore.synchronize {
          @@refs.each { |ref|
            saw_mismatch = false
            saw_match = false
            needed_values = []
            checkfields.each { |field|
              next if !cfg[field]
              ext_value = ref.instance_variable_get("@#{field.to_s}".to_sym)
              if !ext_value
                needed_values << field
                next
              end
              if cfg[field] != ext_value
                saw_mismatch = true
              elsif required.include?(field) and cfg[field] == ext_value
                saw_match = true
              end
            }
            if saw_match and !saw_mismatch
              # populate empty fields we got from this request
              if needed_values.size > 0
                newref = ref.dup
                needed_values.each { |field|
                  newref.instance_variable_set("@#{field.to_s}".to_sym, cfg[field])
                  if !newref.respond_to?(field)
                    newref.singleton_class.instance_eval { attr_reader field.to_sym }
                  end
                }
                @@refs << newref
                return newref
              else
                return ref
              end
            end
          }

        }

        # if we get here, there was no match
        newref = MU::Config::Ref.new(cfg)
        @@ref_semaphore.synchronize {
          @@refs << newref
          return newref
        }
      end

      # A way of dynamically defining +attr_reader+ without leaking memory
      def self.define_reader(name)
        define_method(name) {
          instance_variable_get("@#{name.to_s}")
        }
      end

      # @param cfg [Hash]: A Basket of Kittens configuration hash containing
      # lookup information for a cloud object
      def initialize(cfg)
        cfg.keys.each { |field|
          next if field == "tag"
          if !cfg[field].nil?
            self.instance_variable_set("@#{field}".to_sym, cfg[field])
          elsif !cfg[field.to_sym].nil?
            self.instance_variable_set("@#{field.to_s}".to_sym, cfg[field.to_sym])
          end
          MU::Config::Ref.define_reader(field)
        }
        if cfg['tag'] and cfg['tag']['key'] and
           !cfg['tag']['key'].empty? and cfg['tag']['value']
          @tag_key = cfg['tag']['key']
          @tag_value = cfg['tag']['value']
        end

        if @deploy_id and !@mommacat
          @mommacat = MU::MommaCat.getLitter(@deploy_id, set_context_to_me: false)
        elsif @mommacat and !@deploy_id
          @deploy_id = @mommacat.deploy_id
        end

        # canonicalize the 'type' argument
        _shortclass, _cfg_name, cfg_plural, _classname, _attrs = MU::Cloud.getResourceNames(@type, false)
        @type = cfg_plural if cfg_plural

        kitten(shallow: true) if @mommacat # try to populate the actual cloud object for this
      end

      # Comparison operator
      def <=>(other)
        return 1 if other.nil?
        self.to_s <=> other.to_s
      end

      # Lets callers access us like a {Hash}
      # @param attribute [String,Symbol]
      def [](attribute)
        if respond_to?(attribute.to_sym)
          send(attribute.to_sym)
        else
          nil
        end
      end

      # Lets callers set attributes like a {Hash}
      # @param attribute [String,Symbol]
      def []=(attribute, value)
        instance_variable_set("@#{attribute.to_s}".to_sym, value)
        self.class.define_reader(attribute)
      end

      # Unset an attribute. Sort of. We can't actually do that, so nil it out
      # and we get the behavior we want.
      def delete(attribute)
        attribute = ("@"+attribute).to_sym if attribute.to_s !~ /^@/
        instance_variable_set(attribute.to_sym, nil)
      end

      # Base configuration schema for declared kittens referencing other cloud objects. This is essentially a set of filters that we're going to pass to {MU::MommaCat.findStray}.
      # @param aliases [Array<Hash>]: Key => value mappings to set backwards-compatibility aliases for attributes, such as the ubiquitous +vpc_id+ (+vpc_id+ => +id+).
      # @return [Hash]
      def self.schema(aliases = [], type: nil, parent_obj: nil, desc: nil, omit_fields: [], any_type: false)
        parent_obj ||= caller[1].gsub(/.*?\/([^\.\/]+)\.rb:.*/, '\1')
        desc ||= "Reference a #{type ? "'#{type}' resource" : "resource" } from this #{parent_obj ? "'#{parent_obj}'" : "" } resource"
        schema = {
          "type" => "object",
          "#MU_REFERENCE" => true,
          "minProperties" => 1,
          "description" => desc,
          "properties" => {
            "id" => {
              "type" => "string",
              "description" => "Cloud identifier of a resource we want to reference, typically used when leveraging resources not managed by MU"
            },
            "name" => {
              "type" => "string",
              "description" => "The short (internal Mu) name of a resource we're attempting to reference. Typically used when referring to a sibling resource elsewhere in the same deploy, or in another known Mu deploy in conjunction with +deploy_id+."
            },
            "type" => {
              "type" => "string",
              "description" => "The resource type we're attempting to reference.",
              "enum" => MU::Cloud.resource_types.values.map { |t| t[:cfg_plural] }
            },
            "deploy_id" => {
              "type" => "string",
              "description" => "Our target resource should be found in this Mu deploy."
            },
            "credentials" => MU::Config.credentials_primitive,
            "region" => MU::Config.region_primitive,
            "cloud" => MU::Config.cloud_primitive,
            "tag" => {
              "type" => "object",
              "description" => "If the target resource supports tagging and our resource implementations +find+ method supports it, we can attempt to locate it by tag.",
              "properties" => {
                "key" => {
                  "type" => "string",
                  "description" => "The tag or label key to search against"
                },
                "value" => {
                  "type" => "string",
                  "description" => "The tag or label value to match"
                }
              }
            }
          }
        }
        if !["folders", "habitats"].include?(type)
          schema["properties"]["habitat"] = MU::Config::Habitat.reference
        end

        if omit_fields
          omit_fields.each { |f|
            schema["properties"].delete(f)
          }
        end

        if any_type
          schema["properties"]["type"].delete("enum")
        elsif !type.nil?
          schema["required"] = ["type"]
          schema["properties"]["type"]["default"] = type
          schema["properties"]["type"]["enum"] = [type]
        end

        aliases.each { |a|
          a.each_pair { |k, v|
            if schema["properties"][v]
              schema["properties"][k] = schema["properties"][v].dup
              schema["properties"][k]["description"] = "Alias for <tt>#{v}</tt>"
            else
              MU.log "Reference schema alias #{k} wants to alias #{v}, but no such attribute exists", MU::WARN, details: caller[4]
            end
          }
        }

        schema
      end

      # Is our +@type+ attribute a Mu-supported type, or some rando string?
      # @return [Boolean]
      def is_mu_type?
        _shortclass, _cfg_name, type, _classname, _attrs = MU::Cloud.getResourceNames(@type, false)
        !type.nil?
      end

      # Decompose into a plain-jane {MU::Config::BasketOfKittens} hash fragment,
      # of the sort that would have been used to declare this reference in the
      # first place.
      def to_h
        me = { }

        self.instance_variables.each { |var|
          next if [:@obj, :@mommacat, :@tag_key, :@tag_value].include?(var)
          val = self.instance_variable_get(var)
          next if val.nil?
          val = val.to_h if val.is_a?(MU::Config::Ref)
          me[var.to_s.sub(/^@/, '')] = val
        }
        if @tag_key and !@tag_key.empty?
          me['tag'] = {
            'key' => @tag_key,
            'value' => @tag_value
          }
        end
        me
      end

      # Getter for the #{id} instance variable that attempts to populate it if
      # it's not set.
      # @return [String,nil]
      def id
        return @id if @id
        kitten # if it's not defined, attempt to define it
        @id
      end

      # Alias for {id}
      # @return [String,nil]
      def cloud_id
        id
      end

      # Return a {MU::Cloud} object for this reference. This is only meant to be
      # called in a live deploy, which is to say that if called during initial
      # configuration parsing, results may be incorrect.
      # @param mommacat [MU::MommaCat]: A deploy object which will be searched for the referenced resource if provided, before restoring to broader, less efficient searches.
      def kitten(mommacat = @mommacat, shallow: false, debug: false, cloud: nil)
        cloud ||= @cloud
        return nil if !cloud or !@type

        _shortclass, _cfg_name, cfg_plural, _classname, _attrs = MU::Cloud.getResourceNames(@type, false)
        if cfg_plural
          @type = cfg_plural # make sure this is the thing we expect
        else
          return nil # we don't do non-muish resources
        end

        loglevel = debug ? MU::NOTICE : MU::DEBUG

        if debug
          MU.log "this mf kitten", MU::WARN, details: caller
        end

        if @obj
          @deploy_id ||= @obj.deploy_id
          @id ||= @obj.cloud_id
          @name ||= @obj.config['name'] if @obj.config
          return @obj
        end

        if mommacat and caller.grep(/`findLitterMate'/).empty? # XXX the dumbest
          MU.log "Looking for #{@type} #{@name} #{@id} in deploy #{mommacat.deploy_id}", loglevel
          begin
            @obj = mommacat.findLitterMate(type: @type, name: @name, cloud_id: @id, credentials: @credentials, debug: debug)
          rescue StandardError => e
            if e.message =~ /deadlock/
              MU.log "Saw a recursive deadlock trying to fetch kitten for Ref object in deploy #{mmommacat.deploy_id}", MU::ERR, details: to_h
            end
            raise e
          end
          if @obj # initialize missing attributes, if we can
            @id ||= @obj.cloud_id
            @mommacat ||= mommacat
            @obj.intoDeploy(@mommacat) # make real sure these are set
            @deploy_id ||= mommacat.deploy_id

            if !@name
              if @obj.config and @obj.config['name']
                @name = @obj.config['name']
              elsif @obj.mu_name
if @type == "folders"
MU.log "would assign name '#{@obj.mu_name}' in ref to this folder if I were feeling aggressive", MU::WARN, details: self.to_h
end
#                @name = @obj.mu_name
              end
            end
            return @obj
          else
#            MU.log "Failed to find a live '#{@type.to_s}' object named #{@name}#{@id ? " (#{@id})" : "" }#{ @habitat ? " in habitat #{@habitat}" : "" }", MU::WARN, details: self
          end
        end

        if !@obj and !(cloud == "Google" and @id and @type == "users" and MU::Cloud.resourceClass("Google", "User").cannedServiceAcctName?(@id)) and !shallow
          try_deploy_id = @deploy_id

          begin
            hab_arg = if @habitat.nil?
              [nil]
            elsif @habitat.is_a?(MU::Config::Ref)
              [@habitat.id]
            elsif @habitat.is_a?(Hash)
              [@habitat["id"]]
            else
              [@habitat.to_s]
            end

            MU.log "Ref#kitten calling findStray", loglevel, details: {
              cloud: cloud,
              type: @type,
              name: @name,
              cloud_id: @id,
              deploy_id: try_deploy_id,
              region: @region,
              habitats: hab_arg,
              credentials: @credentials,
              dummy_ok: (["habitats", "folders", "users", "groups", "vpcs"].include?(@type))
            }

            found = MU::MommaCat.findStray(
              cloud,
              @type,
              name: @name,
              cloud_id: @id,
              deploy_id: try_deploy_id,
              region: @region,
              habitats: hab_arg,
              credentials: @credentials,
              dummy_ok: (["habitats", "folders", "users", "groups", "vpcs"].include?(@type))
            )
            MU.log "Ref#kitten results from findStray", loglevel, details: found
            @obj ||= found.first if found
          rescue MU::MommaCat::MultipleMatches => e
            if try_deploy_id.nil? and MU.deploy_id
              MU.log "Attempting to narrow down #{cloud} #{@type} to #{MU.deploy_id}", MU::NOTICE
              try_deploy_id = MU.deploy_id
              retry
            else
              raise e
            end
          rescue ThreadError => e
            # Sometimes MommaCat calls us in a potential deadlock situation;
            # don't be the cause of a fatal error if so, we don't need this
            # object that badly.
            raise e if !e.message.match(/recursive locking/)
          end
        end

        if @obj
          @deploy_id ||= @obj.deploy_id
          @id ||= @obj.cloud_id
          @name ||= @obj.config['name']
        end

        @obj
      end

    end
  end
end
