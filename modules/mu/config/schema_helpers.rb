# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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

    # The default cloud provider for new resources. Must exist in MU.supportedClouds
    # return [String]
    def self.defaultCloud
      configured = {}
      MU::Cloud.supportedClouds.each { |cloud|
        if $MU_CFG[cloud.downcase] and !$MU_CFG[cloud.downcase].empty?
          configured[cloud] = $MU_CFG[cloud.downcase].size
          configured[cloud] += 0.5 if MU::Cloud.cloudClass(cloud).hosted? # tiebreaker
        end
      }
      if configured.size > 0
        return configured.keys.sort { |a, b|
          configured[b] <=> configured[a]
        }.first
      else
        MU::Cloud.supportedClouds.each { |cloud|
          return cloud if MU::Cloud.cloudClass(cloud).hosted?
        }
        return MU::Cloud.supportedClouds.first
      end
    end

    # The default grooming agent for new resources. Must exist in MU.supportedGroomers.
    def self.defaultGroomer
      MU.localOnly ? "Ansible" : "Chef"
    end

    # Accessor for our Basket of Kittens schema definition
    def self.schema
      @@schema
    end

    # Deep merge a configuration hash so we can meld different cloud providers'
    # schemas together, while preserving documentation differences
    def self.schemaMerge(orig, new, cloud)
      if new.is_a?(Hash)
        new.each_pair { |k, v|
          if cloud and k == "description" and v.is_a?(String) and !v.match(/\b#{Regexp.quote(cloud.upcase)}\b/) and !v.empty?
            new[k] = "+"+cloud.upcase+"+: "+v
          end
          if orig and orig.has_key?(k)
          elsif orig
            orig[k] = new[k]
          else
            orig = new
          end
          schemaMerge(orig[k], new[k], cloud)
        }
      elsif orig.is_a?(Array) and new
        orig.concat(new)
        orig.uniq!
      elsif new.is_a?(String)
        orig ||= ""
        orig += "\n" if !orig.empty? 
        orig += "+#{cloud.upcase}+: "+new
      else
# XXX I think this is a NOOP?
      end
    end

    @@allregions = []
    @@loadfails = []
    MU::Cloud.availableClouds.each { |cloud|
      next if @@loadfails.include?(cloud)
      begin
        regions = MU::Cloud.cloudClass(cloud).listRegions()
        @@allregions.concat(regions) if regions
      rescue MU::MuError => e
        @@loadfails << cloud
        MU.log e.message, MU::WARN
      end
    }

    # Configuration chunk for choosing a provider region
    # @return [Hash]
    def self.region_primitive
      if !@@allregions or @@allregions.empty?
        @@allregions = []
        MU::Cloud.availableClouds.each { |cloud|
          next if @@loadfails.include?(cloud)
          cloudclass = MU::Cloud.cloudClass(cloud)
          begin
            return @@allregions if !cloudclass.listRegions()
            @@allregions.concat(cloudclass.listRegions())
          rescue MU::MuError => e
            @@loadfails << cloud
            MU.log e.message, MU::WARN
          end
        }
      end
      {
        "type" => "string",
        "enum" => @@allregions
      }
    end

    # Configuration chunk for choosing a set of cloud credentials
    # @return [Hash]
    def self.credentials_primitive
      {
          "type" => "string",
          "description" => "Specify a non-default set of credentials to use when authenticating to cloud provider APIs, as listed in `mu.yaml` under each provider's subsection. If "
      }
    end

    # Configuration chunk for creating resource tags as an array of key/value
    # pairs.
    # @return [Hash]
    def self.optional_tags_primitive
      {
        "type" => "boolean",
        "description" => "Tag the resource with our optional tags (+MU-HANDLE+, +MU-MASTER-NAME+, +MU-OWNER+).",
        "default" => true
      }
    end

    # Configuration chunk for creating resource tags as an array of key/value
    # pairs.
    # @return [Hash]
    def self.tags_primitive
      {
        "type" => "array",
        "minItems" => 1,
        "items" => {
          "description" => "Tags to apply to this resource. Will apply at the cloud provider level and in node groomers, where applicable.",
          "type" => "object",
          "title" => "tags",
          "required" => ["key", "value"],
          "additionalProperties" => false,
          "properties" => {
            "key" => {
              "type" => "string",
            },
            "value" => {
              "type" => "string",
            }
          }
        }
      }
    end

    # Configuration chunk for choosing a cloud provider
    # @return [Hash]
    def self.cloud_primitive
      {
        "type" => "string",
#        "default" => MU::Config.defaultCloud, # applyInheritedDefaults does this better
        "enum" => MU::Cloud.supportedClouds
      }
    end


    # JSON-schema for resource dependencies
    # @return [Hash]
    def self.dependencies_primitive
      {
        "type" => "array",
        "items" => {
          "type" => "object",
          "description" => "Declare other objects which this resource requires. This resource will wait until the others are available to create itself.",
          "required" => ["name", "type"],
          "additionalProperties" => false,
          "properties" => {
            "name" => {"type" => "string"},
            "type" => {
              "type" => "string",
              "enum" => MU::Cloud.resource_types.values.map { |v| v[:cfg_name] }
            },
            "my_phase" => {
              "type" => "string",
              "description" => "Which part of our creation process should be waiting?",
              "enum" => ["create", "groom"]
            },
            "their_phase" => {
              "type" => "string",
              "description" => "Which part of the creation process of the resource we depend on should we wait for before starting our own creation? Defaults are usually sensible, but sometimes you want, say, a Server to wait on another Server to be completely ready (through its groom phase) before starting up.",
              "enum" => ["create", "groom"]
            },
            "phase" => {
              "type" => "string",
              "description" => "Alias for {their_phase}",
              "enum" => ["create", "groom"]
            },
            "no_create_wait" => {
              "type" => "boolean",
              "description" => "DEPRECATED- setting +true+ is the same as setting {my_phase} to +groom+; setting to +false+ is the same as setting {my_phase} to +create+. If both +no_create_wait+ and {my_phase} are specified, {my_phase} takes precedence."
            }
          }
        }
      }
    end

    # Have a default value available for config schema elements that take an
    # email address.
    # @return [String]
    def self.notification_email 
      if MU.chef_user == "mu"
        ENV['MU_ADMIN_EMAIL']
      else
        MU.userEmail
      end
    end

    # Load and validate the schema for an individual resource class, optionally
    # merging cloud-specific schema components.
    # @param type [String]: The resource type to load
    # @param cloud [String]: A specific cloud, whose implementation's schema of this resource we will merge
    # @return [Hash]
    def self.loadResourceSchema(type, cloud: nil)
      valid = true
      shortclass, _cfg_name, _cfg_plural, _classname = MU::Cloud.getResourceNames(type)
      schemaclass = Object.const_get("MU").const_get("Config").const_get(shortclass)

      [:schema, :validate].each { |method|
        if !schemaclass.respond_to?(method)
          MU.log "MU::Config::#{type}.#{method.to_s} doesn't seem to be implemented", MU::ERR
          return [nil, false] if method == :schema
          valid = false
        end
      }

      schema = schemaclass.schema.dup

      schema["properties"]["virtual_name"] = {
        "description" => "Internal use.",
        "type" => "string"
      }
      schema["properties"]["dependencies"] = MU::Config.dependencies_primitive
      schema["properties"]["cloud"] = MU::Config.cloud_primitive
      schema["properties"]["credentials"] = MU::Config.credentials_primitive
      schema["title"] = type.to_s

      if cloud
        cloudclass = MU::Cloud.resourceClass(cloud, type)

        if cloudclass.respond_to?(:schema)
          _reqd, cloudschema = cloudclass.schema
          cloudschema.each { |key, cfg|
            if schema["properties"][key]
              schemaMerge(schema["properties"][key], cfg, cloud)
            else
              schema["properties"][key] = cfg.dup
            end
          }
        else
          MU.log "MU::Cloud::#{cloud}::#{type}.#{method.to_s} doesn't seem to be implemented", MU::ERR
          valid = false
        end

      end

      return [schema, valid]
    end

    private

    def applySchemaDefaults(conf_chunk = config, schema_chunk = schema, depth = 0, siblings = nil, type: nil)
      return if schema_chunk.nil?

      if conf_chunk != nil and schema_chunk["properties"].kind_of?(Hash) and conf_chunk.is_a?(Hash)

        if schema_chunk["properties"]["creation_style"].nil? or
            schema_chunk["properties"]["creation_style"] != "existing"
          schema_chunk["properties"].each_pair { |key, subschema|
            shortclass = if conf_chunk[key]
              shortclass, _cfg_name, _cfg_plural, _classname = MU::Cloud.getResourceNames(key, false)
              shortclass
            else
              nil
            end

            new_val = applySchemaDefaults(conf_chunk[key], subschema, depth+1, conf_chunk, type: shortclass).dup
            if !new_val.nil?
              begin
                conf_chunk[key] = Marshal.load(Marshal.dump(new_val))
              rescue TypeError
                conf_chunk[key] = new_val.clone
              end
            end
          }
        end
      elsif schema_chunk["type"] == "array" and conf_chunk.kind_of?(Array)
        conf_chunk.map! { |item|
          # If we're working on a resource type, go get implementation-specific
          # schema information so that we set those defaults correctly.
          realschema = if type and schema_chunk["items"] and schema_chunk["items"]["properties"] and item["cloud"] and MU::Cloud.supportedClouds.include?(item['cloud'])

            _toplevel_required, cloudschema = MU::Cloud.resourceClass(item["cloud"], type).schema(self)

            newschema = schema_chunk["items"].dup
            MU::Config.schemaMerge(newschema["properties"], cloudschema, item["cloud"])
            newschema
          else
            schema_chunk["items"].dup
          end

          applySchemaDefaults(item, realschema, depth+1, conf_chunk, type: type).dup
        }
      else
        if conf_chunk.nil? and !schema_chunk["default_if"].nil? and !siblings.nil?
          schema_chunk["default_if"].each { |cond|
            if siblings[cond["key_is"]] == cond["value_is"]
              return Marshal.load(Marshal.dump(cond["set"]))
            end
          }
        end
        if conf_chunk.nil? and schema_chunk["default"] != nil
          return Marshal.load(Marshal.dump(schema_chunk["default"]))
        end
      end

      return conf_chunk
    end

    # Given a bare hash describing a resource, insert default values which can
    # be inherited from its parent or from the root of the BoK.
    # @param kitten [Hash]: A resource descriptor
    # @param type [String]: The type of resource this is ("servers" etc)
    def applyInheritedDefaults(kitten, type)
      return if !kitten.is_a?(Hash)
      kitten['cloud'] ||= @config['cloud']
      kitten['cloud'] ||= MU::Config.defaultCloud

      if !MU::Cloud.supportedClouds.include?(kitten['cloud'])
        return
      end

      cloudclass = MU::Cloud.cloudClass(kitten['cloud'])

      resclass = MU::Cloud.resourceClass(kitten['cloud'], type)

      schema_fields = ["us_only", "scrub_mu_isms", "credentials", "billing_acct"]
      if !resclass.isGlobal?
        kitten['region'] ||= @config['region']
        kitten['region'] ||= cloudclass.myRegion(kitten['credentials'])
        schema_fields << "region"
      end

      kitten['credentials'] ||= @config['credentials']
      kitten['credentials'] ||= cloudclass.credConfig(name_only: true)

      kitten['us_only'] ||= @config['us_only']
      kitten['us_only'] ||= false

      kitten['scrub_mu_isms'] ||= @config['scrub_mu_isms']
      kitten['scrub_mu_isms'] ||= false

      if kitten['cloud'] == "Google"
# TODO this should be cloud-generic (handle AWS accounts, Azure subscriptions)
        if resclass.canLiveIn.include?(:Habitat)
          kitten["project"] ||= MU::Cloud::Google.defaultProject(kitten['credentials'])
          schema_fields << "project"
        end
        if kitten['region'].nil? and !kitten['#MU_CLOUDCLASS'].nil? and
           !resclass.isGlobal? and
           ![MU::Cloud::VPC, MU::Cloud::FirewallRule].include?(kitten['#MU_CLOUDCLASS'])
          if MU::Cloud::Google.myRegion((kitten['credentials'])).nil?
            raise ValidationError, "Google '#{type}' resource '#{kitten['name']}' declared without a region, but no default Google region declared in mu.yaml under #{kitten['credentials'].nil? ? "default" : kitten['credentials']} credential set" 
          end
          kitten['region'] ||= MU::Cloud::Google.myRegion
        end
      elsif kitten["cloud"] == "AWS" and !resclass.isGlobal? and !kitten['region']
        if MU::Cloud::AWS.myRegion.nil?
          raise ValidationError, "AWS resource declared without a region, but no default AWS region found"
        end
        kitten['region'] ||= MU::Cloud::AWS.myRegion
      end


      kitten['billing_acct'] ||= @config['billing_acct'] if @config['billing_acct']

      kitten["dependencies"] ||= []

      # Make sure the schema knows about these "new" fields, so that validation
      # doesn't trip over them.
      schema_fields.each { |field|
        if @@schema["properties"][field]
          MU.log "Adding #{field} to schema for #{type} #{kitten['cloud']}", MU::DEBUG, details: @@schema["properties"][field]
          @@schema["properties"][type]["items"]["properties"][field] ||= @@schema["properties"][field]
        end
      }
    end

    CIDR_PATTERN = "^\\d+\\.\\d+\\.\\d+\\.\\d+\/[0-9]{1,2}$"
    CIDR_DESCRIPTION = "CIDR-formatted IP block, e.g. 1.2.3.4/32"
    CIDR_PRIMITIVE = {
      "type" => "string",
      "pattern" => CIDR_PATTERN,
      "description" => CIDR_DESCRIPTION
    }


    @@schema = {
      "$schema" => "http://json-schema.org/draft-04/schema#",
      "title" => "MU Application",
      "type" => "object",
      "description" => "A MU application stack, consisting of at least one resource.",
      "required" => ["admins", "appname"],
      "properties" => {
        "appname" => {
            "type" => "string",
            "description" => "A name for your application stack. Should be short, but easy to differentiate from other applications.",
        },
        "scrub_mu_isms" => {
            "type" => "boolean",
            "description" => "When 'cloud' is set to 'CloudFormation,' use this flag to strip out Mu-specific artifacts (tags, standard userdata, naming conventions, etc) to yield a clean, source-agnostic template. Setting this flag here will override declarations in individual resources."
        },
        "project" => {
          "type" => "string",
          "description" => "**GOOGLE ONLY**: The project into which to deploy resources"
        },
        "billing_acct" => {
          "type" => "string",
          "description" => "**GOOGLE ONLY**: Billing account ID to associate with a newly-created Google Project. If not specified, will attempt to locate a billing account associated with the default project for our credentials.",
        },
        "region" => MU::Config.region_primitive,
        "credentials" => MU::Config.credentials_primitive,
        "us_only" => {
            "type" => "boolean",
            "description" => "For resources which span regions, restrict to regions inside the United States",
            "default" => false
        },
        "conditions" => {
            "type" => "array",
            "items" => {
              "type" => "object",
              "required" => ["name", "cloudcode"],
              "description" => "CloudFormation-specific. Define Conditions as in http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/conditions-section-structure.html. Arguments must use the cloudCode() macro.",
              "properties" => {
                "name" => { "required" => true, "type" => "string" },
                "cloudcode" => { "required" => true, "type" => "string" },
              }
            }
        },
        "parameters" => {
            "type" => "array",
            "items" => {
                "type" => "object",
                "title" => "parameter",
                "description" => "Parameters to be substituted elsewhere in this Basket of Kittens as ERB variables (<%= varname %>)",
                "additionalProperties" => false,
                "properties" => {
                  "name" => { "required" => true, "type" => "string" },
                  "default" => { "type" => "string" },
                  "list_of" => {
                    "type" => "string",
                    "description" => "Treat the value as a comma-separated list of values with this key name, equivalent to CloudFormation's various List<> types. For example, set to 'subnet_id' to pass values as an array of subnet identifiers as the 'subnets' argument of a VPC stanza."
                  },
                  "prettyname" => {
                    "type" => "string",
                    "description" => "An alternative name to use when generating parameter fields in, for example, CloudFormation templates"
                  },
                  "description" => {"type" => "string"},
                  "cloudtype" => {
                    "type" => "string",
                    "description" => "A platform-specific string describing the type of validation to use for this parameter. E.g. when generating a CloudFormation template, set to AWS::EC2::Image::Id to validate input as an AMI identifier."
                  },
                  "required" => {
                    "type" => "boolean",
                    "default" => true
                  },
                  "valid_values" => {
                    "type" => "array",
                    "description" => "List of valid values for this parameter. Can only be a list of static strings, for now.",
                    "items" => {
                      "type" => "string"
                    }
                  }
                }
            }
        },
        # TODO availability zones (or an array thereof) 

        "admins" => {
          "type" => "array",
          "items" => {
            "type" => "object",
            "title" => "admin",
            "description" => "Administrative contacts for this application stack. Will be automatically set to invoking Mu user, if not specified.",
            "required" => ["name", "email"],
            "additionalProperties" => false,
            "properties" => {
              "name" => {"type" => "string"},
              "email" => {"type" => "string"},
              "public_key" => {
                "type" => "string",
                "description" => "An OpenSSH-style public key string. This will be installed on all instances created in this deployment."
              }
            }
          },
          "minItems" => 1,
          "uniqueItems" => true
        }
      },
      "additionalProperties" => false
    }

  end #class
end #module
