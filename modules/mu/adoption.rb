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

  # Scrape cloud providers for existing resources, and reverse-engineer them
  # into runnable {MU::Config} descriptors and/or {MU::MommaCat} deploy objects.
  class Adoption

    attr_reader :found

    # Error class for objects which fail to fully resolve (e.g. references to 
    # other objects which are not found)
    class Incomplete < MU::MuNonFatal; end

    # Presets methods we use to clump discovered resources into discrete deploys
    GROUPMODES = {
      :logical => "Group resources in logical layers (folders and habitats together, users/roles/groups together, network resources together, etc)",
      :omnibus => "Jam everything into one monolothic configuration"
    }

    def initialize(clouds: MU::Cloud.supportedClouds, types: MU::Cloud.resource_types.keys, parent: nil, billing: nil, sources: nil, credentials: nil, group_by: :logical, savedeploys: false, diff: false, habitats: [])
      @scraped = {}
      @clouds = clouds
      @types = types
      @parent = parent
      @boks = {}
      @billing = billing
      @reference_map = {}
      @sources = sources
      @target_creds = credentials
      @group_by = group_by
      @savedeploys = savedeploys
      @diff = diff
      @habitats = habitats
      @habitats ||= []
    end

    # Walk cloud providers with available credentials to discover resources
    def scrapeClouds()
      @default_parent = nil

      @clouds.each { |cloud|
        cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
        next if cloudclass.listCredentials.nil?

        if cloud == "Google" and !@parent and @target_creds
          dest_org = MU::Cloud::Google.getOrg(@target_creds)
          if dest_org
            @default_parent = dest_org.name
          end
        end

        cloudclass.listCredentials.each { |credset|
          next if @sources and !@sources.include?(credset)

          if @parent
# TODO handle different inputs (cloud_id, etc)
# TODO do something about vague matches
            found = MU::MommaCat.findStray(
              cloud,
              "folders",
              flags: { "display_name" => @parent },
              credentials: credset,
              allow_multi: false,
              dummy_ok: true,
              debug: false
            )
            if found and found.size == 1
              @default_parent = found.first
            end
          end

          @types.each { |type|
            begin
              resclass = Object.const_get("MU").const_get("Cloud").const_get(cloud).const_get(type)
            rescue ::MU::Cloud::MuCloudResourceNotImplemented
              next
            end
            if !resclass.instance_methods.include?(:toKitten)
              MU.log "Skipping MU::Cloud::#{cloud}::#{type} (resource has not implemented #toKitten)", MU::WARN
              next
            end
            MU.log "Scraping #{cloud}/#{credset} for #{resclass.cfg_plural}"

            found = MU::MommaCat.findStray(
              cloud,
              type,
              credentials: credset,
              allow_multi: true,
              habitats: @habitats.dup,
              dummy_ok: true,
              debug: false,
              flags: { "skip_provider_owned" => true }
            )


            if found and found.size > 0
              MU.log "Found #{found.size.to_s} raw #{resclass.cfg_plural} in #{cloud}"
              @scraped[type] ||= {}
              found.each { |obj|
                # XXX apply any filters (e.g. MU-ID tags)
                @scraped[type][obj.cloud_id] = obj
              }
            end

          }
        }
      }

      if @parent and !@default_parent
        MU.log "Failed to locate a folder that resembles #{@parent}", MU::ERR
      end
      MU.log "Scraping complete"
    end

    # Given a list of BoK style tags, try to reverse-engineer the correct
    # Basket of Kittens shorthand name of the resource that owns them. Mostly
    # this infers from Mu-style tagging, but we'll add a couple cases for
    # special cloud provider cases.
    # @param tags [Array<Hash>]
    # return [String]
    def self.tagsToName(tags = [])
      tags.each { |tag|
        if tag['key'] == "aws:cloudformation:logical-id"
          return tag['value']
        end
      }
      muid = nil
      tags.each { |tag|
        if tag['key'] == "MU-ID" or tag['key'] == "mu-id"
          muid = tag['value']
          break
        end
      }
      tags.each { |tag|
        if tag['key'] == "Name"
          if muid and tag['value'].match(/^#{Regexp.quote(muid)}-(.*)/)
            return Regexp.last_match[1].downcase
          else
            return tag['value'].downcase
          end
        end
      }
      nil
    end

    # Generate a {MU::Config} (Basket of Kittens) hash using our discovered
    # cloud objects.
    # @return [Hash]
    def generateBaskets(prefix: "")
      groupings = {
        "" =>  MU::Cloud.resource_types.values.map { |v| v[:cfg_plural] }
      }

      # XXX as soon as we come up with a method that isn't about what resource
      # type you are, this code will stop making sense
      if @group_by == :logical
        groupings = {
          "spaces" => ["folders", "habitats"],
          "people" => ["users", "groups", "roles"],
          "network" => ["vpcs", "firewall_rules", "dnszones"],
          "storage" => ["storage_pools", "buckets"],
        }
        # "the movie star/and the rest"
        groupings["services"] = MU::Cloud.resource_types.values.map { |v| v[:cfg_plural] } - groupings.values.flatten
      elsif @group_by == :omnibus
        prefix = "mu" if prefix.empty? # so that appnames aren't ever empty
      end

      groupings.each_pair { |appname, types|
        bok = { "appname" => prefix+appname }
        if @target_creds
          bok["credentials"] = @target_creds
        end

        count = 0
        allowed_types = @types.map { |t| MU::Cloud.resource_types[t][:cfg_plural] }
        next if (types & allowed_types).size == 0
        origin = {
          "appname" => bok['appname'],
          "types" => (types & allowed_types).sort,
          "habitats" => @habitats.sort,
          "group_by" => @group_by.to_s
        }

        deploy = MU::MommaCat.findMatchingDeploy(origin)
        if @diff and !deploy
          MU.log "--diff was set but I failed to find a deploy like me to compare to", MU::ERR, details: origin
          exit 1
        end

        threads = []
        @clouds.each { |cloud|
          @scraped.each_pair { |type, resources|
            res_class = begin
              MU::Cloud.loadCloudType(cloud, type)
            rescue MU::Cloud::MuCloudResourceNotImplemented => e
              # XXX I don't think this can actually happen
              next
            end
            next if !types.include?(res_class.cfg_plural)

            bok[res_class.cfg_plural] ||= []

            class_semaphore = Mutex.new

            Thread.abort_on_exception = true
            resources.each_pair { |cloud_id_thr, obj_thr|
              threads << Thread.new(cloud_id_thr, obj_thr) { |cloud_id, obj|

                kitten_cfg = obj.toKitten(rootparent: @default_parent, billing: @billing, habitats: @habitats)
                if kitten_cfg
                  print "."
                  kitten_cfg.delete("credentials") if @target_creds
                  class_semaphore.synchronize {
                    bok[res_class.cfg_plural] << kitten_cfg
                  }
                  count += 1
                end
              }

            }

            threads.each { |t|
              t.join
            }
            puts ""
            bok[res_class.cfg_plural].sort! { |a, b|
              strs = [a, b].map { |x|
                if x['cloud_id']
                  x['cloud_id']
                elsif x['parent'] and ['parent'].respond_to?(:id) and kitten_cfg['parent'].id
                  x['name']+x['parent'].id
                elsif x['project']
                  x['name']+x['project']
                else
                  x['name']
                end
              }
              strs[0] <=> strs[1]
            }

            # If we've got duplicate names in here, try to deal with it
            bok[res_class.cfg_plural].each { |kitten_cfg|
              bok[res_class.cfg_plural].each { |sibling|
                next if kitten_cfg == sibling
                if sibling['name'] == kitten_cfg['name']
                  MU.log "#{res_class.cfg_name} name #{sibling['name']} unavailable, will attempt to rename duplicate object", MU::DEBUG, details: kitten_cfg
                  if kitten_cfg['parent'] and kitten_cfg['parent'].respond_to?(:id) and kitten_cfg['parent'].id
                    kitten_cfg['name'] = kitten_cfg['name']+kitten_cfg['parent'].id
                  elsif kitten_cfg['project']
                    kitten_cfg['name'] = kitten_cfg['name']+kitten_cfg['project']
                  elsif kitten_cfg['region']
                    kitten_cfg['name'] = kitten_cfg['name']+kitten_cfg['region']
                  elsif kitten_cfg['cloud_id']
                    kitten_cfg['name'] = kitten_cfg['name']+kitten_cfg['cloud_id'].gsub(/[^a-z0-9]/i, "-")
                  else
                    raise MU::Config::DuplicateNameError, "Saw duplicate #{res_class.cfg_name} name #{sibling['name']} and couldn't come up with a good way to differentiate them"
                  end
                  MU.log "De-duplication: Renamed #{res_class.cfg_name} name '#{sibling['name']}' => '#{kitten_cfg['name']}'", MU::NOTICE
                  break
                end
              }
            }
          }
        }

        # No matching resources isn't necessarily an error
        next if count == 0 or bok.nil?

# Now walk through all of the Refs in these objects, resolve them, and minimize
# their config footprint
        MU.log "Minimizing footprint of #{count.to_s} found resources", MU::DEBUG
        @boks[bok['appname']] = vacuum(bok, origin: origin, save: @savedeploys)

        if @diff and !deploy
          MU.log "diff flag set, but no comparable deploy provided for #{bok['appname']}", MU::ERR
          exit 1
        end

        if deploy and @diff
          prevcfg = MU::Config.manxify(vacuum(deploy.original_config, deploy: deploy))
          if !prevcfg
            MU.log "#{deploy.deploy_id} didn't have a working original config for me to compare", MU::ERR
            exit 1
          end
          newcfg = MU::Config.manxify(@boks[bok['appname']])

          prevcfg.diff(newcfg)
          exit
        end
      }
      @boks
    end

    private

    def scrubSchemaDefaults(conf_chunk, schema_chunk, depth = 0, siblings = nil, type: nil)
      return if schema_chunk.nil?

      if !conf_chunk.nil? and schema_chunk["properties"].kind_of?(Hash) and conf_chunk.is_a?(Hash)
        deletia = []
        schema_chunk["properties"].each_pair { |key, subschema|
          next if !conf_chunk[key]
          shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(key)

          if subschema["default_if"]
            subschema["default_if"].each { |cond|
              if conf_chunk[cond["key_is"]] == cond["value_is"]
                subschema["default"] = cond["set"]
                break
              end
            }
          end

          if subschema["default"] and conf_chunk[key] == subschema["default"]
            deletia << key
          elsif ["array", "object"].include?(subschema["type"])
            scrubSchemaDefaults(conf_chunk[key], subschema, depth+1, conf_chunk, type: shortclass)
          end
        }
        deletia.each { |key| conf_chunk.delete(key) }
      elsif schema_chunk["type"] == "array" and conf_chunk.kind_of?(Array)
        conf_chunk.each { |item|
          # this bit only happens at the top-level key for a resource type, in
          # theory
          realschema = if type and schema_chunk["items"] and schema_chunk["items"]["properties"] and item["cloud"] and MU::Cloud.supportedClouds.include?(item['cloud'])

            cloudclass = Object.const_get("MU").const_get("Cloud").const_get(item["cloud"]).const_get(type)
            toplevel_required, cloudschema = cloudclass.schema(self)

            newschema = schema_chunk["items"].dup
            newschema["properties"].merge!(cloudschema)
            newschema
          else
            schema_chunk["items"].dup
          end
          next if ["array", "object"].include?(realschema["type"])

          scrubSchemaDefaults(item, realschema, depth+1, conf_chunk, type: type)
        }
      end

      conf_chunk
    end

    # Recursively walk through a BoK hash, validate all {MU::Config::Ref}
    # objects, convert them to hashes, and pare them down to the minimal
    # representation (remove extraneous attributes that match the parent
    # object).
    # Do the same for our main objects: if they all use the same credentials,
    # for example, remove the explicit +credentials+ attributes and set that
    # value globally, once.
    def vacuum(bok, origin: nil, save: false, deploy: nil)
      deploy ||= generateStubDeploy(bok)

      globals = {
        'cloud' => {},
        'credentials' => {},
        'region' => {},
        'billing_acct' => {},
        'us_only' => {},
      }
      clouds = {}
      credentials = {}
      regions = {}
      MU::Cloud.resource_types.each_pair { |typename, attrs|
        if bok[attrs[:cfg_plural]]
          processed = []
          bok[attrs[:cfg_plural]].each { |resource|
            globals.each_pair { |field, counts|
              if resource[field]
                counts[resource[field]] ||= 0
                counts[resource[field]] += 1
              end
            }
            obj = deploy.findLitterMate(type: attrs[:cfg_plural], name: resource['name'])
            begin
              raise Incomplete if obj.nil?
              new_cfg = resolveReferences(resource, deploy, obj)
              new_cfg.delete("cloud_id")
              cred_cfg = MU::Cloud.const_get(obj.cloud).credConfig(obj.credentials)
              if cred_cfg['region'] == new_cfg['region']
                new_cfg.delete('region')
              end
              if cred_cfg['default']
                new_cfg.delete('credentials')
                new_cfg.delete('habitat')
              end
              processed << new_cfg
            rescue Incomplete
            end
          }

          deploy.original_config[attrs[:cfg_plural]] = processed
          bok[attrs[:cfg_plural]] = processed
        end
      }

      # Pare out global values like +cloud+ or +region+ that appear to be
      # universal in the deploy we're creating.
      def scrub_globals(h, field)
        if h.is_a?(Hash)
          newhash = {}
          h.each_pair { |k, v|
            next if k == field
            newhash[k] = scrub_globals(v, field)
          }
          h = newhash
        elsif h.is_a?(Array)
          newarr = []
          h.each { |v|
            newarr << scrub_globals(v, field)
          }
          h = newarr
        end

        h
      end

      globals.each_pair { |field, counts|
        next if counts.size != 1
        bok[field] = counts.keys.first
        MU.log "Setting global default #{field} to #{bok[field]} (#{deploy.deploy_id})", MU::DEBUG
        MU::Cloud.resource_types.each_pair { |typename, attrs|
          if bok[attrs[:cfg_plural]]
            new_resources = []
            bok[attrs[:cfg_plural]].each { |resource|
              new_resources << scrub_globals(resource, field)
            }
            bok[attrs[:cfg_plural]] = new_resources
          end
        }
      }

      scrubSchemaDefaults(bok, MU::Config.schema)

      if save
        MU.log "Committing adopted deployment to #{MU.dataDir}/deployments/#{deploy.deploy_id}", MU::NOTICE, details: origin
        deploy.save!(force: true, origin: origin)
      end

      bok
    end

    def resolveReferences(cfg, deploy, parent)
      if cfg.is_a?(MU::Config::Ref)
        hashcfg = cfg.to_h
        if cfg.kitten(deploy)
          littermate = deploy.findLitterMate(type: cfg.type, name: cfg.name, cloud_id: cfg.id, habitat: cfg.habitat)

          if littermate and littermate.config['name']
            hashcfg['name'] = littermate.config['name']
            hashcfg.delete("id") if hashcfg["name"]
            hashcfg
          elsif cfg.deploy_id and cfg.name and @savedeploys
            hashcfg.delete("id") if hashcfg["name"]
            hashcfg
          elsif cfg.id
            littermate = deploy.findLitterMate(type: cfg.type, cloud_id: cfg.id, habitat: cfg.habitat)
            if littermate and littermate.config['name']
              hashcfg['name'] = littermate.config['name']
              hashcfg.delete("id") if hashcfg["name"]
            elsif !@savedeploys
              hashcfg.delete("deploy_id")
              hashcfg.delete("name")
            else
              hashcfg.delete("name") if cfg.id and !cfg.deploy_id
            end
          end
        elsif hashcfg["id"] # reference to raw cloud ids is reasonable
          hashcfg.delete("deploy_id")
          hashcfg.delete("name")
        else
          pp parent.cloud_desc
          raise Incomplete, "Failed to resolve reference on behalf of #{parent}"
        end
        hashcfg.delete("deploy_id") if hashcfg['deploy_id'] == deploy.deploy_id
        if parent and parent.config
          cred_cfg = MU::Cloud.const_get(parent.cloud).credConfig(parent.credentials)

          if parent.config['region'] == hashcfg['region'] or
             cred_cfg['region'] == hashcfg['region']
            hashcfg.delete("region")
          end

          habitat_id = if cfg.habitat
            if cfg.habitat.is_a?(MU::Config::Ref)
              cfg.habitat.id
            else
              cfg.habitat['id']
            end
          else
            nil
          end

          if habitat_id
            if (parent.config['habitat'] and parent.config['habitat']['id'] == habitat_id) or
               cred_cfg['account_number'] == habitat_id or # AWS
               cred_cfg['project'] == habitat_id or # GCP
               cred_cfg['subscription'] == habitat_id # Azure
              hashcfg.delete('habitat') 
            end
          end

          if parent.config['credentials'] == hashcfg['credentials']
            hashcfg.delete("credentials")
          end
        end
        cfg = hashcfg
      elsif cfg.is_a?(Hash)
        deletia = []
        cfg.each_pair { |key, value|
          begin
            cfg[key] = resolveReferences(value, deploy, parent)
          rescue Incomplete
            MU.log "Dropping unresolved key #{key}", MU::WARN, details: cfg
            deletia << key
          end
        }
        deletia.each { |key|
          cfg.delete(key)
        }
        cfg = nil if cfg.empty? and deletia.size > 0
      elsif cfg.is_a?(Array)
        new_array = []
        cfg.each { |value|
          begin
            new_item = resolveReferences(value, deploy, parent)
            if !new_item
              MU.log "Dropping unresolved value", MU::WARN, details: value
            else
              new_array << new_item
            end
          rescue Incomplete
            MU.log "Dropping unresolved value", MU::WARN, details: value
          end
        }
        cfg = new_array
      end

      cfg
    end

    # @return [MU::MommaCat]
    def generateStubDeploy(bok)
#      hashify Ref objects before passing into here... or do we...?

      time = Time.new
      timestamp = time.strftime("%Y%m%d%H").to_s;
      timestamp.freeze

      retries = 0
      deploy_id = nil
      seed = nil
      begin
        raise MuError, "Failed to allocate an unused MU-ID after #{retries} tries!" if retries > 70
        seedsize = 1 + (retries/10).abs
        seed = (0...seedsize+1).map { ('a'..'z').to_a[rand(26)] }.join
        deploy_id = bok['appname'].upcase + "-ADOPT-" + timestamp + "-" + seed.upcase
      end while MU::MommaCat.deploy_exists?(deploy_id) or seed == "mu" or seed[0] == seed[1]

      MU.setVar("deploy_id", deploy_id)
      MU.setVar("appname", bok['appname'].upcase)
      MU.setVar("environment", "ADOPT")
      MU.setVar("timestamp", timestamp)
      MU.setVar("seed", seed)
      MU.setVar("handle", MU::MommaCat.generateHandle(seed))

      deploy = MU::MommaCat.new(
        deploy_id,
        create: true,
        config: bok,
        environment: "adopt",
        appname: bok['appname'].upcase,
        timestamp: timestamp,
        nocleanup: true,
        no_artifacts: !(@savedeploys),
        set_context_to_me: true,
        mu_user: MU.mu_user
      )

      MU::Cloud.resource_types.each_pair { |typename, attrs|
        if bok[attrs[:cfg_plural]]
          bok[attrs[:cfg_plural]].each { |kitten|

            if !@scraped[typename][kitten['cloud_id']]
              MU.log "No object in scraped tree for #{attrs[:cfg_name]} #{kitten['cloud_id']} (#{kitten['name']})", MU::ERR, details: kitten
              next
            end

            MU.log "Inserting #{attrs[:cfg_name]} #{kitten['name']} (#{kitten['cloud_id']}) into stub deploy", MU::DEBUG, details: @scraped[typename][kitten['cloud_id']]

            @scraped[typename][kitten['cloud_id']].config!(kitten)

            deploy.addKitten(
              attrs[:cfg_plural],
              kitten['name'],
              @scraped[typename][kitten['cloud_id']]
            )
          }
        end
      }

      deploy
    end

    # Go through everything we've scraped and update our mappings of cloud ids
    # and bare name fields, so that resources can reference one another
    # portably by name.
    def catalogResources
    end

  end
end
