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

    def initialize(clouds: MU::Cloud.supportedClouds, types: MU::Cloud.resource_types.keys, parent: nil, billing: nil, sources: nil, credentials: nil, group_by: :logical, savedeploys: false, diff: false, habitats: [], scrub_mu_isms: false, regions: [], merge: false, pattern: nil)
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
      @regions = regions
      @habitats ||= []
      @scrub_mu_isms = scrub_mu_isms
      @merge = merge
      @pattern = pattern
    end

    # Walk cloud providers with available credentials to discover resources
    def scrapeClouds()
      @default_parent = nil

      @clouds.each { |cloud|
        cloudclass = MU::Cloud.cloudClass(cloud)
        next if cloudclass.listCredentials.nil?

        if cloud == "Google" and !@parent and @target_creds
          dest_org = MU::Cloud::Google.getOrg(@target_creds)
          if dest_org
            @default_parent = dest_org.name
          end
        end

        cloudclass.listCredentials.each { |credset|
          next if @sources and !@sources.include?(credset)
          cfg = cloudclass.credConfig(credset)
          if cfg and cfg['restrict_to_habitats']
            cfg['restrict_to_habitats'] << cfg['project'] if cfg['project']
          end

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
              resclass = MU::Cloud.resourceClass(cloud, type)
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
              region: @regions,
              dummy_ok: true,
              skip_provider_owned: true,
#              debug: false#,
            )


            if found and found.size > 0
              if resclass.cfg_plural == "habitats"
                found.reject! { |h|
                  !cloudclass.listHabitats(credset).include?(h.cloud_id)
                }
              end
              MU.log "Found #{found.size.to_s} raw #{resclass.cfg_plural} in #{cloud}"
              @scraped[type] ||= {}
              found.each { |obj|
                if obj.habitat and !cloudclass.listHabitats(credset).include?(obj.habitat)
                  next
                end

                # XXX apply any filters (e.g. MU-ID tags)
                if obj.cloud_id.nil?
                  MU.log "This damn thing gave me no cloud id, what do I even do with that", MU::ERR, details: obj
                  exit
                end
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

      @scraped
    end

    # Given a list of BoK style tags, try to reverse-engineer the correct
    # Basket of Kittens shorthand name of the resource that owns them. Mostly
    # this infers from Mu-style tagging, but we'll add a couple cases for
    # special cloud provider cases.
    # @param tags [Array<Hash>]
    # @param basename [String]
    # return [String]
    def self.tagsToName(tags = [], basename: nil)
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

      if basename and muid and basename.match(/^#{Regexp.quote(muid)}-(.*)/)
        return Regexp.last_match[1].downcase
      end

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

      # Find any previous deploys with this particular profile, which we'll use
      # later for --diff.
      @existing_deploys = {}
      @existing_deploys_by_id = {}
      @origins = {}
      @types_found_in = {}
      groupings.each_pair { |appname, types|
        allowed_types = @types.map { |t| MU::Cloud.resource_types[t][:cfg_plural] }
        next if (types & allowed_types).size == 0
        origin = {
          "appname" => prefix+appname,
          "types" => (types & allowed_types).sort,
          "habitats" => @habitats.sort,
          "group_by" => @group_by.to_s
        }

        @existing_deploys[appname] = MU::MommaCat.findMatchingDeploy(origin)
        if @existing_deploys[appname]
          @existing_deploys_by_id[@existing_deploys[appname].deploy_id] = @existing_deploys[appname]
          @origins[appname] = origin
          origin['types'].each { |t|
            @types_found_in[t] = @existing_deploys[appname]
          }
        end
      }

      groupings.each_pair { |appname, types|
        allowed_types = @types.map { |t| MU::Cloud.resource_types[t][:cfg_plural] }
        next if (types & allowed_types).size == 0

        bok = { "appname" => prefix+appname }
        if @scrub_mu_isms
          bok["scrub_mu_isms"] = true
        end
        if @target_creds
          bok["credentials"] = @target_creds
        end

        count = 0
        if @diff
          if !@existing_deploys[appname]
            MU.log "--diff was set but I failed to find a deploy like '#{appname}' to compare to (have #{@existing_deploys.keys.join(", ")})", MU::ERR, details: @origins[appname]
            exit 1
          else
            MU.log "Will diff current live resources against #{@existing_deploys[appname].deploy_id}", MU::NOTICE, details: @origins[appname]
          end
        end

        threads = []
        timers = {}
        walltimers = {}
        @clouds.each { |cloud|
          @scraped.each_pair { |type, resources|
            typestart = Time.now
            res_class = begin
              MU::Cloud.resourceClass(cloud, type)
            rescue MU::Cloud::MuCloudResourceNotImplemented
              # XXX I don't think this can actually happen
              next
            end
            next if !types.include?(res_class.cfg_plural)

            bok[res_class.cfg_plural] ||= []
            timers[type] ||= {}

            class_semaphore = Mutex.new

            Thread.abort_on_exception = true
            resources.values.each { |obj_thr|
              obj_desc = nil
              begin
                obj_desc = obj_thr.cloud_desc
              rescue StandardError
              ensure
                if !obj_desc
                  MU.log cloud+" "+type.to_s+" "+obj_thr.cloud_id+" #{cloud == "Google" ? "in org #{MU::Cloud::Google.getOrg(obj_thr.credentials).display_name} ": ""}did not return a cloud descriptor, skipping", MU::WARN
                  next
                end
              end
              threads << Thread.new(obj_thr) { |obj|
                start = Time.now

                kitten_cfg = obj.toKitten(rootparent: @default_parent, billing: @billing, habitats: @habitats, types: @types)
                if kitten_cfg and (!@pattern or @pattern.match(kitten_cfg['name']))
                  print "."
                  kitten_cfg.delete("credentials") if @target_creds
                  class_semaphore.synchronize {
                    bok[res_class.cfg_plural] << kitten_cfg
                    if !kitten_cfg['cloud_id']
                      MU.log "No cloud id in this #{res_class.cfg_name} kitten!", MU::ERR, details: kitten_cfg
                    end
                    timers[type][kitten_cfg['cloud_id']] = (Time.now - start)
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
                  MU::Adoption.deDuplicateName(kitten_cfg, res_class)
                  MU.log "De-duplication: Renamed #{res_class.cfg_name} name '#{sibling['name']}' => '#{kitten_cfg['name']}'", MU::NOTICE
                  break
                end
              }
            }
            walltimers[type] ||= 0
            walltimers[type] += (Time.now - typestart)
          }
        }

        timers.each_pair { |type, resources|
          next if resources.empty?
          total = resources.values.sum
          top_5 =  resources.keys.sort { |a, b|
            resources[b] <=> resources[a]
          }.slice(0, 5).map { |k|
            k.to_s+": "+sprintf("%.2fs", resources[k])
          }
          if walltimers[type] < 45
            MU.log "Kittened #{resources.size.to_s} eligible #{type}s in #{sprintf("%.2fs", walltimers[type])}"
          else
            MU.log "Kittened #{resources.size.to_s} eligible #{type}s in #{sprintf("%.2fs", walltimers[type])} (CPU time #{sprintf("%.2fs", total)}, avg #{sprintf("%.2fs", total/resources.size)}). Top 5:", MU::NOTICE, details: top_5
          end
        }

        # No matching resources isn't necessarily an error
        next if count == 0 or bok.nil?

# Now walk through all of the Refs in these objects, resolve them, and minimize
# their config footprint
        MU.log "Minimizing footprint of #{count.to_s} found resources", MU::DEBUG

        generated_deploy = generateStubDeploy(bok)
        @boks[bok['appname']] = vacuum(bok, origin: @origins[appname], deploy: generated_deploy, save: @savedeploys)

        if @diff and !@existing_deploys[appname]
          MU.log "diff flag set, but no comparable deploy provided for #{bok['appname']}", MU::ERR
          exit 1
        end

        if @diff
          prev_vacuumed = vacuum(@existing_deploys[appname].original_config, deploy: @existing_deploys[appname], keep_missing: true, copy_from: generated_deploy)
          prevcfg = MU::Config.manxify(prev_vacuumed)
          if !prevcfg
            MU.log "#{@existing_deploys[appname].deploy_id} didn't have a working original config for me to compare", MU::ERR
            exit 1
          end
          newcfg = MU::Config.manxify(@boks[bok['appname']])
          report = prevcfg.diff(newcfg)

          if report

            if MU.muCfg['adopt_change_notify']
              notifyChanges(@existing_deploys[appname], report.freeze)
            end
            if @merge
              MU.log "Saving changes to #{@existing_deploys[appname].deploy_id}"
              @existing_deploys[appname].updateBasketofKittens(newcfg, save_now: true)
            end
          end

        end
      }
      @boks
    end

    private

    # @param tier [Hash]
    # @param parent_key [String]
    def crawlChangeReport(tier, parent_key = nil, indent: "")
      report = []
      if tier.is_a?(Array)
        tier.each { |a|
          sub_report = crawlChangeReport(a, parent_key)
          report.concat(sub_report) if sub_report and !sub_report.empty?
        }
      elsif tier.is_a?(Hash)
        if tier[:action]
          preposition = if tier[:action] == :added
            "to"
          elsif tier[:action] == :removed
            "from"
          else
            "in"
          end

          name = ""
          type_of = parent_key.sub(/s$|\[.*/, '') if parent_key
          loc = tier[:habitat]

          if tier[:value] and tier[:value].is_a?(Hash)
            name, loc = MU::MommaCat.getChunkName(tier[:value], type_of)
          elsif parent_key
            name = parent_key
          end

          path_str = []
          slack_path_str = ""
          if tier[:parents] and tier[:parents].size > 2
            path = tier[:parents].clone
            slack_path_str += "#{preposition} \*"+path.join(" ⇨ ")+"\*" if path.size > 0
            path.shift
            path.shift
            path.pop if path.last == name
            for c in (0..(path.size-1)) do
              path_str << ("  " * (c+2)) + (path[c] || "<nil>")
            end
          end
          path_str << "" if !path_str.empty?

          plain = (name ? name : type_of) if name or type_of
          plain ||= "" # XXX but this is a problem
          slack = "`"+plain+"`"

          plain += " ("+loc+")" if loc and !loc.empty?
          color = plain

          if tier[:action] == :added
            color = "+ ".green + plain
            plain = "+ " + plain
            slack += " added"
          elsif tier[:action] == :removed
            color = "- ".red + plain
            plain = "- " + plain
            slack += " removed"
          end

          slack += " #{tier[:action]} #{preposition} \*#{loc}\*" if loc and !loc.empty? and [Array, Hash].include?(tier[:value].class)

          plain = path_str.join(" => \n") + indent + plain
          color = path_str.join(" => \n") + indent + color

          slack += " "+slack_path_str if !slack_path_str.empty?
          myreport = {
            "slack" => slack,
            "plain" => plain,
            "color" => color
          }

          append = ""
          if tier[:value] and (tier[:value].is_a?(Array) or tier[:value].is_a?(Hash))
            if tier[:value].is_a?(Hash)
              if name
                tier[:value].delete("entity")
                tier[:value].delete(name.sub(/\[.*/, '')) if name
              end
              if (tier[:value].keys - ["id", "name", "type"]).size > 0
                myreport["details"] = tier[:value].clone
                append = PP.pp(tier[:value], '').gsub(/(^|\n)/, '\1'+indent)
              end
            else
              append = indent+"["+tier[:value].map { |v| MU::MommaCat.getChunkName(v, type_of).reverse.join("/") || v.to_s.light_blue }.join(", ")+"]"
              slack += " #{tier[:action].to_s}: "+tier[:value].map { |v| MU::MommaCat.getChunkName(v, type_of).reverse.join("/") || v.to_s }.join(", ")
            end
          else
            tier[:value] ||= "<nil>"
            if ![:removed].include?(tier[:action])
              myreport["slack"] += ". New #{tier[:field] ? "`"+tier[:field]+"`" : :value}: \*#{tier[:value]}\*"
            else
              myreport["slack"] += " (was \*#{tier[:value]}\*)"
            end
            append = tier[:value].to_s.bold
          end

          if append and !append.empty?
            myreport["plain"] += " =>\n  "+indent+append
            myreport["color"] += " =>\n  "+indent+append
          end

          report << myreport if tier[:action]
        end

        # Just because we've got changes at this level doesn't mean there aren't
        # more further down.
        tier.each_pair { |k, v|
          next if !(v.is_a?(Hash) or v.is_a?(Array))
          sub_report = crawlChangeReport(v, k, indent: indent+"  ")
          report.concat(sub_report) if sub_report and !sub_report.empty?
        }
      end

      report
    end


    def notifyChanges(deploy, report)
      snippet_threshold = (MU.muCfg['adopt_change_notify'] && MU.muCfg['adopt_change_notify']['slack_snippet_threshold']) || 5

      report.each_pair { |res_type, resources|
        shortclass, _cfg_name, _cfg_plural, _classname = MU::Cloud.getResourceNames(res_type, false)
        next if !shortclass # we don't really care about Mu metadata changes
        resources.each_pair { |name, data|
          if MU::MommaCat.getChunkName(data[:value], res_type).first.nil?
            symbol = if data[:action] == :added
              "+".green
            elsif data[:action] == :removed
              "-".red
            else
              "~".yellow
            end
            puts (symbol+" "+res_type+"["+name+"]")
          end

          noun = shortclass ? shortclass.to_s : res_type.capitalize
          verb = if data[:action]
            data[:action].to_s
          else
            "modified"
          end

          changes = crawlChangeReport(data.freeze, res_type)

          slacktext = "#{noun} \*#{name}\* was #{verb}"
          if data[:habitat]
            slacktext += " in \*#{data[:habitat]}\*"
          end
          snippets = []

          if [:added, :removed].include?(data[:action]) and data[:value]
            snippets << { text: "```"+JSON.pretty_generate(data[:value])+"```" }
          else
            changes.each { |c|
              slacktext += "\n • "+c["slack"]
              if c["details"]
                details = JSON.pretty_generate(c["details"])
                snippets << { text: "```"+JSON.pretty_generate(c["details"])+"```" }
              end
            }
          end

          changes.each { |c|
            puts c["color"]
          }
          puts ""

          if MU.muCfg['adopt_change_notify'] and MU.muCfg['adopt_change_notify']['slack']
            deploy.sendAdminSlack(slacktext, scrub_mu_isms: MU.muCfg['adopt_scrub_mu_isms'], snippets: snippets, noop: false)
          end

        }
      }

    end

    def scrubSchemaDefaults(conf_chunk, schema_chunk, depth = 0, type: nil)
      return if schema_chunk.nil?

      if !conf_chunk.nil? and schema_chunk["properties"].kind_of?(Hash) and conf_chunk.is_a?(Hash)
        deletia = []
        schema_chunk["properties"].each_pair { |key, subschema|
          next if !conf_chunk[key]
          shortclass, _cfg_name, _cfg_plural, _classname = MU::Cloud.getResourceNames(key, false)

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
            scrubSchemaDefaults(conf_chunk[key], subschema, depth+1, type: shortclass)
          end
        }
        deletia.each { |key| conf_chunk.delete(key) }
      elsif schema_chunk["type"] == "array" and conf_chunk.kind_of?(Array)
        conf_chunk.each { |item|
          # this bit only happens at the top-level key for a resource type, in
          # theory
          realschema = if type and schema_chunk["items"] and schema_chunk["items"]["properties"] and item["cloud"] and MU::Cloud.supportedClouds.include?(item['cloud'])

            _toplevel_required, cloudschema = MU::Cloud.resourceClass(item['cloud'], type).schema(self)

            newschema = schema_chunk["items"].dup
            newschema["properties"].merge!(cloudschema)
            newschema
          else
            schema_chunk["items"].dup
          end
          next if ["array", "object"].include?(realschema["type"])

          scrubSchemaDefaults(item, realschema, depth+1, type: type)
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
    def vacuum(bok, origin: nil, save: false, deploy: nil, copy_from: nil, keep_missing: false)

      globals = {
        'cloud' => {},
        'credentials' => {},
        'region' => {},
        'billing_acct' => {},
        'us_only' => {},
      }
      MU::Cloud.resource_types.values.each { |attrs|
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
            inject_metadata = save
            if obj.nil? and copy_from
              obj = copy_from.findLitterMate(type: attrs[:cfg_plural], name: resource['name'])
              if obj
                inject_metadata = true
                obj.intoDeploy(deploy, force: true)
              end
            end

            begin
              raise Incomplete if obj.nil?
              if inject_metadata
                deploydata = obj.notify
                deploy.notify(attrs[:cfg_plural], resource['name'], deploydata, triggering_node: obj)
              end
              new_cfg = resolveReferences(resource, deploy, obj)
              new_cfg.delete("cloud_id")
              cred_cfg = MU::Cloud.cloudClass(obj.cloud).credConfig(obj.credentials)
              if cred_cfg['region'] == new_cfg['region']
                new_cfg.delete('region')
              end
              if cred_cfg['default']
                new_cfg.delete('credentials')
                new_cfg.delete('habitat')
              end
              processed << new_cfg
            rescue Incomplete
              if keep_missing
                processed << resource
              else
                MU.log "#{attrs[:cfg_name]} #{resource['name']} didn't show up from findLitterMate", MU::WARN, details: deploy.original_config[attrs[:cfg_plural]].reject { |r| r['name'] != "" }
              end
            end
          }

          deploy.original_config[attrs[:cfg_plural]] = processed
          bok[attrs[:cfg_plural]] = processed
        end
      }

      # Pare out global values like +cloud+ or +region+ that appear to be
      # universal in the deploy we're creating.
      scrub_globals = Proc.new { |h, field|
        if h.is_a?(Hash)
          newhash = {}
          h.each_pair { |k, v|
            next if k == field
            newhash[k] = scrub_globals.call(v, field)
          }
          h = newhash
        elsif h.is_a?(Array)
          newarr = []
          h.each { |v|
            newarr << scrub_globals.call(v, field)
          }
          h = newarr.uniq
        end
        h
      }

      globals.each_pair { |field, counts|
        next if counts.size != 1
        bok[field] = counts.keys.first
        MU.log "Setting global default #{field} to #{bok[field]} (#{deploy.deploy_id})", MU::DEBUG
        MU::Cloud.resource_types.values.each { |attrs|
          if bok[attrs[:cfg_plural]]
            new_resources = []
            bok[attrs[:cfg_plural]].each { |resource|
              new_resources << scrub_globals.call(resource, field)
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
      mask_deploy_id = false

      check_deploy_id = Proc.new { |cfgblob|
        (deploy and
         (cfgblob.is_a?(MU::Config::Ref) or cfgblob.is_a?(Hash)) and
         cfgblob['deploy_id'] and
         cfgblob['deploy_id'] != deploy.deploy_id and
         @diff and
         @types_found_in[cfgblob['type']] and
         @types_found_in[cfgblob['type']].deploy_id == cfgblob['deploy_id']
        )
      }

      mask_deploy_id = check_deploy_id.call(cfg)

      if cfg.is_a?(MU::Config::Ref)
        if mask_deploy_id
          cfg.delete("deploy_id")
          cfg.delete("mommacat")
          cfg.kitten(deploy)
        else
          cfg.kitten(deploy) || cfg.kitten
        end

        hashcfg = cfg.to_h

        if cfg.kitten
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
        elsif hashcfg["id"] and !hashcfg["name"]
          hashcfg.delete("deploy_id")
        else
          raise Incomplete.new "Failed to resolve reference on behalf of #{parent}", details: hashcfg
        end
        hashcfg.delete("deploy_id") if hashcfg['deploy_id'] == deploy.deploy_id

        if parent and parent.config
          cred_cfg = MU::Cloud.cloudClass(parent.cloud).credConfig(parent.credentials)

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
        cfg = new_array.uniq
      end

      if mask_deploy_id or check_deploy_id.call(cfg)
        cfg.delete("deploy_id")
        MU.log "#{parent} in #{deploy.deploy_id} references something in #{@types_found_in[cfg['type']].deploy_id}, ditching extraneous deploy_id", MU::DEBUG, details: cfg.to_h
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
              if kitten['cloud_id'].nil?
                pp caller
                exit
              end
              next
            end

            MU.log "Inserting #{attrs[:cfg_name]} #{kitten['name']} (#{kitten['cloud_id']}) into stub deploy", MU::DEBUG, details: @scraped[typename][kitten['cloud_id']]

            @scraped[typename][kitten['cloud_id']].config!(kitten)

            deploy.addKitten(
              attrs[:cfg_plural],
              kitten['name'],
              @scraped[typename][kitten['cloud_id']],
              do_notify: true
            )
          }
        end
      }

      deploy
    end

    def self.deDuplicateName(kitten_cfg, res_class)
      orig_name = kitten_cfg['name'].dup
      if kitten_cfg['parent'] and kitten_cfg['parent'].respond_to?(:id) and kitten_cfg['parent'].id
        kitten_cfg['name'] = kitten_cfg['name']+"-"+kitten_cfg['parent'].id
      elsif kitten_cfg['project']
        kitten_cfg['name'] = kitten_cfg['name']+"-"+kitten_cfg['project']
      elsif kitten_cfg['region']
        kitten_cfg['name'] = kitten_cfg['name']+"-"+kitten_cfg['region']
      elsif kitten_cfg['cloud_id']
        kitten_cfg['name'] = kitten_cfg['name']+"-"+kitten_cfg['cloud_id'].gsub(/[^a-z0-9]/i, "-")
      else
        raise MU::Config::DuplicateNameError, "Saw duplicate #{res_class.cfg_name} name #{orig_name} and couldn't come up with a good way to differentiate them"
      end
    end

    # Go through everything we've scraped and update our mappings of cloud ids
    # and bare name fields, so that resources can reference one another
    # portably by name.
    def catalogResources
    end

  end
end
