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

    # Accessor for our Basket of Kittens schema definition, with various
    # cloud-specific details merged so we can generate documentation for them.
    def self.docSchema
      docschema = Marshal.load(Marshal.dump(@@schema))
      only_children = {}
      MU::Cloud.resource_types.each_pair { |classname, attrs|
        MU::Cloud.supportedClouds.each { |cloud|
          begin
            require "mu/providers/#{cloud.downcase}/#{attrs[:cfg_name]}"
          rescue LoadError
            next
          end
          _required, res_schema = MU::Cloud.resourceClass(cloud, classname).schema(self)
          docschema["properties"][attrs[:cfg_plural]]["items"]["description"] ||= ""
          docschema["properties"][attrs[:cfg_plural]]["items"]["description"] += "\n#\n# `#{cloud}`: "+res_class.quality
          res_schema.each { |key, cfg|
            if !docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]
              only_children[attrs[:cfg_plural]] ||= {}
              only_children[attrs[:cfg_plural]][key] ||= {}
              only_children[attrs[:cfg_plural]][key][cloud] = cfg
            end
          }
        }
      }

      # recursively chase down description fields in arrays and objects of our
      # schema and prepend stuff to them for documentation
      def self.prepend_descriptions(prefix, cfg)
        cfg["prefix"] = prefix
        if cfg["type"] == "array" and cfg["items"]
          cfg["items"] = prepend_descriptions(prefix, cfg["items"])
        elsif cfg["type"] == "object" and cfg["properties"]
          cfg["properties"].keys.each { |key|
            cfg["properties"][key] = prepend_descriptions(prefix, cfg["properties"][key])
          }
        end
        cfg
      end

      MU::Cloud.resource_types.each_pair { |classname, attrs|
        MU::Cloud.supportedClouds.each { |cloud|
          res_class = nil
          begin
            res_class = MU::Cloud.resourceClass(cloud, classname)
          rescue MU::Cloud::MuCloudResourceNotImplemented
            next
          end
          required, res_schema = res_class.schema(self)
          next if required.size == 0 and res_schema.size == 0
          res_schema.each { |key, cfg|
            cfg["description"] ||= ""
            if !cfg["description"].empty?
              cfg["description"] = "\n# +"+cloud.upcase+"+: "+cfg["description"]
            end
            if docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]
              schemaMerge(docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key], cfg, cloud)
              docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]["description"] ||= ""
              docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]["description"] += "\n"+(cfg["description"].match(/^#/) ? "" : "# ")+cfg["description"]
              MU.log "Munging #{cloud}-specific #{classname.to_s} schema into BasketofKittens => #{attrs[:cfg_plural]} => #{key}", MU::DEBUG, details: docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]
            else
              if only_children[attrs[:cfg_plural]][key]
                prefix = only_children[attrs[:cfg_plural]][key].keys.map{ |x| x.upcase }.join(" & ")+" ONLY"
                cfg["description"].gsub!(/^\n#/, '') # so we don't leave the description blank in the "optional parameters" section
                cfg = prepend_descriptions(prefix, cfg)
              end

              docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key] = cfg
            end
            docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]["clouds"] = {}
            docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]["clouds"][cloud] = cfg
          }

          docschema['required'].concat(required)
          docschema['required'].uniq!
        }
      }

      docschema
    end

    # Output the dependencies of this BoK stack as a directed acyclic graph.
    # Very useful for debugging.
    def visualizeDependencies
      # GraphViz won't like MU::Config::Tail, pare down to plain Strings
      config = MU::Config.stripConfig(@config)
      begin
        g = GraphViz.new(:G, :type => :digraph)
        # Generate a GraphViz node for each resource in this stack
        nodes = {}
        MU::Cloud.resource_types.each_pair { |classname, attrs|
          nodes[attrs[:cfg_name]] = {}
          if config.has_key?(attrs[:cfg_plural]) and config[attrs[:cfg_plural]]
            config[attrs[:cfg_plural]].each { |resource|
              nodes[attrs[:cfg_name]][resource['name']] = g.add_nodes("#{classname}: #{resource['name']}")
            }
          end
        }
        # Now add edges corresponding to the dependencies they list
        MU::Cloud.resource_types.values.each { |attrs|
          if config.has_key?(attrs[:cfg_plural]) and config[attrs[:cfg_plural]]
            config[attrs[:cfg_plural]].each { |resource|
              if resource.has_key?("dependencies")
                me = nodes[attrs[:cfg_name]][resource['name']]
                resource["dependencies"].each { |dep|
                  parent = nodes[dep['type']][dep['name']]
                  g.add_edges(me, parent)
                }
              end
            }
          end
        }
        # Spew some output?
        MU.log "Emitting dependency graph as /tmp/#{config['appname']}.jpg", MU::NOTICE
        g.output(:jpg => "/tmp/#{config['appname']}.jpg")
      rescue StandardError => e
        MU.log "Failed to generate GraphViz dependency tree: #{e.inspect}. This should only matter to developers.", MU::WARN, details: e.backtrace
      end
    end

    # Generate a documentation-friendly dummy Ruby class for our mu.yaml main
    # config.
    def self.emitConfigAsRuby
      example = %Q{---
public_address: 1.2.3.4
mu_admin_email: egtlabs@eglobaltech.com
mu_admin_name: Joe Schmoe
mommacat_port: 2260
banner: My Example Mu Master
mu_repository: git://github.com/cloudamatic/mu.git
repos:
- https://github.com/cloudamatic/mu_demo_platform
allow_invade_foreign_vpcs: true
ansible_dir:
aws:
  egtdev:
    region: us-east-1
    log_bucket_name: egt-mu-log-bucket
    default: true
    name: egtdev
  personal:
    region: us-east-2
    log_bucket_name: my-mu-log-bucket
    name: personal
  google:
    egtlabs:
      project: egt-labs-admin
      credentials_file: /opt/mu/etc/google.json
      region: us-east4
      log_bucket_name: hexabucket-761234
      default: true
}
      mu_yaml_schema = eval(%Q{
$NOOP = true
load "#{MU.myRoot}/bin/mu-configure"
$CONFIGURABLES
})
      return if mu_yaml_schema.nil? or !mu_yaml_schema.is_a?(Hash)
      muyamlpath = "#{MU.myRoot}/modules/mu/mu.yaml.rb"
      MU.log "Converting mu.yaml schema to Ruby objects in #{muyamlpath}"
      muyaml_rb = File.new(muyamlpath, File::CREAT|File::TRUNC|File::RDWR, 0644)
      muyaml_rb.puts "# Configuration schema for mu.yaml. See also {https://github.com/cloudamatic/mu/wiki/Configuration the Mu wiki}."
      muyaml_rb.puts "#"
      muyaml_rb.puts "# Example:"
      muyaml_rb.puts "#"
      muyaml_rb.puts "# <pre>"
      example.split(/\n/).each { |line|
        muyaml_rb.puts "#      "+line+"    " # markdooooown
      }
      muyaml_rb.puts "# </pre>"
      muyaml_rb.puts "module MuYAML"
      muyaml_rb.puts "\t# The configuration file format for Mu's main config file."
      MU::Config.printMuYamlSchema(muyaml_rb, [], { "subtree" => mu_yaml_schema })
      muyaml_rb.puts "end"
      muyaml_rb.close
    end

    # Take the schema we've defined and create a dummy Ruby class tree out of
    # it, basically so we can leverage Yard to document it.
    def self.emitSchemaAsRuby
      kittenpath = "#{MU.myRoot}/modules/mu/kittens.rb"
      MU.log "Converting Basket of Kittens schema to Ruby objects in #{kittenpath}"
      kitten_rb = File.new(kittenpath, File::CREAT|File::TRUNC|File::RDWR, 0644)
      kitten_rb.puts "### THIS FILE IS AUTOMATICALLY GENERATED, DO NOT EDIT ###"
      kitten_rb.puts "#"
      kitten_rb.puts "#"
      kitten_rb.puts "#"
      kitten_rb.puts "module MU"
      kitten_rb.puts "class Config"
      kitten_rb.puts "\t# The configuration file format for Mu application stacks."
      self.printSchema(kitten_rb, ["BasketofKittens"], MU::Config.docSchema)
      kitten_rb.puts "end"
      kitten_rb.puts "end"
      kitten_rb.close

    end

    # Emit our Basket of Kittens schema in a format that YARD can comprehend
    # and turn into documentation.
    def self.printSchema(kitten_rb, class_hierarchy, schema, in_array = false, required = false, prefix: nil)
      return if schema.nil?

      if schema["type"] == "object"
        printme = []

        if !schema["properties"].nil?
          # order sub-elements by whether they're required, so we can use YARD's
          # grouping tags on them
          if !schema["required"].nil? and schema["required"].size > 0
            prop_list = schema["properties"].keys.sort_by { |name|
              schema["required"].include?(name) ? 0 : 1
            }
          else
            prop_list = schema["properties"].keys
          end
          req = false
          printme << "# @!group Optional parameters" if schema["required"].nil? or schema["required"].size == 0
          prop_list.each { |name|
            prop = schema["properties"][name]

            if class_hierarchy.size == 1

              _shortclass, cfg_name, cfg_plural, _classname = MU::Cloud.getResourceNames(name, false)
              if cfg_name
                example_path = MU.myRoot+"/modules/mu/config/"+cfg_name+".yml"
                if File.exist?(example_path)
                  example = "#\n# Examples:\n#\n"
                  # XXX these variables are all parameters from the BoKs in
                  # modules/tests. A really clever implementation would read
                  # and parse them to get default values, perhaps, instead of
                  # hard-coding them here.
                  instance_type = "t2.medium"
                  db_size = "db.t2.medium"
                  vpc_name = "some_vpc"
                  logs_name = "some_loggroup"
                  queues_name = "some_queue"
                  server_pools_name = "some_server_pool"
                  ["simple", "complex"].each { |complexity|
                    erb = ERB.new(File.read(example_path), nil, "<>")
                    example += "#      !!!yaml\n"
                    example += "#      ---\n"
                    example += "#      appname: #{complexity}\n"
                    example += "#      #{cfg_plural}:\n"
                    firstline = true
                    erb.result(binding).split(/\n/).each { |l|
                      l.chomp!
                      l.sub!(/#.*/, "") if !l.match(/#(?:INTERNET|NAT|DENY)/)
                      next if l.empty? or l.match(/^\s+$/)
                      if firstline
                        l = "- "+l
                        firstline = false
                      else
                        l = "  "+l
                      end
                      example += "#      "+l+"    "+"\n"
                    }
                    example += "# &nbsp;\n#\n" if complexity == "simple"
                  }
                  schema["properties"][name]["items"]["description"] ||= ""
                  if !schema["properties"][name]["items"]["description"].empty?
                    schema["properties"][name]["items"]["description"] += "\n"
                  end
                  schema["properties"][name]["items"]["description"] += example
                end
              end
            end

            if !schema["required"].nil? and schema["required"].include?(name)
              printme << "# @!group Required parameters" if !req
              req = true
            else
              if req
                printme << "# @!endgroup"
                printme << "# @!group Optional parameters"
              end
              req = false
            end

            printme << self.printSchema(kitten_rb, class_hierarchy+ [name], prop, false, req, prefix: schema["prefix"])
          }
          printme << "# @!endgroup"
        end

        tabs = 1
        class_hierarchy.each { |classname|
          if classname == class_hierarchy.last and !schema['description'].nil?
            kitten_rb.puts ["\t"].cycle(tabs).to_a.join('') + "# #{schema['description']}\n"
          end
          kitten_rb.puts ["\t"].cycle(tabs).to_a.join('') + "class #{classname}"
          tabs = tabs + 1
        }
        printme.each { |lines|
          if !lines.nil? and lines.is_a?(String)
            lines.lines.each { |line|
              kitten_rb.puts ["\t"].cycle(tabs).to_a.join('') + line
            }
          end
        }

        i = class_hierarchy.size
        until i == 0 do
          tabs = tabs - 1
          kitten_rb.puts ["\t"].cycle(tabs).to_a.join('') + "end"
          i -= 1
        end

        # And now that we've dealt with our children, pass our own rendered
        # commentary back up to our caller.
        name = class_hierarchy.last
        if in_array
          type = "Array<#{class_hierarchy.join("::")}>"
        else
          type = class_hierarchy.join("::")
        end

        docstring = "\n"
        docstring = docstring + "# **REQUIRED**\n" if required
        docstring = docstring + "# **"+schema["prefix"]+"**\n" if schema["prefix"]
        docstring = docstring + "# #{schema['description'].gsub(/\n/, "\n#")}\n" if !schema['description'].nil?
        docstring = docstring + "#\n"
        docstring = docstring + "# @return [#{type}]\n"
        docstring = docstring + "# @see #{class_hierarchy.join("::")}\n"
        docstring = docstring + "attr_accessor :#{name}"
        return docstring

      elsif schema["type"] == "array"
        return self.printSchema(kitten_rb, class_hierarchy, schema['items'], true, required, prefix: prefix)
      else
        name = class_hierarchy.last
        if schema['type'].nil?
          MU.log "Couldn't determine schema type in #{class_hierarchy.join(" => ")}", MU::WARN, details: schema
          return nil
        end
        if in_array
          type = "Array<#{schema['type'].capitalize}>"
        else
          type = schema['type'].capitalize
        end
        docstring = "\n"

        prefixes = []
        prefixes << "# **REQUIRED**" if required and schema['default'].nil?
        prefixes << "# **"+schema["prefix"]+"**" if schema["prefix"]
        prefixes << "# **Default: `#{schema['default']}`**" if !schema['default'].nil?
        if !schema['enum'].nil? and !schema["enum"].empty?
          prefixes << "# **Must be one of: `#{schema['enum'].join(', ')}`**"
        elsif !schema['pattern'].nil?
          # XXX unquoted regex chars confuse the hell out of YARD. How do we
          # quote {}[] etc in YARD-speak?
          prefixes << "# **Must match pattern `#{schema['pattern'].gsub(/\n/, "\n#")}`**"
        end

        if prefixes.size > 0
          docstring += prefixes.join(",\n")
          if schema['description'] and schema['description'].size > 1
            docstring += " - "
          end
          docstring += "\n"
        end

        docstring = docstring + "# #{schema['description'].gsub(/\n/, "\n#")}\n" if !schema['description'].nil?
        docstring = docstring + "#\n"
        docstring = docstring + "# @return [#{type}]\n"
        docstring = docstring + "attr_accessor :#{name}"

        return docstring
      end
    end

    # Emit our mu.yaml schema in a format that YARD can comprehend and turn into
    # documentation.
    def self.printMuYamlSchema(muyaml_rb, class_hierarchy, schema, in_array = false, required = false)
      return if schema.nil?
      if schema["subtree"]
        printme = Array.new
        # order sub-elements by whether they're required, so we can use YARD's
        # grouping tags on them
        have_required = schema["subtree"].keys.any? { |k| schema["subtree"][k]["required"] }
        prop_list = schema["subtree"].keys.sort { |a, b|
          if schema["subtree"][a]["required"] and !schema["subtree"][b]["required"]
            -1
          elsif !schema["subtree"][a]["required"] and schema["subtree"][b]["required"]
            1
          else
            a <=> b
          end
        }

        req = false
        printme << "# @!group Optional parameters" if !have_required
        prop_list.each { |name|
          prop = schema["subtree"][name]
          if prop["required"]
            printme << "# @!group Required parameters" if !req
            req = true
          else
            if req
              printme << "# @!endgroup"
              printme << "# @!group Optional parameters"
            end
            req = false
          end

          printme << self.printMuYamlSchema(muyaml_rb, class_hierarchy+ [name], prop, false, req)
        }
        printme << "# @!endgroup"

        desc = (schema['desc'] || schema['title'])

        tabs = 1
        class_hierarchy.each { |classname|
          if classname == class_hierarchy.last and desc
            muyaml_rb.puts ["\t"].cycle(tabs).to_a.join('') + "# #{desc}\n"
          end
          muyaml_rb.puts ["\t"].cycle(tabs).to_a.join('') + "class #{classname}"
          tabs = tabs + 1
        }
        printme.each { |lines|
          if !lines.nil? and lines.is_a?(String)
            lines.lines.each { |line|
              muyaml_rb.puts ["\t"].cycle(tabs).to_a.join('') + line
            }
          end
        }

#        class_hierarchy.each { |classname|
#          tabs = tabs - 1
#          muyaml_rb.puts ["\t"].cycle(tabs).to_a.join('') + "end"
#        }
        i = class_hierarchy.size
        until i == 0 do
          tabs = tabs - 1
          muyaml_rb.puts ["\t"].cycle(tabs).to_a.join('') + "end"
          i -= 1
        end

        # And now that we've dealt with our children, pass our own rendered
        # commentary back up to our caller.
        name = class_hierarchy.last
        if in_array
          type = "Array<#{class_hierarchy.join("::")}>"
        else
          type = class_hierarchy.join("::")
        end

        docstring = "\n"
        docstring = docstring + "# **REQUIRED**\n" if required
#        docstring = docstring + "# **"+schema["prefix"]+"**\n" if schema["prefix"]
        docstring = docstring + "# #{desc.gsub(/\n/, "\n#")}\n" if desc
        docstring = docstring + "#\n"
        docstring = docstring + "# @return [#{type}]\n"
        docstring = docstring + "# @see #{class_hierarchy.join("::")}\n"
        docstring = docstring + "attr_accessor :#{name}"
        return docstring

      else
        in_array = schema["array"]
        name = class_hierarchy.last
        type = if schema['boolean']
          "Boolean"
        else
          "String"
        end
        if in_array
          type = "Array<#{type}>"
        end
        docstring = "\n"

        prefixes = []
        prefixes << "# **REQUIRED**" if schema["required"] and schema['default'].nil?
#        prefixes << "# **"+schema["prefix"]+"**" if schema["prefix"]
        prefixes << "# **Default: `#{schema['default']}`**" if !schema['default'].nil?
        if !schema['pattern'].nil?
          # XXX unquoted regex chars confuse the hell out of YARD. How do we
          # quote {}[] etc in YARD-speak?
          prefixes << "# **Must match pattern `#{schema['pattern'].to_s.gsub(/\n/, "\n#")}`**"
        end

        desc = (schema['desc'] || schema['title'])
        if prefixes.size > 0
          docstring += prefixes.join(",\n")
          if desc and desc.size > 1
            docstring += " - "
          end
          docstring += "\n"
        end

        docstring = docstring + "# #{desc.gsub(/\n/, "\n#")}\n" if !desc.nil?
        docstring = docstring + "#\n"
        docstring = docstring + "# @return [#{type}]\n"
        docstring = docstring + "attr_accessor :#{name}"

        return docstring
      end
    end

  end #class
end #module
