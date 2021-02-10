# Copyright:: Copyright (c) 2018 eGlobalTech, Inc., all rights reserved
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
  class Config
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/database.rb
    class Database

      # Base configuration schema for a Database
      # @return [Hash]
      def self.schema
        {
        "type" => "object",
        "description" => "Create a dedicated database server.",
        "required" => ["name", "engine", "size", "cloud"],
        "additionalProperties" => false,
        "properties" => {
            "groomer" => {
                "type" => "string",
                "default" => MU::Config.defaultGroomer,
                "enum" => MU.supportedGroomers
            },
            "name" => {"type" => "string"},
            "scrub_mu_isms" => {
                "type" => "boolean",
                "default" => false,
                "description" => "When 'cloud' is set to 'CloudFormation,' use this flag to strip out Mu-specific artifacts (tags, standard userdata, naming conventions, etc) to yield a clean, source-agnostic template."
            },
            "region" => MU::Config.region_primitive,
            "db_family" => {"type" => "string"},
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => MU::Config.optional_tags_primitive,
            "alarms" => MU::Config::Alarm.inline,
            "add_firewall_rules" => {
              "type" => "array",
              "items" => MU::Config::FirewallRule.reference,
            },
            "read_replica_of" => reference,
            "ingress_rules" => {
              "type" => "array",
              "items" => MU::Config::FirewallRule.ruleschema
            },
            "engine_version" => {"type" => "string"},
            "engine" => {
                "enum" => ["mysql", "postgres", "oracle", "oracle-se1", "oracle-se2", "oracle-se", "oracle-ee", "sqlserver-ee", "sqlserver-se", "sqlserver-ex", "sqlserver-web", "aurora", "mariadb"],
                "type" => "string"
            },
            "add_cluster_node" => {
              "type" => "boolean",
              "description" => "Internal use",
              "default" => false
            },
            "member_of_cluster" => MU::Config::Ref.schema(type: "databases", desc: "Internal use"),
            "dns_records" => MU::Config::DNSZone.records_primitive(need_target: false, default_type: "CNAME", need_zone: true, embedded_type: "database"),
            "dns_sync_wait" => {
                "type" => "boolean",
                "description" => "Wait for DNS record to propagate in DNS Zone.",
                "default" => true
            },
            "size" => { # XXX this is AWS-specific, and also we should implement an API check like we do for Server and ServerPool
              "pattern" => "^db\.(t|m|c|i|g|r|hi|hs|cr|cg|cc){1,2}[0-9]\\.(micro|small|medium|[248]?x?large)$",
              "type" => "string",
              "description" => "The Amazon RDS instance type to use when creating this database instance.",
            },
            "storage" => {
              "type" => "integer",
              "description" => "Storage space for this database instance (GB).",
              "default" => 20
            },
            "run_sql_on_deploy" => {
              "type" => "array",
              "minItems" => 1,
              "items" => {
                "description" => "Arbitrary SQL commands to run after the database is fully configred (PostgreSQL databases only).",
                "type" => "string"
              }
            },
            "port" => {"type" => "integer"},
            "vpc" => MU::Config::VPC.reference(MU::Config::VPC::MANY_SUBNETS, MU::Config::VPC::NAT_OPTS, "all_public"),
            "publicly_accessible" => {
                "type" => "boolean"
            },
            "multi_az_on_create" => {
                "type" => "boolean",
                "description" => "Enable high availability when the database instance is created",
                "default" => false
            },
            "multi_az_on_deploy" => {
                "type" => "boolean",
                "description" => "See multi_az_on_groom", 
                "default" => false
            },
            "multi_az_on_groom" => {
                "type" => "boolean",
                "description" => "Enable high availability after the database instance is created. This may make deployments based on creation_style other then 'new' faster.",
                "default" => false
            },
            "backup_retention_period" => {
                "type" => "integer",
                "default" => 1,
                "description" => "The number of days to retain an automatic database snapshot. If set to 0 and deployment is multi-az will be overridden to 35"
            },
            "preferred_backup_window" => {
                "type" => "string",
                "default" => "05:00-05:30",
                "description" => "The preferred time range to perform automatic database backups."
            },
            "preferred_maintenance_window" => {
                "type" => "string",
                "description" => "The preferred data/time range to perform database maintenance. Ex. Sun:02:00-Sun:03:00"
            },
            "iops" => {
                "type" => "integer",
                "description" => "The amount of IOPS to allocate to Provisioned IOPS (io1) volumes. Increments of 1,000"
            },
            "auto_minor_version_upgrade" => {
                "type" => "boolean",
                "default" => true
            },
            "allow_major_version_upgrade" => {
                "type" => "boolean",
                "default" => false
            },
            "storage_encrypted" => {
                "type" => "boolean",
                "default" => false
            },
            "creation_style" => {
              "type" => "string",
              "enum" => ["existing", "new", "new_snapshot", "existing_snapshot", "point_in_time"],
              "description" => "+new+ creates a pristine database instance; +existing+ clones an existing database instance; +new_snapshot+ creates a snapshot of an existing database, then creates a new instance from that snapshot; +existing_snapshot+ creates database from a pre-existing snapshot; +point_in_time+ create database from point in time backup of an existing database. All styles other than +new+ require that +identifier+ or +source+ be set.",
              "default" => "new"
            },
            "identifier" => {
              "type" => "string",
              "description" => "Cloud id of a source database to use for creation styles other than +new+; use +source+ for more sophisticated resource references."
            },
            "source" => MU::Config::Ref.schema(type: "databases", "desc": "Reference a source database to use for +creation_style+ settings +existing+, +new_snapshot+, +existing_snapshot+, or +point_in_time+."),
            "master_user" => {
              "type" => "string",
              "description" => "Set master user name for this database instance; if not specified a random username will be generated"
            },
            "restore_time" => {
              "type" => "string",
              "description" => "Must either be set to 'latest' or date/time value in the following format: 2015-09-12T22:30:00Z. Applies only to point_in_time creation_style",
              "default" => "latest"
            },
            "create_read_replica" => {
              "type" => "boolean",
              "default" => false
            },
            "read_replica_region" => {
              "type" => "string",
              "description" => "Put read-replica in a particular region, other than the region of the source database."
            },
            "cluster_node_count" => {
              "type" => "integer",
              "description" => "The number of database instances to add to a database cluster. This only applies to aurora",
              "default" => 2
            },
            "create_cluster" => {
              "type" => "boolean",
                "description" => "Create a database cluster instead of a standalone database.",
                "default_if" => [
                  {
                    "key_is" => "engine",
                    "value_is" => "aurora-mysql",
                    "set" => true
                  }
                ]
            },
            "auth_vault" => {
                "type" => "object",
                "additionalProperties" => false,
                "required" => ["vault", "item"],
                "description" => "The vault storing the password of the database master user. a random password will be generated if not specified.",
                "properties" => {
                    "vault" => {
                        "type" => "string",
                        "default" => "database",
                        "description" => "The vault where these credentials reside"
                    },
                    "item" => {
                        "type" => "string",
                        "default" => "credentials",
                        "description" => "The vault item where these credentials reside"
                    },
                    "password_field" => {
                        "type" => "string",
                        "default" => "password",
                        "description" => "The field within the Vault item where the password for database master user is stored"
                    }
                }
            }
        }
        }
      end

      # Schema block for other resources to use when referencing a sibling Database
      # @return [Hash]
      def self.reference
        schema_aliases = [
          { "db_id" => "id" },
          { "db_name" => "name" }
        ]
        MU::Config::Ref.schema(schema_aliases, type: "databases")
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::databases}, bare and unvalidated.
      # @param db [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(db, configurator)
        ok = true
        read_replicas = []
        cluster_nodes = []

        db['ingress_rules'] ||= []
        if db['auth_vault'] && !db['auth_vault'].empty?
          groomclass = MU::Groomer.loadGroomer(db['groomer'])
          if db['password']
            MU.log "Database password and database auth_vault can't both be used.", MU::ERR
            ok = false
          end

          begin
            item = groomclass.getSecret(vault: db['auth_vault']['vault'], item: db['auth_vault']['item'])
            if !item.has_key?(db['auth_vault']['password_field'])
              MU.log "No value named password_field in Chef Vault #{db['auth_vault']['vault']}:#{db['auth_vault']['item']}, will use an auto generated password.", MU::NOTICE
              db['auth_vault'].delete(field)
            end
          rescue MuError
            ok = false
          end
        end

        if db["identifier"]
          if db["source"]
            if db["source"]["id"] != db["identifier"]
              MU.log "Database #{db['name']} specified identifier '#{db["identifier"]}' with a source parameter that doesn't match", MU::ERR, db["source"]
              ok = false
            end
          else
            db["source"] = MU::Config::Ref.get(
              id: db["identifier"],
              cloud: db["cloud"],
              credentials: db["credentials"],
              type: "databases"
            )
          end
          db.delete("identifier")
        end

        if db["storage"].nil? and db["creation_style"] == "new" and !db['create_cluster']
          MU.log "Must provide a value for 'storage' when creating a new database.", MU::ERR, details: db
          ok = false
        end

        if db["create_cluster"]
          if db["cluster_node_count"] < 1
            MU.log "You are trying to create a database cluster but cluster_node_count is set to #{db["cluster_node_count"]}", MU::ERR
            ok = false
          end

          MU.log "'storage' is not supported when creating a database cluster, disregarding", MU::NOTICE if db["storage"]
          MU.log "'multi_az_on_create' and multi_az_on_deploy are not supported when creating a database cluster, disregarding", MU::NOTICE if db["storage"] if db["multi_az_on_create"] || db["multi_az_on_deploy"]
        end

        if db["size"].nil?
          MU.log "You must specify 'size' when creating a new database or a database from a snapshot.", MU::ERR
          ok = false
        end

        if db["creation_style"] == "new" and db["storage"].nil?
          unless db["create_cluster"]
            MU.log "You must specify 'storage' when creating a new database.", MU::ERR
            ok = false
          end
        end

        if db["creation_style"] == "point_in_time" && db["restore_time"].nil?
          ok = false
          MU.log "Database '#{db['name']}' must provide restore_time when creation_style is point_in_time", MU::ERR
        end

        if %w{existing new_snapshot existing_snapshot point_in_time}.include?(db["creation_style"])
          if db["source"].nil?
            ok = false
            MU.log "Database '#{db['name']}' needs existing database/snapshot, but no identifier or source was specified", MU::ERR
          end
        end

        if !db["run_sql_on_deploy"].nil? and (db["engine"] != "postgres" and db["engine"] != "mysql")
          ok = false
          MU.log "Running SQL on deploy is only supported for postgres and mysql databases", MU::ERR
        end

        if !db["vpc"].nil?
          if db["vpc"]["subnet_pref"] and !db["vpc"]["subnets"]
            if db["vpc"]["subnet_pref"] == "public"
              db["vpc"]["subnet_pref"] = "all_public"
            elsif db["vpc"]["subnet_pref"] == "private"
              db["vpc"]["subnet_pref"] = "all_private"
            elsif %w{all any}.include? db["vpc"]["subnet_pref"]
              MU.log "subnet_pref #{db["vpc"]["subnet_pref"]} is not supported for database instance.", MU::ERR
              ok = false
            end
          end
        end

        # Automatically manufacture another database object, which will serve
        # as a read replica of this one, if we've set create_read_replica.
        if db['create_read_replica']
          if db['create_cluster']
            db["create_read_replica"] = false
            MU.log "Ignoring extraneous create_read_replica flag on database cluster #{db['name']}", MU::WARN
          else
            replica = Marshal.load(Marshal.dump(db))
            replica['name'] = db['name']+"-replica"
            replica["credentials"] = db["credentials"]
            replica['create_read_replica'] = false
            replica["create_cluster"] = false
            replica["region"] = db['read_replica_region']
            if db['region'] != replica['region']
              replica.delete("vpc")
            end
            replica['read_replica_of'] = {
              "name" => db['name'],
              "cloud" => db['cloud'],
              "region" => db['region'],
              "credentials" => db['credentials'],
            }
            MU::Config.addDependency(replica, db["name"], "database", their_phase: "groom")
            read_replicas << replica
          end
        end

        # Do database cluster nodes the same way we do read replicas, by
        # duplicating the declaration of the master as a new first-class
        # resource and tweaking it.
        if db["create_cluster"] and db['cluster_mode'] != "serverless"
          db["add_cluster_node"] = false
          (1..db["cluster_node_count"]).each{ |num|
            node = Marshal.load(Marshal.dump(db))
            node["name"] = "#{db['name']}-#{num}"
            node["credentials"] = db["credentials"]
            node["create_cluster"] = false
            node["create_read_replica"] = false
            node["creation_style"] = "new"
            node["add_cluster_node"] = true
            node["member_of_cluster"] = {
              "name" => db['name'],
              "cloud" => db['cloud'],
              "region" => db['region'],
              "credentials" => db['credentials'],
              "type" => "databases"
            }
            # AWS will figure out for us which database instance is the writer/master so we can create all of them concurrently.
            MU::Config.addDependency(node, db["name"], "database", their_phase: "groom")
            cluster_nodes << node

           # Alarms are set on each DB cluster node, not on the cluster itself,
           # so futz any alarm declarations accordingly.
            if node.has_key?("alarms") && !node["alarms"].empty?
              node["alarms"].each{ |alarm|
                alarm["name"] = "#{alarm["name"]}-#{node["name"]}"
              }
            end
          }

        end

        if !db['read_replica_of'].nil?
          rr = MU::Config::Ref.get(db['read_replica_of'])
          if rr.name and !rr.deploy_id
            db['dependencies'] << { "name" => rr.name, "type" => "database" }
            MU::Config.addDependency(db, rr.name, "database")
          elsif !rr.kitten
            MU.log "Couldn't resolve Database reference to a unique live Database in #{db['name']}", MU::ERR, details: rr
            ok = false
          end
        elsif db["member_of_cluster"]
          cluster = MU::Config::Ref.get(db["member_of_cluster"])
          if cluster['name']
            if !configurator.haveLitterMate?(cluster['name'], "databases")
              MU.log "Database cluster node #{db['name']} references sibling source #{cluster['name']}, but I have no such database", MU::ERR
              ok = false
            end
          else
            if !cluster.kitten
              MU.log "Couldn't resolve Database reference to a unique live Database in #{db['name']}", MU::ERR, details: cluster.to_h
              ok = false
            end
          end
        end

        if db["source"] 
          
          if db["source"]["name"] and
             !db["source"]["deploy_id"] and
             configurator.haveLitterMate?(db["source"]["name"], "databases")
            MU::Config.addDependency(db, db["source"]["name"], "database")
          end
          db["source"]["cloud"] ||= db["cloud"]
        end

        db['dependencies'].uniq!

        read_replicas.each { |new_replica|
          ok = false if !configurator.insertKitten(new_replica, "databases")
        }
        cluster_nodes.each { |member|
          ok = false if !configurator.insertKitten(member, "databases")
        }

        ok
      end

    end
  end
end
