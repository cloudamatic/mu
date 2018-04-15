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
    class Database

      def self.schema
        {
        "type" => "object",
        "title" => "database",
        "description" => "Create a dedicated database server.",
        "required" => ["name", "engine", "size", "cloud"],
        "additionalProperties" => false,
        "properties" => {
            "cloud" => MU::Config.cloud_primitive,
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
            "optional_tags" => {
                "type" => "boolean",
                "description" => "Tag the resource with our optional tags (MU-HANDLE, MU-MASTER-NAME, MU-OWNER). Defaults to true",
                "default" => true
            },
            "alarms" => MU::Config::Alarm.inline,
            "engine_version" => {"type" => "string"},
            "add_firewall_rules" => MU::Config::FirewallRule.reference,
            "read_replica_of" => reference,
            "ingress_rules" => {
                "type" => "array",
                "items" => MU::Config::FirewallRule.ruleschema
            },
            "engine" => {
                "enum" => ["mysql", "postgres", "oracle-se1", "oracle-se2", "oracle-se", "oracle-ee", "sqlserver-ee", "sqlserver-se", "sqlserver-ex", "sqlserver-web", "aurora", "mariadb"],
                "type" => "string"
            },
            "add_cluster_node" => {
              "type" => "boolean",
              "description" => "Internal use",
              "default" => false
            },
            "member_of_cluster" => {
              "description" => "Internal use",
              "type" => "object"
            },
            "dns_records" => MU::Config::DNSZone.records_primitive(need_target: false, default_type: "CNAME", need_zone: true),
            "dns_sync_wait" => {
                "type" => "boolean",
                "description" => "Wait for DNS record to propagate in DNS Zone.",
                "default" => true
            },
            "dependencies" => MU::Config.dependencies_primitive,
            "size" => { # XXX this is AWS-specific, and also we should implement an API check like we do for Server and ServerPool
              "pattern" => "^db\.(t|m|c|i|g|r|hi|hs|cr|cg|cc){1,2}[0-9]\\.(micro|small|medium|[248]?x?large)$",
              "type" => "string",
              "description" => "The Amazon RDS instance type to use when creating this database instance.",
            },
            "storage" => {
              "type" => "integer",
              "description" => "Storage space for this database instance (GB)."
            },
            "storage_type" => {
                "enum" => ["standard", "gp2", "io1"],
                "type" => "string",
                "default" => "gp2"
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
                "type" => "boolean",
                "default" => true
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
                "description" => "'new' - create a pristine database instances; 'existing' - use an existing database instance; 'new_snapshot' - create a snapshot of an existing database, and create a new one from that snapshot; 'existing_snapshot' - create database from an existing snapshot.; 'point_in_time' - create database from point in time backup of an existing database",
                "default" => "new"
            },
            "identifier" => {
                "type" => "string",
                "description" => "For any creation_style other than 'new' this parameter identifies the database to use. In the case of new_snapshot or point_in_time this is the identifier of an existing database instance; in the case of existing_snapshot this is the identifier of the snapshot."
            },
            "master_user" => {
              "type" => "string",
              "description" => "Set master user name for this database instance; if not specified a random username will be generated"
            },
            "restore_time" => {
              "type" => "string",
              "description" => "Must either be set to 'latest' or date/time value in the following format: 2015-09-12T22:30:00Z. Applies only to point_in_time creation_style"
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
              "default_if" => [
                {
                  "key_is" => "engine",
                  "value_is" => "aurora",
                  "set" => 1
                }
              ]
            },
            "create_cluster" => {
              "type" => "boolean",
                "description" => "Rather to create a database cluster. This only applies to aurora",
                "default_if" => [
                  {
                    "key_is" => "engine",
                    "value_is" => "aurora",
                    "set" => true
                  }
                ]
            },
            "parameter_group_family" => {
                "type" => "String",
                "enum" => [
                  "postgres9.6", "postgres9.5", "postgres9.4", "postgres9.3", 
                  "mysql5.1", "mysql5.5", "mysql5.6", "mysql5.7", 
                  "oracle-ee-11.2", "oracle-ee-12.1", "oracle-se-11.2", "oracle-se-12.1", "oracle-se1-11.2", "oracle-se1-12.1",
                  "sqlserver-ee-10.5", "sqlserver-ee-11.0", "sqlserver-ee-12.0", "sqlserver-ex-10.5", "sqlserver-ex-11.0", "sqlserver-ex-12.0", "sqlserver-se-10.5", "sqlserver-se-11.0", "sqlserver-se-12.0", "sqlserver-web-10.5", "sqlserver-web-11.0", "sqlserver-web-12.0", 
                  "aurora5.6", "mariadb-10.0", "mariadb-10.1"
                ],
                "description" => "The database family to create the DB Parameter Group for. The family type must be the same type as the database major version - eg if you set engine_version to 9.4.4 the db_family must be set to postgres9.4."
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

      def self.reference
        {
          "type" => "object",
          "description" => "Incorporate a database object",
          "minProperties" => 1,
          "additionalProperties" => false,
          "properties" => {
            "db_id" => {"type" => "string"},
            "db_name" => {"type" => "string"},
            "region" => MU::Config.region_primitive,
            "cloud" => MU::Config.cloud_primitive,
            "tag" => {
              "type" => "string",
              "description" => "Identify this Database by a tag (key=value). Note that this tag must not match more than one resource.",
              "pattern" => "^[^=]+=.+"
            },
            "deploy_id" => {
              "type" => "string",
              "description" => "Look for a Database fitting this description in another Mu deployment with this id.",
            }
          }
        }
      end

    end
  end
end
