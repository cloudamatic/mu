# Copyright:: Copyright (c) 2016 eGlobalTech, Inc., all rights reserved
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

autoload :Net, 'net/ssh/gateway'

module MU
  class Cloud
    class CloudFormation
      # A database as configured in {MU::Config::BasketofKittens::databases}
      class Database < MU::Cloud::Database
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :cloud_id
        attr_reader :config
        attr_reader :groomer    

        attr_reader :cfm_name
        attr_reader :cfm_template

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::databases}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          # @mu_name = mu_name ? mu_name : @deploy.getResourceName(@config["name"])
          @config["groomer"] = MU::Config.defaultGroomer unless @config["groomer"]
          @groomclass = MU::Groomer.loadGroomer(@config["groomer"])

          if !mu_name.nil?
            @mu_name = mu_name
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name ||=
              if @config["engine"].match(/^sqlserver/)
                @deploy.getResourceName(@config["name"], max_length: 15)
              else
                @deploy.getResourceName(@config["name"], max_length: 63)
              end

            @mu_name.gsub(/(--|-$)/i, "").gsub(/(_)/, "-").gsub!(/^[^a-z]/i, "")
          end
        end

        # Populate @cfm_template with a resource description for this database
        # in CloudFormation language.
        def create
          # RDS is picky, we can't just use our regular node names for things
          # like the default schema or username. And it varies from engine to
          # engine.
          basename = @config["name"].to_s
          basename = basename+@deploy.timestamp+MU.seed.downcase if !@config['scrub_mu_isms']
          basename.gsub!(/[^a-z0-9]/i, "")
          @config["db_name"] = MU::Cloud::AWS::Database.getName(basename, type: "dbname", config: @config)
          @config['master_user'] = MU::Cloud::AWS::Database.getName(basename, type: "dbuser", config: @config)

          if @config["create_cluster"]
            @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase("dbcluster", self, tags: @config['tags'], scrub_mu_isms: @config['scrub_mu_isms']) if @cfm_template.nil?
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Port", @config['port']) if @config['port']
          else
            @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase(self.class.cfg_name, self, tags: @config['tags'], scrub_mu_isms: @config['scrub_mu_isms']) if @cfm_template.nil?
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DBInstanceClass", @config['size'])
            if !@config['storage'].nil?
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "AllocatedStorage", @config['storage'].to_s)
            end


            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DBInstanceIdentifier", @config['db_name']) if @config['db_name']
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "PubliclyAccessible", @config['publicly_accessible'])
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Iops", @config['iops']) if @config['iops']

            ["allow_major_version_upgrade", "auto_minor_version_upgrade", "license_model", "storage_type", "port"].each { |arg|
              if !@config[arg].nil?
                key = ""
                arg.split(/_/).each { |chunk| key = key + chunk.capitalize }
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], key, @config[arg])
              end
            }

            if @config['multi_az_on_create'] or @config['multi_az_on_deploy']
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "MultiAZ", true)
            end

            if @config['read_replica_of'] and !@config["add_cluster_node"]
              rr = @config['read_replica_of']
              if rr['db_name']
                if @dependencies.has_key?("database") and @dependencies["database"].has_key?(rr['db_name'])
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "SourceDBInstanceIdentifier", { "Ref" => @dependencies["database"][rr['db_name']].cloudobj.cfm_name } )
                else
                  raise MuError, "Couldn't find database by name in read_replica_of stanza of #{@mu_name} (#{@config['read_replica_of']})"
                end
              elsif rr['db_id']
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "SourceDBInstanceIdentifier", rr['db_id'])
              end
            end

            # Are we supposed to be a cluster member?
            if @config["add_cluster_node"]
              cluster = nil
              rr = @config["member_of_cluster"]
              if rr['db_name']
                cluster = @deploy.findLitterMate(type: "database", name: rr['db_name'])
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DBClusterIdentifier", { "Ref" => cluster.cloudobj.cfm_name })
              elsif rr["db_id"]
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DBClusterIdentifier", rr["db_id"])
              else
                raise MuError, "Cannot resolve Database cluster id from #{rr}"
              end
              # Remove arguments that are invalid in clusters
              ["AllocatedStorage", "CharacterSetName", "DBSecurityGroups", "SourceDBInstanceIdentifier", "StorageType"].each { |arg|
                @cfm_template[@cfm_name]["Properties"].delete(arg)
              }
# XXX @config["subnet_group_name"] = @config['cluster_identifier']
            end
          end

          # Parameter groups- more or less common between clusters and instances
          if @config['parameter_group_family']
            params_name = params_template = nil
            if @config["create_cluster"]
              params_name, params_template = MU::Cloud::CloudFormation.cloudFormationBase("dbclusterparametergroup", name: @mu_name, tags: @config['tags'], scrub_mu_isms: @config['scrub_mu_isms'])
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DBClusterParameterGroupName", { "Ref" => params_name })
            else
              params_name, params_template = MU::Cloud::CloudFormation.cloudFormationBase("dbparametergroup", name: @mu_name, tags: @config['tags'], scrub_mu_isms: @config['scrub_mu_isms'])
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DBParameterGroupName", { "Ref" => params_name })
            end
            MU::Cloud::CloudFormation.setCloudFormationProp(params_template[params_name], "Description", "Parameter group for database #{@mu_name}")
            MU::Cloud::CloudFormation.setCloudFormationProp(params_template[params_name], "Family", @config['parameter_group_family'])
            if @config["db_parameter_group_parameters"] && !@config["db_parameter_group_parameters"].empty?
              params = {}
              @config["db_parameter_group_parameters"].each { |item|
                params[item['name']] = item['value']
              }
              MU::Cloud::CloudFormation.setCloudFormationProp(params_template[params_name], "Parameters", params)
            end

            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", params_name)
            @cfm_template.merge!(params_template)
          end

          # DB Subnet groups also common between clusters and instances
          if @config["vpc"]
            subnets_name, subnets_template = MU::Cloud::CloudFormation.cloudFormationBase("dbsubnetgroup", name: @mu_name, tags: @config['tags'], scrub_mu_isms: @config['scrub_mu_isms'])
            MU::Cloud::CloudFormation.setCloudFormationProp(subnets_template[subnets_name], "DBSubnetGroupDescription", @mu_name)
            if !@config["vpc"]["subnets"].nil? and @config["vpc"]["subnets"].size > 0
              @config["vpc"]["subnets"].each { |subnet|
                if !subnet["subnet_id"].nil?
                  MU::Cloud::CloudFormation.setCloudFormationProp(subnets_template[subnets_name], "SubnetIds", subnet["subnet_id"])
                elsif @dependencies.has_key?("vpc") and @dependencies["vpc"].has_key?(@config["vpc"]["vpc_name"])
                  @dependencies["vpc"][@config["vpc"]["vpc_name"]].subnets.each { |subnet_obj|
                    if subnet_obj.name == subnet['subnet_name']
                      MU::Cloud::CloudFormation.setCloudFormationProp(subnets_template[subnets_name], "DependsOn", subnet_obj.cfm_name)
                      MU::Cloud::CloudFormation.setCloudFormationProp(subnets_template[subnets_name], "SubnetIds", { "Ref" => subnet_obj.cfm_name } )
                    end
                  }
                end
              }
            end
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DBSubnetGroupName", { "Ref" => subnets_name } )
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", subnets_name)

            if @config['add_firewall_rules']
              @config['add_firewall_rules'].each { |acl|
                if acl["rule_id"]
                  MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "VPCSecurityGroups", acl["rule_id"])
                else
                  MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "VPCSecurityGroups", { @dependencies["firewall_rule"][acl["rule_name"]].cloudobj.cfm_name })
                end
              }
            end

            @cfm_template.merge!(subnets_template)
          end

          # Other common parameters
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "StorageEncrypted", @config['storage_encrypted'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "MasterUsername", @config['master_user'])
          ["engine", "backup_retention_period", "preferred_backup_window", "engine_version", "preferred_maintenance_window"].each { |arg|
            if !@config[arg].nil?
              key = ""
              arg.split(/_/).each { |chunk| key = key + chunk.capitalize }
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], key, @config[arg])
            end
          }

          # Source snapshots and passwords work almost the same
          if @config["creation_style"] == "new_snapshot"
            raise MuCloudFlagNotImplemented, "Database creation node 'new_snapshot' is not supported for CloudFormation targets"
          elsif @config["creation_style"] == "existing_snapshot"
            if !@config["create_cluster"]
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DBSnapshotIdentifier", @config['identifier'])
            elsif !@config['read_replica_of']
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "SnapshotIdentifier", @config['identifier'])
            end
          else
            # This password will be stored in plain text somewhere. Probably
            # best off making it a parameter in most use cases, because whoa
            # nelly is that insecure
            if @config["create_cluster"]
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DatabaseName", @config['db_name'])
            elsif @config['db_name']
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DBName", @config['db_name'])
            end
            if @config['password'].nil?
              if @config['auth_vault'] && !@config['auth_vault'].empty?
                @config['password'] = @groomclass.getSecret(
                  vault: @config['auth_vault']['vault'],
                  item: @config['auth_vault']['item'],
                  field: @config['auth_vault']['password_field']
                )
              else
                # Should we use random instead?
                @config['password'] = Password.pronounceable(10..12)
              end
            end
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "MasterUserPassword", @config['password'])
          end
        end

        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def groom
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def allowHost
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def self.find(*args)
          MU.log "find() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def self.cleanup(*args)
          MU.log "cleanup() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def notify
          {}
        end

      end #class
    end #class
  end
end #module
