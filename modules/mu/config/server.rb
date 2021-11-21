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
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/server.rb
    class Server

      # Verify that a server or server_pool has a valid LDAP config referencing
      # valid Vaults for credentials.
      # @param server [Hash]
      def self.checkVaultRefs(server)
        ok = true
        server['vault_access'] = [] if server['vault_access'].nil?
        server['groomer'] ||= self.defaultGroomer
        groomclass = MU::Groomer.loadGroomer(server['groomer'])

        begin
          if !server['active_directory'].nil?
            ["domain_admin_vault", "domain_join_vault"].each { |vault_class|
              server['vault_access'] << {
                "vault" => server['active_directory'][vault_class]['vault'],
                "item" => server['active_directory'][vault_class]['item']
              }
              item = groomclass.getSecret(
                vault: server['active_directory'][vault_class]['vault'],
                item: server['active_directory'][vault_class]['item'],
              )
              ["username_field", "password_field"].each { |field|
                if !item.has_key?(server['active_directory'][vault_class][field])
                  ok = false
                  MU.log "I don't see a value named #{field} in Chef Vault #{server['active_directory'][vault_class]['vault']}:#{server['active_directory'][vault_class]['item']}", MU::ERR
                end
              }
            }
          end

          if !server['windows_auth_vault'].nil?
            server['use_cloud_provider_windows_password'] = false

            server['vault_access'] << {
              "vault" => server['windows_auth_vault']['vault'],
              "item" => server['windows_auth_vault']['item']
            }
            item = groomclass.getSecret(
              vault: server['windows_auth_vault']['vault'],
              item: server['windows_auth_vault']['item']
            )
            ["password_field", "ec2config_password_field", "sshd_password_field"].each { |field|
              if !item.has_key?(server['windows_auth_vault'][field])
                MU.log "No value named #{field} in Chef Vault #{server['windows_auth_vault']['vault']}:#{server['windows_auth_vault']['item']}, will use a generated password.", MU::NOTICE
                server['windows_auth_vault'].delete(field)
              end
            }
          end
          # Check all of the non-special ones while we're at it
          server['vault_access'].each { |v|
            next if v['vault'] == "splunk" and v['item'] == "admin_user"
            next if !v['vault'] # assumed to be the one the server or database will always have
            item = groomclass.getSecret(vault: v['vault'], item: v['item'])
          }
        rescue MuError
          MU.log "Can't load a Chef Vault I was configured to use. Does it exist?", MU::ERR
          ok = false
        end
        return ok
      end

      # Generate schema for a storage volume
      # @return [Hash]
      def self.storage_primitive
      {
        "type" => "array",
        "items" => {
            "type" => "object",
            "description" => "Creates and attaches an EBS volume to this instance.",
            "required" => ["size"],
            "additionalProperties" => false,
            "properties" => {
                "size" => {
                    "type" => "integer",
                    "description" => "Size of this EBS volume (GB)",
                },
                "iops" => {
                    "type" => "integer",
                    "description" => "The amount of IOPS to allocate to Provisioned IOPS (io1) volumes.",
                },
                "device" => {
                    "type" => "string",
                    "description" => "Map this volume to a specific OS-level device (e.g. /dev/sdg)",
                },
                "virtual_name" => {
                    "type" => "string",
                },
                "snapshot_id" => {
                    "type" => "string",
                },
                "delete_on_termination" => {
                    "type" => "boolean",
                    "default" => true
                },
                "no_device" => {
                    "type" => "string",
                    "description" => "Do not share this device with the OS"
                },
                "encrypted" => {
                    "type" => "boolean",
                    "default" => false
                },
                "volume_type" => {
                    "enum" => ["standard", "io1", "gp2", "st1", "sc1"],
                    "type" => "string",
                    "default" => "gp2"
                }
            }
        }
      }
      end

      # Generate schema for an inline userdata script declaration
      # @return [Hash]
      def self.userdata_primitive
        {
          "type" => "object",
          "description" => "A script to be run during the bootstrap process. Typically used to preconfigure Windows instances.",
          "required" => ["path"],
          "additionalProperties" => false,
          "properties" => {
              "use_erb" => {
                  "type" => "boolean",
                  "default" => true,
                  "description" => "Assume that this script is an ERB template and parse it as one before passing to the instance."
              },
              "skip_std" => {
                  "type" => "boolean",
                  "default" => false,
                  "description" => "Omit the standard Mu userdata entirely in favor of this custom script (normally we'd run both)."
              },
              "path" => {
                  "type" => "string",
                  "description" => "A local path or URL to a file which will be loaded and passed to the instance. Relative paths will be resolved from the current working directory of the deploy tool when invoked."
              }
          }
        }
      end

      # Generate schema for a static IP assignment for an instance
      # @return [Hash]
      def self.static_ip_primitive
      {
          "type" => "object",
          "additionalProperties" => false,
          "minProperties" => 1,
          "description" => "Assign a specific IP to this instance once it's ready.",
          "properties" => {
              "ip" => {
                  "type" => "string",
                  "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$",
              },
              "assign_ip" => {
                  "type" => "boolean",
                  "default" => true
              }
          }
      }
      end

      # properties common to both server and server_pool resources
      def self.common_properties
        {
          "name" => {"type" => "string"},
          "ansible_vars" => {
            "type" => "object",
            "description" => "When using Ansible as a groomer, this will insert a +vars+ tree into the playbook for this node."
          },
          "scrub_mu_isms" => {
              "type" => "boolean",
              "default" => false,
              "description" => "When 'cloud' is set to 'CloudFormation,' use this flag to strip out Mu-specific artifacts (tags, standard userdata, naming conventions, etc) to yield a clean, source-agnostic template."
          },
          "region" => MU::Config.region_primitive,
          "async_groom" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Bootstrap asynchronously via the Momma Cat daemon instead of during the main deployment process"
          },
          "groomer" => {
            "type" => "string",
            "default" => MU::Config.defaultGroomer,
            "enum" => MU.supportedGroomers
          },
          "groomer_autofetch" => {
            "type" => "boolean",
            "description" => "For groomer implementations which support automatically fetching roles/recipes/manifests from a public library, such as Ansible Galaxy, this will toggle this behavior on or off.",
            "default" => true
          },
          "groom" => {
            "type" => "boolean",
            "default" => true,
            "description" => "Whether to run a host configuration agent, e.g. Chef, when bootstrapping"
          },
          "groomer_variables" => {
            "type" => "object",
            "description" => "Metadata variables to expose to Groomer clients, under a top-level key named +mu+. Same thing as +application_attributes+, but with a name that makes a modicum of sense."
          },
          "groomer_timeout" => {
              "type" => "integer",
              "default" => 1800,
              "description" => "Maximum execution time for a groomer run"
          },
          "scrub_groomer" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Remove pre-existing groomer agents from node before bootstrapping. Especially useful for image builds."
          },
          "monitor" => {
            "type" => "boolean",
            "default" => true,
            "description" => "Whether to monitor this host with Nagios"
          },
          "tags" => MU::Config.tags_primitive,
          "optional_tags" => MU::Config.optional_tags_primitive,
          "alarms" => MU::Config::Alarm.inline,
          "active_directory" => {
              "type" => "object",
              "additionalProperties" => false,
              "required" => ["domain_name", "short_domain_name", "domain_controllers", "domain_join_vault", "domain_admin_vault"],
              "description" => "Integrate this node into an Active Directory domain. On Linux, will configure Winbind and PAM for system-level AD authentication.",
              "properties" => {
                  "domain_name" => {
                      "type" => "string",
                      "description" => "The full name Active Directory domain to join"
                  },
                  "short_domain_name" => {
                      "type" => "string",
                      "description" => "The short (NetBIOS) Active Directory domain to join"
                  },
                  "domain_controllers" => {
                      "type" => "array",
                      "minItems" => 1,
                      "items" => {
                          "type" => "string",
                          "description" => "IP address of a domain controller"
                      }
                  },
                  "domain_controller_hostname" => {
                      "type" => "string",
                      "description" => "A custom hostname for your domain controller. mu_windows_name will be used if not specified. Do not specify when joining a Domain-Node"
                  },
                  "domain_operation" => {
                      "type" => "string",
                      "default" => "join",
                      "enum" => ["join", "create", "add_controller"],
                      "description" => "Rather to join, create or add a Domain Controller"
                  },
                  "domain_sid" => {
                      "type" => "string",
                      "description" => "SID of a known domain. Used to help Linux clients map uids and gids properly with SSSD."
                  },
                  "node_type" => {
                      "type" => "string",
                      "enum" => ["domain_node", "domain_controller"],
                      "description" => "If the node will be a domain controller or a domain node",
                      "default" => "domain_node",
                      "default_if" => [
                          {
                              "key_is" => "domain_operation",
                              "value_is" => "create",
                              "set" => "domain_controller"
                          },
                          {
                              "key_is" => "domain_operation",
                              "value_is" => "add_controller",
                              "set" => "domain_controller"
                          },
                          {
                              "key_is" => "domain_operation",
                              "value_is" => "join",
                              "set" => "domain_node"
                          }
                      ]
                  },
                  "computer_ou" => {
                      "type" => "string",
                      "description" => "The OU to which to add this computer when joining the domain."
                  },
                  "domain_join_vault" => {
                      "type" => "object",
                      "additionalProperties" => false,
                      "description" => "Vault used to store the credentials for the domain join user",
                      "properties" => {
                          "vault" => {
                              "type" => "string",
                              "default" => "active_directory",
                              "description" => "The vault where these credentials reside"
                          },
                          "item" => {
                              "type" => "string",
                              "default" => "join_domain",
                              "description" => "The vault item where these credentials reside"
                          },
                          "password_field" => {
                              "type" => "string",
                              "default" => "password",
                              "description" => "The field within the Vault item where the password for these credentials resides"
                          },
                          "username_field" => {
                              "type" => "string",
                              "default" => "username",
                              "description" => "The field where the user name for these credentials resides"
                          }
                      }
                  },
                  "domain_admin_vault" => {
                      "type" => "object",
                      "additionalProperties" => false,
                      "description" => "Vault used to store the credentials for the domain admin user",
                      "properties" => {
                          "vault" => {
                              "type" => "string",
                              "default" => "active_directory",
                              "description" => "The vault where these credentials reside"
                          },
                          "item" => {
                              "type" => "string",
                              "default" => "domain_admin",
                              "description" => "The vault item where these credentials reside"
                          },
                          "password_field" => {
                              "type" => "string",
                              "default" => "password",
                              "description" => "The field within the Vault item where the password for these credentials resides"
                          },
                          "username_field" => {
                              "type" => "string",
                              "default" => "username",
                              "description" => "The field where the user name for these credentials resides"
                          }
                      }
                  }
              }
          },
          "add_private_ips" => {
              "type" => "integer",
              "description" => "Assign extra private IP addresses to this server."
          },
          "skipinitialupdates" => {
              "type" => "boolean",
              "description" => "Node bootstrapping normally runs an internal recipe that does a full system update. This is very slow for testing, so let's have an option to disable it.",
              "default" => false
          },
          "sync_siblings" => {
              "type" => "boolean",
              "description" => "If true, chef-client will automatically re-run on nodes of the same type when this instance has finished grooming. Use, for example, to add new members to a database cluster in an autoscale group by sharing data in Chef's node structures.",
              "default" => false
          },
          "dns_sync_wait" => {
              "type" => "boolean",
              "description" => "Wait for DNS record to propagate in DNS Zone.",
              "default" => true,
          },
          "loadbalancers" => {
            "type" => "array",
            "minItems" => 1,
            "items" => MU::Config::LoadBalancer.reference
          },
          "add_firewall_rules" => {
            "type" => "array",
            "items" => MU::Config::FirewallRule.reference,
          },
          "static_ip" => static_ip_primitive,
          "src_dst_check" => {
              "type" => "boolean",
              "description" => "Turn off network-level routing paranoia. Set this false to make a NAT do its thing.",
              "default" => true
          },
          "associate_public_ip" => {
              "type" => "boolean",
              "description" => "Whether to associate a public IP address with this server. Default behavior is to align with resident VPC/subnet, which to say +true+ if the subnet is publicly routable, +false+ if not. For non-VPC instances (AWS Classic), we default to +true+."
          },
          "userdata_script" => userdata_primitive,
          "windows_admin_username" => {
            "type" => "string",
            "description" => "Use an alternate Windows account for Administrator functions. Will change the name of the Administrator account, if it has not already been done."
          },
          "windows_auth_vault" => {
              "type" => "object",
              "additionalProperties" => false,
              "required" => ["vault", "item"],
              "description" => "Set Windows nodes' local administrator password to a value specified in a Chef Vault.",
              "properties" => {
                  "vault" => {
                      "type" => "string",
                      "default" => "windows",
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
                      "description" => "The field within the Vault item where the password for Windows local Administrator user is stored"
                  },
                  "ec2config_password_field" => {
                      "type" => "string",
                      "default" => "ec2config_password",
                      "description" => "The field within the Vault item where the password for the EC2config service user is stored"
                  },
                  "sshd_password_field" => {
                      "type" => "string",
                      "default" => "sshd_password",
                      "description" => "The field within the Vault item where the password for the Cygwin/SSH service user is stored"
                  }
              }
          },
          "ssh_user" => {
            "type" => "string",
            "default" => "root",
            "default_if" => [
              {
                "key_is" => "platform",
                "value_is" => "centos",
                "set" => "centos"
              },
              {
                "key_is" => "platform",
                "value_is" => "centos6",
                "set" => "centos"
              },
              {
                "key_is" => "platform",
                "value_is" => "centos7",
                "set" => "centos"
              },
              {
                "key_is" => "platform",
                "value_is" => "centos8",
                "set" => "centos"
              }
            ]
          },
          "use_cloud_provider_windows_password" => {
              "type" => "boolean",
              "default" => true
          },
          "platform" => {
              "type" => "string",
              "default" => "linux",
              "enum" => MU::Cloud.listPlatforms,
              "description" => "Helps select default machine images, and enables correct grooming behavior based on operating system type.",
          },
          "run_list" => {
              "type" => "array",
              "items" => {
                  "type" => "string",
                  "description" => "A list of +groomer+ recipes/roles/scripts to run, using naming conventions specific to the appropriate grooming layer. In +Chef+, this corresponds to a node's +run_list+ attribute, and entries should be of the form <tt>role[rolename]</tt> or <tt>recipe[recipename]</tt>. In +Ansible+, it should be a list of roles (+rolename+), which Mu will use to generate a custom Playbook for the deployment."
              }
          },
          "ingress_rules" => {
              "type" => "array",
              "items" => MU::Config::FirewallRule.ruleschema
          },
          # This is a free-form means to pass stuff to the mu-tools Chef cookbook
          "application_attributes" => {
              "type" => "object",
              "description" => "Chef Node structure artifact for mu-tools cookbook.",
          },
          # Objects here will be stored in this node's Chef/Ansible/etc Vault
          "secrets" => {
              "type" => "object",
              "description" => "JSON artifact to be stored the appropriate groomer vault for this node. Note that these values will still be stored in plain text local to the MU server, but only accessible to nodes via Vault."
          },
          # This node will be granted access to the following Vault items.
          "vault_access" => {
            "type" => "array",
            "minItems" => 1,
            "items" => {
              "description" => "Chef Vault items to which this node should be granted access.",
              "type" => "object",
              "title" => "vault_access",
              "required" => ["item"],
              "additionalProperties" => false,
              "properties" => {
                "vault" => {
                  "type" => "string",
                  "description" => "The Vault to which this node should be granted access. If not specified, will resolve to this resource's own vault (ex +MYAPP-DEV-2021091617-QT-FOODB+)"
                },
                "item" => {
                  "type" => "string",
                  "description" => "The item within the Vault to which this node should be granted access."
                }
              }
            }
          },
          "existing_deploys" => {
            "type" => "array",
            "minItems" => 1,
            "items" => {
              "type" => "object",
              "additionalProperties" => false,
              "description" => "Existing deploys that will be loaded into the new deployment metadata. This metadata will be saved on the Chef node",
              "properties" => {
                  "cloud_type" => {
                    "type" => "string",
                    "description" => "The type of resource we will parse metdata for",
                    "enum" => ["server", "database", "storage_pool", "cache_cluster"]
                  },
                  "cloud_id" => {
                    "type" => "string",
                    "description" => "The cloud identifier of the resource from which you would like to add metadata to this deployment. eg - i-d96eca0d. Must use either 'cloud_id' OR 'mu_name' AND 'deploy_id'"
                  },
                  "mu_name" => {
                    "type" => "string",
                    "description" => "The full name of a resource in a foreign deployment from which we should add the metdata to this deployment. You should also include 'deploy_id' so we will be able to identifiy a single resource. Use either 'cloud_id' OR 'mu_name' and 'deploy_id'"
                  },
                  "deploy_id" => {
                    "type" => "string",
                    "description" => "Should be used with 'mu_name' to identifiy a single resource."
                  }
              }
            }
          }
        }
      end

      # Base configuration schema for a Server
      # @return [Hash]
      def self.schema
        base = {
          "type" => "object",
          "required" => ["name", "size", "cloud"],
          "additionalProperties" => false,
          "description" => "Create individual server instances.",
          "properties" => {
              "dns_records" => MU::Config::DNSZone.records_primitive(need_target: false, default_type: "A", need_zone: true, embedded_type: "server"),
              "bastion" => {
                "type" => "boolean",
                "default" => false,
                "description" => "Allow this server to be automatically used as a bastion host"
              },
              "image_id" => {
                "type" => "string",
                "description" => "The cloud provider image on which to base this instance. Will use the default appropriate for the +platform+, if not specified."
              },
              "create_image" => {
                  "type" => "object",
                  "title" => "create_image",
                  "required" => ["image_then_destroy", "image_exclude_storage", "public"],
                  "description" => "Create a reusable image of this server once it is complete.",
                  "properties" => {
                      "public" => {
                          "type" => "boolean",
                          "description" => "Make the image public once it's complete",
                          "default" => false
                      },
                      "image_then_destroy" => {
                          "type" => "boolean",
                          "description" => "Destroy the source server after creating the reusable image(s).",
                          "default" => false
                      },
                      "image_exclude_storage" => {
                          "type" => "boolean",
                          "description" => "When creating an image of this server, exclude the block device mappings of the source server.",
                          "default" => false
                      },
                      "copy_to_regions" => {
                          "type" => "array",
                          "description" => "Replicate the AMI to regions other than the source server's.",
                          "items" => {
                              "type" => "String",
                              "description" => "Regions in which to place more copies of this image. If none are specified, or if the keyword #ALL is specified, will place in all available regions."
                          }
                      }
                  }
              },
              "vpc" => MU::Config::VPC.reference(MU::Config::VPC::ONE_SUBNET+MU::Config::VPC::MANY_SUBNETS, MU::Config::VPC::NAT_OPTS, "public"),
              "monitoring" => {
                  "type" => "boolean",
                  "default" => true,
                  "description" => "Enable detailed instance monitoring.",
              },
              "private_ip" => {
                "type" => "string",
                "description" => "Request a specific private IP address for this instance.",
                "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$"
              },
              "size" => {
                "description" => "The instance type to create. Must be valid for the cloud provider into which we're deploying.",
                "type" => "string"
              },
              "storage" => storage_primitive,
          }
        }
        base["properties"].merge!(common_properties)
        base
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::servers}, bare and unvalidated.
      # @param server [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(server, configurator)
        ok = true
        if configurator.haveLitterMate?(server["name"], "server_pools") 
          MU.log "Can't use name #{server['name']} more than once in servers/server_pools"
          ok = false
        end
        server['skipinitialupdates'] = true if @skipinitialupdates
        server['ingress_rules'] ||= []
        server['vault_access'] ||= []
        server['vault_access'] << {"vault" => "splunk", "item" => "admin_user"}
        ok = false if !MU::Config::Server.checkVaultRefs(server)

        server['groomer'] ||= self.defaultGroomer
        groomclass = MU::Groomer.loadGroomer(server['groomer'])
        if !groomclass.available?(server['platform'].match(/^win/))
          MU.log "Groomer #{server['groomer']} for #{server['name']} is missing or has incomplete dependencies", MU::ERR
          ok = false
        end

        if server["cloud"] != "Azure"
          server['dependencies'] << configurator.adminFirewallRuleset(vpc: server['vpc'], region: server['region'], cloud: server['cloud'], credentials: server['credentials'])
        end

        if !server["vpc"].nil?
          # Common mistake- using all_public or all_private subnet_pref for
          # resources that can only go in one subnet. Let's just handle that
          # for people.
          if server["vpc"]["subnet_pref"] == "all_private"
            MU.log "Servers only support single subnets, setting subnet_pref to 'private' instead of 'all_private' on #{server['name']}", MU::WARN
            server["vpc"]["subnet_pref"] = "private"
          end
          if server["vpc"]["subnet_pref"] == "all_public"
            MU.log "Servers only support single subnets, setting subnet_pref to 'public' instead of 'all_public' on #{server['name']}", MU::WARN
            server["vpc"]["subnet_pref"] = "public"
          end

          if server["associate_public_ip"].nil?
            server["associate_public_ip"] = server["vpc"]["subnet_pref"] == "public" ? true : false

          end

          if !server["vpc"]["subnet_name"].nil? and configurator.nat_routes.has_key?(server["vpc"]["subnet_name"]) and !configurator.nat_routes[server["vpc"]["subnet_name"]].empty?
            MU::Config.addDependency(server, configurator.nat_routes[server["vpc"]["subnet_name"]], "server", their_phase: "groom", my_phase: "groom")
          elsif !server["vpc"]["name"].nil?
            siblingvpc = configurator.haveLitterMate?(server["vpc"]["name"], "vpcs")
            if siblingvpc and siblingvpc['bastion'] and
               server['name'] != siblingvpc['bastion']['name']
              MU::Config.addDependency(server, siblingvpc['bastion']['name'], "server", their_phase: "groom", my_phase: "groom")
            end
          end
        else
          server["associate_public_ip"] ||= false
        end

        ok
      end

    end #class
  end #class
end #module
