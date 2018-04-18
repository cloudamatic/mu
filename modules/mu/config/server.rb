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
    class Server

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
        "tags" => MU::Config.tags_primitive,
        "optional_tags" => {
            "type" => "boolean",
            "description" => "Tag the resource with our optional tags (MU-HANDLE, MU-MASTER-NAME, MU-OWNER). Defaults to true",
            "default" => true
        },
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
        "loadbalancers" => MU::Config::LoadBalancer.reference,
        "add_firewall_rules" => MU::Config::FirewallRule.reference,
        "static_ip" => static_ip_primitive,
        "src_dst_check" => {
            "type" => "boolean",
            "description" => "Turn off network-level routing paranoia. Set this false to make a NAT do its thing.",
            "default" => true
        },
        "associate_public_ip" => {
            "type" => "boolean",
            "default" => false,
            "description" => "Associate public IP address?"
        },
        "userdata_script" => userdata_primitive,
        "windows_admin_username" => {
            "type" => "string",
            "default" => "Administrator",
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
                    "value_is" => "windows",
                    "set" => "Administrator"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "win2k12",
                    "set" => "Administrator"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "win2k12r2",
                    "set" => "Administrator"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "win2k16",
                    "set" => "Administrator"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "ubuntu",
                    "set" => "ubuntu"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "ubuntu14",
                    "set" => "ubuntu"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "centos7",
                    "set" => "centos"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "rhel7",
                    "set" => "ec2-user"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "rhel71",
                    "set" => "ec2-user"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "amazon",
                    "set" => "ec2-user"
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
            "enum" => ["linux", "windows", "centos", "ubuntu", "centos6", "ubuntu14", "win2k12", "win2k12r2", "win2k16", "centos7", "rhel7", "rhel71", "amazon"],
# XXX change to reflect available keys in mu/defaults/amazon_images.yaml and mu/defaults/google_images.yaml
            "description" => "Helps select default AMIs, and enables correct grooming behavior based on operating system type.",
        },
        "run_list" => {
            "type" => "array",
            "items" => {
                "type" => "string",
                "description" => "Chef run list entry, e.g. role[rolename] or recipe[recipename]."
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
        # Objects here will be stored in this node's Chef Vault
        "secrets" => {
            "type" => "object",
            "description" => "JSON artifact to be stored in Chef Vault for this node. Note that these values will still be stored in plain text local to the MU server, but only accessible to nodes via Vault."
        },
        # This node will be granted access to the following Vault items.
        "vault_access" => {
            "type" => "array",
            "minItems" => 1,
            "items" => {
                "description" => "Chef Vault items to which this node should be granted access.",
                "type" => "object",
                "title" => "vault_access",
                "required" => ["vault", "item"],
                "additionalProperties" => false,
                "properties" => {
                    "vault" => {
                        "type" => "string",
                        "description" => "The Vault to which this node should be granted access."
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

    def self.schema
      base = {
        "type" => "object",
        "required" => ["name", "size", "cloud"],
        "additionalProperties" => false,
        "description" => "Create individual server instances.",
        "properties" => {
            "dns_records" => MU::Config::DNSZone.records_primitive(need_target: false, default_type: "A", need_zone: true),
            "create_image" => {
                "type" => "object",
                "title" => "create_image",
                "required" => ["image_then_destroy", "image_exclude_storage", "public"],
                "additionalProperties" => false,
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
            "generate_iam_role" => {
                "type" => "boolean",
                "default" => true,
                "description" => "Generate a unique IAM profile for this Server or ServerPool.",
            },
            "iam_role" => {
                "type" => "string",
                "description" => "An Amazon IAM instance profile, from which to harvest role policies to merge into this node's own instance profile. If generate_iam_role is false, will simple use this profile.",
            },
            "iam_policies" => {
                "type" => "array",
                "items" => {
                    "description" => "Amazon-compatible role policies which will be merged into this node's own instance profile.  Not valid with generate_iam_role set to false. Our parser expects the role policy document to me embedded under a named container, e.g. { 'name_of_policy':'{ <policy document> } }",
                    "type" => "object"
                }
            }
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
        ok = false if !MU::Config.check_vault_refs(server)

        server['dependencies'] << configurator.adminFirewallRuleset(vpc: server['vpc'], region: server['region'], cloud: server['cloud']) if !server['scrub_mu_isms']

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

          if !server["vpc"]["subnet_name"].nil? and configurator.nat_routes.has_key?(server["vpc"]["subnet_name"])
            server["dependencies"] << {
              "type" => "server",
              "name" => configurator.nat_routes[server["vpc"]["subnet_name"]],
              "phase" => "groom"
            }
          end
        end

        ok
      end

    end #class
  end #class
end #module