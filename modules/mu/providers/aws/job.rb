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
  class Cloud
    class AWS
      # A scheduled task facility as configured in {MU::Config::BasketofKittens::jobs}
      class Job < MU::Cloud::Job

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          @cloud_id = @mu_name

          params = get_properties

          MU.log "Creating CloudWatch Event #{@mu_name}", MU::NOTICE, details: params

          MU::Cloud::AWS.cloudwatchevents(region: @config['region'], credentials: @credentials).put_rule(params)
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          new_props = get_properties
          current = MU.structToHash(cloud_desc(use_cache: false))
          params = {}
          new_props.each_pair { |k, v|
            next if k == :tags # doesn't seem to do anything
            if v != current[k]
              params[k] = v
            end
          }

          if params.size > 0
            MU.log "Updating CloudWatch Event #{@cloud_id}", MU::NOTICE, details: params
            MU::Cloud::AWS.cloudwatchevents(region: @config['region'], credentials: @credentials).put_rule(new_props)
          end

          if @config['targets']
            target_params = []
            @config['targets'].each { |t|
              MU.retrier([MuNonFatal], max:5, wait: 9) {
              target_ref = MU::Config::Ref.get(t)
              target_obj = target_ref.kitten(cloud: "AWS")
              this_target = if target_ref.is_mu_type? and target_obj and
                               !target_obj.arn.nil?
                if target_ref.type == "functions"
                  target_obj.addTrigger(arn, "events", @mu_name)
                end
                {
                  id: target_obj.cloud_id,
                  arn: target_obj.arn
                }
              elsif target_ref.id and target_ref.id.match(/^arn:/)
                {
                  id: target_ref.id || target_ref.name,
                  arn: target_ref.id
                }
              else
                raise MuNonFatal.new "Failed to retrieve ARN from CLoudWatch Event target descriptor", details: target_ref.to_h
              end
              if t['role']
                role_obj = MU::Config::Ref.get(t['role']).kitten(@deploy, cloud: "AWS")
                  raise MuError.new "Failed to fetch object from role reference", details: t['role'].to_h if !role_obj
                  params[:role_arn] = role_obj.arn
              end
              [:input, :input_path, :input_transformer, :kinesis_parameters, :run_command_parameters, :batch_parameters, :sqs_parameters, :ecs_parameters].each { |attr|
                if t[attr.to_s]
                  this_target[attr] = MU.structToHash(t[attr.to_s])
                end
              }
              target_params << this_target
              }
            }
            MU::Cloud::AWS.cloudwatchevents(region: @config['region'], credentials: @credentials).put_targets(
              rule: @cloud_id,
              event_bus_name: cloud_desc.event_bus_name,
              targets: target_params
            )
          end

        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc ? cloud_desc.arn : nil
        end

        # Return the metadata for this job
        # @return [Hash]
        def notify
          MU.structToHash(cloud_desc, stringify_keys: true)
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::BETA
        end

        # Remove all jobs associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          found = find(region: region, credentials: credentials)

          found.each_pair { |id, desc|
            if (desc.description and desc.description == deploy_id) or
               (flags and flags['known'] and flags['known'].include?(id))
              MU.log "Deleting CloudWatch Event #{id}"
              if !noop
                resp = MU::Cloud::AWS.cloudwatchevents(region: region, credentials: credentials).list_targets_by_rule(
                  rule: id,
                  event_bus_name: desc.event_bus_name,
                )
                if resp and resp.targets and !resp.targets.empty?
                  MU::Cloud::AWS.cloudwatchevents(region: region, credentials: credentials).remove_targets(
                    rule: id,
                    event_bus_name: desc.event_bus_name,
                    ids: resp.targets.map { |t| t.id }
                  )
                end

                MU::Cloud::AWS.cloudwatchevents(region: region, credentials: credentials).delete_rule(
                  name: id,
                  event_bus_name: desc.event_bus_name
                )
              end
            end
          }
        end

        # Locate an existing event.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching CloudWatch Event
        def self.find(**args)
          found = {}

          MU::Cloud::AWS.cloudwatchevents(region: args[:region], credentials: args[:credentials]).list_rules.rules.each { |r|
            next if args[:cloud_id] and ![r.name, r.arn].include?(args[:cloud_id])
            found[r.name] = r
          }

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**_args)
          bok = {
            "cloud" => "AWS",
            "credentials" => @config['credentials'],
            "cloud_id" => @cloud_id,
            "region" => @config['region']
          }

          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end
          bok['name'] = cloud_desc.name
          if cloud_desc.description and !cloud_desc.description.empty?
            bok['description'] = cloud_desc.description
          end

          bok['disabled'] = true if cloud_desc.state == "DISABLED"

#          schedule_expression="cron(15 6 * * ? *)"
          if cloud_desc.schedule_expression
            if cloud_desc.schedule_expression.match(/cron\((\S+) (\S+) (\S+) (\S+) (\S+) (\S+)\)/)
              bok['schedule'] = {
                "minute" => Regexp.last_match[1],
                "hour" => Regexp.last_match[2],
                "day_of_month" => Regexp.last_match[3],
                "month" => Regexp.last_match[4],
                "day_of_week" => Regexp.last_match[5],
                "year" => Regexp.last_match[6]
              }
            else
              MU.log "HALP", MU::ERR, details: cloud_desc.schedule_expression
            end
          end

          if cloud_desc.role_arn
            shortname = cloud_desc.role_arn.sub(/.*?role\/([^\/]+)$/, '\1')
            bok['role'] = MU::Config::Ref.get(
              id: shortname,
              cloud: "AWS",
              type: "roles"
            )
          end

          targets = MU::Cloud::AWS.cloudwatchevents(region: @config['region'], credentials: @credentials).list_targets_by_rule(
            rule: @cloud_id,
            event_bus_name: cloud_desc.event_bus_name
          ).targets
          targets.each { |t|
            bok['targets'] ||= []
            _arn, _plat, service, region, account, resource = t.arn.split(/:/, 6)
            target_type = if service == "lambda"
              resource.sub!(/^function:/, '')
              "functions"
            elsif service == "sns"
              "notifiers"
            elsif service == "sqs"
              "msg_queues"
            else
              service
            end
            ref_params = {
              id: resource,
              region: region,
              type: target_type,
              cloud: "AWS",
              credentials: @credentials,
              habitat: MU::Config::Ref.get(
                id: account,
                cloud: "AWS",
                credentials: @credentials
              )
            }
            [:input, :input_path, :input_transformer, :kinesis_parameters, :run_command_parameters, :batch_parameters, :sqs_parameters].each { |attr|
              if t.respond_to?(attr) and !t.send(attr).nil?
                ref_params[attr] = MU.structToHash(t.send(attr), stringify_keys: true)
              end
            }

            bok['targets'] << MU::Config::Ref.get(ref_params)
          }

# XXX cloud_desc.event_pattern - what do we want to do with this?

          bok
        end


        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []

          target_schema = MU::Config::Ref.schema(any_type: true, desc: "A resource which will be invoked by this event. Can be a reference to a sibling Mu resource, typically a +Function+ or +MsgQueue+, or to an unadorned external cloud resource.")
          target_params = {
            "role" => MU::Config::Ref.schema(type: "roles", desc: "A sibling {MU::Config::BasketofKittens::roles} entry or the id of an existing IAM role to assign to use when interacting with this target.", omit_fields: ["region", "tag"]),
            "input" => {
              "type" => "string"
            },
            "input_path" => {
              "type" => "string"
            },
            "run_command_parameters" => {
              "type" => "object",
              "description" => "Parameters used when you are using the rule to invoke Amazon EC2 Run Command",
              "required" => ["run_command_targets"],
              "properties" => {
                "run_command_targets" => {
                  "type" => "array",
                  "items" => {
                    "type" => "object",
                    "description" => "Currently, AWS supports including only one +run_command_targets+ block, which specifies either an array of InstanceIds or a tag.",
                    "required" => ["key", "values"],
                    "properties" => {
                      "key" => {
                        "type" => "string",
                        "description" => "Can be either +tag: tag-key+ or +InstanceIds+"
                      },
                      "values" => {
                        "type" => "array",
                        "items" => {
                          "description" => "If +key+ is +tag: tag-key+, +values+ is a list of tag values; if +key+ is +InstanceIds+, +values+ is a list of Amazon EC2 instance IDs.",
                          "type" => "string"
                        }
                      }
                    }
                  }
                }
              }
            },
            "input_transformer" => {
              "type" => "object",
              "description" => "Settings to enable you to provide custom input to a target based on certain event data. You can extract one or more key-value pairs from the event and then use that data to send customized input to the target.",
              "required" => ["input_template"],
              "properties" => {
                "input_template" => {
                  "type" => "string",
                  "description" => "Input template where you specify placeholders that will be filled with the values of the keys from +input_paths_map+ to customize the data sent to the target."
                },
                "input_paths_map" => {
                  "type" => "object",
                  "description" => "Hash representing JSON paths to be extracted from the event"
                }
              }
            },
            "batch_parameters" => {
              "type" => "object",
              "description" => "If the event target is an AWS Batch job, this contains the job definition, job name, and other parameters. See: https://docs.aws.amazon.com/batch/latest/userguide/jobs.html",
              "required" => ["job_definition", "job_name"],
              "properties" => {
                "job_definition" => {
                  "description" => "The ARN or name of the job definition to use if the event target is an AWS Batch job.",
                  "type" => "string"
                },
                "job_name" => {
                  "description" => "The name to use for this execution of the job, if the target is an AWS Batch job.",
                  "type" => "string"
                },
                "array_properties" => {
                  "type" => "object",
                  "description" => "The array properties for the submitted job, such as the size of the array.",
                  "properties" => {
                    "size" => {
                      "description" => "Size of the submitted array",
                      "type" => "integer"
                    }
                  }
                },
                "retry_strategy" => {
                  "type" => "object",
                  "description" => "The retry strategy to use for failed jobs, if the target is an AWS Batch job.",
                  "properties" => {
                    "attempts" => {
                      "description" => "Number of retry attempts, valid values from 1-10",
                      "type" => "integer"
                    }
                  }
                }
              }
            },
            "sqs_parameters" => {
              "type" => "object",
              "description" => "Contains the message group ID to use when the target is an SQS FIFO queue.",
              "required" => ["message_group_id"],
              "properties" => {
                "message_group_id" => {
                  "type" => "string"
                }
              }
            },
            "kinesis_parameters" => {
              "type" => "object",
              "description" => "The custom parameter you can use to control the shard assignment, when the target is a Kinesis data stream.",
              "required" => ["partition_key_path"],
              "properties" => {
                "partition_key_path" => {
                  "type" => "string"
                }
              }
            },
            "http_parameters" => {
              "type" => "object",
              "description" => "Contains the HTTP parameters to use when the target is a API Gateway REST endpoint.",
              "properties" => {
                "path_parameter_values" => {
                  "type" => "array",
                  "items" => {
                    "description" => "The path parameter values to be used to populate API Gateway REST API path wildcards (\"*\").",
                    "type" => "string"
                  }
                },
                "header_parameters" => {
                  "description" => "Key => value pairs to pass as headers",
                  "type" => "object"
                },
                "query_string_parameters" => {
                  "description" => "Key => value pairs to pass as query strings",
                  "type" => "object"
                }
              }
            }
          }
          target_schema["properties"].merge!(target_params)

          schema = {
            "disabled" => {
              "type" => "boolean",
              "description" => "Leave this job in place but disabled",
              "default" => false
            },
            "role" => MU::Config::Ref.schema(type: "roles", desc: "A sibling {MU::Config::BasketofKittens::roles} entry or the id of an existing IAM role to assign to this CloudWatch Event.", omit_fields: ["region", "tag"]),
            "targets" => {
              "type" => "array",
              "items" => target_schema
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::jobs}, bare and unvalidated.
        # @param job [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(job, _configurator)
          ok = true

          job['targets'].each { |t|
            target_ref = MU::Config::Ref.get(t)
            if target_ref.is_mu_type? and target_ref.name
              MU::Config.addDependency(job, target_ref.name, target_ref.type)
            end
          }

          ok
        end

        private

        def get_properties
          params = {
            name: @cloud_id,
            state: @config['disabled'] ? "DISABLED" : "ENABLED",
            event_bus_name: "default" # XXX expose, or create a deploy-specific one?
          }

          params[:description] = if @config['description'] and @config['scrub_mu_isms']
            @config['description']
          else
            @deploy.deploy_id
          end

          if @tags
            params[:tags] = @tags.each_key.map { |k| { :key => k, :value => @tags[k] } }
          end

          if @config['role']
            role_obj = MU::Config::Ref.get(@config['role']).kitten(@deploy, cloud: "AWS")
            raise MuError.new "Failed to fetch object from role reference", details: @config['role'].to_h if !role_obj
            params[:role_arn] = role_obj.arn
          end

          if @config['schedule']
            params[:schedule_expression] = "cron(" + ["minute", "hour", "day_of_month", "month", "day_of_week", "year"].map { |i| @config['schedule'][i] }.join(" ") +")"
          end


          params
        end

      end
    end
  end
end
