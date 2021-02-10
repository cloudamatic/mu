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
      # A scheduled task facility as configured in {MU::Config::BasketofKittens::cdns}
      class CDN < MU::Cloud::CDN

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          resp = MU::Cloud::AWS.cloudfront(credentials: @credentials).create_cloud_front_origin_access_identity(
            cloud_front_origin_access_identity_config: {
              caller_reference: @mu_name,
              comment: @mu_name
            }
          )

          @origin_access_identity = "origin-access-identity/cloudfront/"+resp.cloud_front_origin_access_identity.id

          params = get_properties

          begin
            MU.log "Creating CloudFront distribution #{@mu_name}", details: params
            MU.retrier([Aws::CloudFront::Errors::InvalidOrigin], wait: 10, max: 6) {
              resp = MU::Cloud::AWS.cloudfront(credentials: @credentials).create_distribution_with_tags(
                distribution_config_with_tags: {
                  distribution_config: params,
                  tags: {
                    items: @tags.each_key.map { |k| { :key => k, :value => @tags[k] } }
                  }
                }
              )
              @cloud_id = resp.distribution.id
            }
            ready?
          rescue ::Aws::CloudFront::Errors::InvalidViewerCertificate => e
            cert_arn, cert_domains = MU::Cloud::AWS.findSSLCertificate(
              name: @config['certificate']["name"],
              id: @config['certificate']["id"],
              region: @config['certificate']['region'],
              credentials: @config['certificate']['credentials']
            )
            raise MuError.new e.message, details: { "aliases" => @config['aliases'], "certificate domains" => cert_domains }
          rescue ::Aws::CloudFront::Errors::InvalidOrigin => e
            raise MuError.new e.message, details: params[:origins]
          rescue ::Aws::CloudFront::Errors::InvalidArgument => e
            raise MuError.new e.message, details: params
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          params = get_properties

          if !@config['dns_records'].nil?
            if !MU::Cloud::AWS.isGovCloud?
              MU::Cloud.resourceClass("AWS", "DNSZone").createRecordsFromConfig(@config['dns_records'], target: cloud_desc.domain_name)
            end
          end
          MU.log "CloudFront Distribution #{@config['name']} at #{cloud_desc.domain_name}", MU::SUMMARY
          if @config['aliases']
            @config['aliases'].each { |a|
              MU.log "Alias for CloudFront Distribution #{@config['name']}: #{a}", MU::SUMMARY
            }
          end

          # Make sure we show up in the bucket policy of our target bucket,
          # if it's a sibling in this deploy
          cloud_desc(use_cache: false).origins.items.each { |o|
            if o.s3_origin_config
              id = o.s3_origin_config.origin_access_identity.sub(/^origin-access-identity\/cloudfront\//, '')
              bucketref = get_bucketref_from_domain(o.domain_name)
              next if !bucketref or !bucketref.kitten
              resp = MU::Cloud::AWS.cloudfront(credentials: @credentials).get_cloud_front_origin_access_identity(id: id)
#              bucketref.kitten.allowPrincipal("arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity "+id, doc_id: "PolicyForCloudFrontPrivateContent", permissions: ["GetObject"])
              bucketref.kitten.allowPrincipal(resp.cloud_front_origin_access_identity.s3_canonical_user_id, doc_id: "PolicyForCloudFrontPrivateContent", permissions: ["GetObject"], name: @mu_name)
            end
          }

        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc ? cloud_desc.arn : nil
        end

        # Return the metadata for this cdn
        # @return [Hash]
        def notify
          MU.structToHash(cloud_desc, stringify_keys: true)
        end

        # Wait until the distribution is ready (status is +Deployed+)
        def ready?
          self.class.ready?(@cloud_id, credentials: @credentials)
        end

        # Wait until a distribution is ready (status is +Deployed+)
        # @param id [String]
        # @param credentials [String]
        def self.ready?(id, credentials: nil)
          desc = nil
          MU.retrier([], loop_if: Proc.new { !desc or desc.status != "Deployed" }, wait: 30, max:60) {
            desc = MU::Cloud::AWS.cloudfront(credentials: credentials).get_distribution(id: id).distribution
          }
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          true
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::ALPHA
        end

        # Remove all cdns associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, credentials: nil, flags: {})

          resp = MU::Cloud::AWS.cloudfront(credentials: credentials).list_distributions
          if resp and resp.distribution_list and resp.distribution_list.items
            delete_threads = []
            ids = Hash[resp.distribution_list.items.map { |distro| [distro.arn, distro] }]

            ids.each_key { |arn|
              tags = MU::Cloud::AWS.cloudfront(credentials: credentials).list_tags_for_resource(resource: arn).tags.items

              found_muid = found_master = false
              name = nil
              tags.each { |tag|
                name = tag.value if tag.key == "Name"
                found_muid = true if tag.key == "MU-ID" && tag.value == deploy_id
                found_master = true if tag.key == "MU-MASTER-IP" && tag.value == MU.mu_public_ip
              }

              if found_muid and (ignoremaster or found_master)
                delete_threads << Thread.new(arn, name) { |my_arn, my_name|
                  current = MU::Cloud::AWS.cloudfront(credentials: credentials).get_distribution_config(id: ids[my_arn].id)
                  etag = current.etag

                  if !noop

                    if current.distribution_config.enabled
                      newcfg = MU.structToHash(current.distribution_config)
                      newcfg[:enabled] = false
                      MU.log "Disabling CloudFront distribution #{my_name ? my_name : ids[my_arn].id})", MU::NOTICE
                      updated = MU::Cloud::AWS.cloudfront(credentials: credentials).update_distribution(id: ids[my_arn].id, distribution_config: newcfg, if_match: etag)
                      etag = updated.etag
                    end

                  end

                  MU.log "Deleting CloudFront distribution #{my_name ? my_name : ids[my_arn].id})"
                  if !noop
                    ready?(ids[my_arn].id, credentials: credentials)
                    MU::Cloud::AWS.cloudfront(credentials: credentials).delete_distribution(id: ids[my_arn].id, if_match: etag)
                  end
                }
              end
            }
            delete_threads.each { |t| t.join }
          end

          resp = MU::Cloud::AWS.cloudfront(credentials: credentials).list_cloud_front_origin_access_identities
          if resp and resp.cloud_front_origin_access_identity_list and
             resp.cloud_front_origin_access_identity_list.items.each and
             deploy_id =~ /-\d{10}-[A-Z]{2}/
            resp.cloud_front_origin_access_identity_list.items.each { |ident|
              if ident.comment =~ /^#{Regexp.quote(deploy_id)}-/
                MU.log "Deleting CloudFront origin access identity #{ident.id} (#{ident.comment})"
                if !noop
                  getresp = MU::Cloud::AWS.cloudfront(credentials: credentials).get_cloud_front_origin_access_identity(id: ident.id)
                  begin
                    MU::Cloud::AWS.cloudfront(credentials: credentials).delete_cloud_front_origin_access_identity(id: ident.id, if_match: getresp.etag)
                  rescue ::Aws::CloudFront::Errors::CloudFrontOriginAccessIdentityInUse => e
                    MU.log "Got #{e.message} deleting #{ident.id}; it likely belongs to a distribution we can't to delete", MU::WARN, details: ident
                  end
                end
              end
            }
          end
        end

        # Locate an existing event.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching CloudWatch Event
        def self.find(**args)
          found = {}

          MU::Cloud::AWS.cloudfront(credentials: args[:credentials]).list_distributions.distribution_list.items.each { |d|
            next if args[:cloud_id] and ![d.id, d.arn].include?(args[:cloud_id])
            found[d.id] = d
          }

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**_args)
          bok = {
            "cloud" => "AWS",
            "credentials" => @credentials,
            "cloud_id" => @cloud_id
          }

          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end

          resp = MU::Cloud::AWS.cloudfront(credentials: @credentials).list_tags_for_resource(resource: arn)
          if resp and resp.tags and resp.tags.items
            tags = MU.structToHash(resp.tags.items, stringify_keys: true)
            bok['name'] = MU::Adoption.tagsToName(tags)
            bok['tags'] = tags if !tags.empty?
          end

          if !bok['name'] 
            bok['name'] = if cloud_desc.domain_name !~ /\.cloudfront\.net$/
              cloud_desc.domain_name.sub(/\..*/, '')
            elsif cloud_desc.aliases and !cloud_desc.aliases.items.empty?
              cloud_desc.aliases.items.first.sub(/\..*/, '')
            # XXX maybe try to guess from the name of an origin resource?
            else
              @cloud_id
            end
          end

          cloud_desc.origins.items.each { |o|
            bok['origins'] ||= []
            origin = {
              "path" => o.origin_path,
              "name" => o.id
            }
            if o.s3_origin_config
              origin["bucket"] = get_bucketref_from_domain(o.domain_name)
            end
            origin["domain_name"] = o.domain_name if !origin["bucket"]
            if o.custom_origin_config
              origin["http_port"] = o.custom_origin_config.http_port
              origin["https_port"] = o.custom_origin_config.https_port
              origin["protocol_policy"] = o.custom_origin_config.origin_protocol_policy
              origin["ssl_protocols"] = o.custom_origin_config.origin_ssl_protocols.items
            end

            if o.custom_headers and !o.custom_headers.empty?
            end

            bok['origins'] << origin
          }

          if cloud_desc.aliases and cloud_desc.aliases.items and
             !cloud_desc.aliases.items.empty?
            bok['aliases'] = cloud_desc.aliases.items
          end

          bok['disabled'] = true if !cloud_desc.enabled

          bok['behaviors'] = []

          add_behavior = Proc.new { |b, default|
            behavior = {}

            behavior["origin"] = b.target_origin_id
            behavior["path_pattern"] = b.path_pattern if b.respond_to?(:path_pattern)
            behavior["protocol_policy"] = b.viewer_protocol_policy
            if b.lambda_function_associations and !b.lambda_function_associations.items.empty?
              b.lambda_function_associations.items.each { |f|
                behavior['functions'] ||= []
                f.lambda_function_arn.match(/^arn:.*?:lambda:([^:]+?):(\d*):function:([^:]+)/)
                region = Regexp.last_match[1]
                acct = Regexp.last_match[2]
                id = Regexp.last_match[3]
                behavior['functions'] << MU::Config::Ref.get(
                  id: id,
                  region: region,
                  type: "functions",
                  event_type: f.event_type,
                  include_body: f.include_body,
                  cloud: "AWS",
                  credentials: @credentials,
                  habitat: MU::Config::Ref.get(
                    id: acct,
                    cloud: "AWS",
                    credentials: @credentials
                  )
                )
              }
              [:min_ttl, :default_ttl, :max_ttl].each { |ttl|
                behavior[ttl.to_s] = b.send(ttl)
              }
            end
            bok['behaviors'] << behavior
          }

          add_behavior.call(cloud_desc.default_cache_behavior, true)

          if cloud_desc.cache_behaviors and
             !cloud_desc.cache_behaviors.items.empty?
            cloud_desc.cache_behaviors.items.each { |b|
              add_behavior.call(b, false)
            }
          end

          bok
        end


        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []

          schema = {
            "disabled" => {
              "type" => "boolean",
              "description" => "Flag this CloudFront distribution as disabled",
              "default" => false
            },
            "certificate" => MU::Config::Ref.schema(type: "certificate", desc: "Required if any domains have been specified with +aliases+; parser will attempt to autodetect a valid ACM or IAM certificate if not specified.", omit_fields: ["cloud", "tag", "deploy_id"]),
            "behaviors" => {
              "items" => {
                "properties" => {
                  "min_ttl" => {
                    "type" => "integer",
                    "description" => "The minimum amount of time that you want objects to stay in CloudFront caches before CloudFront forwards another request to your origin to determine whether the object has been updated.",
                    "default" => 0
                  },
                  "default_ttl" => {
                    "type" => "integer",
                    "description" => "The default amount of time that you want objects to stay in CloudFront caches before CloudFront forwards another request to your origin to determine whether the object has been updated.",
                    "default" => 86400
                  },
                  "max_ttl" => {
                    "type" => "integer",
                    "description" => "The maximum amount of time that you want objects to stay in CloudFront caches before CloudFront forwards another request to your origin to determine whether the object has been updated.",
                    "default" => 31536000
                  },
                  "protocol_policy" => {
                    "type" => "string",
                    "enum" => %w{allow-all https-only redirect-to-https},
                    "default" => "redirect-to-https"
                  },
                  "functions" => {
                    "type" => "array",
                    "items" => MU::Config::Ref.schema(type: "functions", desc: "Add a Lambda function which can be invoked on requests or responses through this distribution.")
                  },
                  "forwarded_values" => {
                    "type" => "object",
                    "description" => "HTTP request artifacts to include in requests passed to our back-end +origin+",
                    "default" => {
                      "query_string" => false
                    },
                    "properties" => {
                      "query_string" => {
                        "type" => "boolean",
                        "description" => "Indicates whether you want CloudFront to forward query strings to the origin that is associated with this cache behavior and cache based on the query string parameters.",
                        "default" => false
                      },
                      "cookies" => {
                        "type" => "object",
                        "description" => "A complex type that specifies whether you want CloudFront to forward cookies to the origin and, if so, which ones.",
                        "default" => {
                          "forward" => "none"
                        },
                        "properties" => {
                          "forward" => {
                            "type" => "string",
                            "description" => "Specifies which cookies to forward to the origin for this cache behavior: all, none, or the list of cookies specified in +whitelisted_names+",
                            "enum" => %w{none whitelist all}
                          },
                          "whitelisted_names" => {
                            "type" => "array",
                            "items" => {
                              "description" => "Required if you specify whitelist for the value of +forward+",
                              "type" => "string"
                            }
                          },
                        }
                      },
                      "headers" => {
                        "type" => "array",
                        "items" => {
                          "description" => "Specifies the headers, if any, that you want CloudFront to forward to the origin for this cache behavior (whitelisted headers).",
                          "type" => "string"
                        }
                      },
                      "query_string_cache_keys" => {
                        "type" => "array",
                        "items" => {
                          "description" => "Indicates whether you want CloudFront to forward query strings to the origin that is associated with this cache behavior and cache based on the query string parameters",
                          "type" => "string"
                        }
                      }
                    }
                  }
                }
              }
            },
            "origins" => {
              "items" => {
                "properties" => {
                  "bucket" => MU::Config::Ref.schema(type: "buckets", desc: "Reference an S3 bucket for use as an origin"),
                  "endpoint" => MU::Config::Ref.schema(type: "endpoints", desc: "Reference an API Gateway for use as an origin"),
                  "loadbalancer" => MU::Config::Ref.schema(type: "loadbalancers", desc: "Reference a Load Balancer for use as an origin"),
                  "connection_attempts" => {
                    "type" => "integer",
                    "default" => 3
                  },
                  "connection_timeout" => {
                    "type" => "integer",
                    "default" => 10
                  },
                  "protocol_policy" => {
                    "type" => "string",
                    "enum" => %w{http-only https-only match-viewer},
                    "default" => "match-viewer"
                  },
                  "ssl_protocols" => {
                    "type" => "array",
                    "default" => ["TLSv1.2"],
                    "items" => {
                      "type" => "string",
                      "enum" => %w{SSLv3 TLSv1 TLSv1.1 TLSv1.2},
                    }
                  },
                  "http_port" => {
                    "type" => "integer",
                    "default" => 80
                  },
                  "https_port" => {
                    "type" => "integer",
                    "default" => 443
                  },
                  "custom_headers" => {
                    "type" => "array",
                    "items" => {
                      "description" => "A list of HTTP header names and values that CloudFront adds to requests it sends to the origin.",
                      "type" => "object",
                      "required" => ["key", "value"],
                      "properties" => {
                        "key" => {
                          "type" => "string"
                        },
                        "value" => {
                          "type" => "string"
                        },
                      }
                    }
                  }
                }
              }
            }
          }

          schema["behaviors"]["items"]["properties"]["functions"]["items"]["include_body"] = {
            "type" => "boolean",
            "default" => false
          }
          schema["behaviors"]["items"]["properties"]["functions"]["items"]["event_type"] = {
            "type" => "string",
            "enum" => %w{viewer-request viewer-response origin-request origin-response},
            "default" => "viewer-request"
          }

          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::cdns}, bare and unvalidated.
        # @param cdn [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(cdn, configurator)
          ok = true

          cdn['origins'].each { |o|
            count = 0
            ['bucket', 'endpoint', 'loadbalancer'].each { |sib_type|
              if o[sib_type]
                if count > 0
                  ok = false
                  MU.log "Origin in CloudFront distro #{cdn['name']} may specify at most one of bucket, endpoint, or loadbalancer.", MU::ERR
                end
                target_ref = MU::Config::Ref.get(o[sib_type])
                if target_ref.name
                  MU::Config.addDependency(cdn, target_ref.name, sib_type, their_phase: "groom")
                end
                count += 1
              end
            }
          }

          cert_domains = nil

          if cdn['certificate']
            cert_arn, cert_domains = MU::Cloud::AWS.resolveSSLCertificate(cdn['certificate'], region: cdn['region'], credentials: cdn['credentials'])
            if !cert_arn
              MU.log "Failed to find an ACM or IAM certificate specified in CloudFront distribution #{cdn['name']}", MU::ERR, details: cdn['certificate'].to_h
              ok = false
            end
          end

          if cdn['aliases']
            cdn['aliases'].each { |a|
              if !cdn['certificate']
                foundcert, cert_domains = MU::Cloud::AWS.findSSLCertificate(name: a, region: cdn['region'], credentials: cdn['credentials'], raise_on_missing: false)
                if !foundcert
                  foundcert, cert_domains = MU::Cloud::AWS.findSSLCertificate(name: a.sub(/^[^\.]+\./, '*.'), region: cdn['region'], credentials: cdn['credentials'], raise_on_missing: false)
                end
                if !foundcert
                  MU.log "Failed to find an ACM or IAM certificate matching #{a} for CloudFront distribution #{cdn['name']}", MU::ERR
                  ok = false
                else
                  cdn['certificate'] = {
                    "id" => foundcert,
                    "credentials" => cdn['credentials']
                  }
                  MU.log "Auto-detected SSL certificate for CloudFront distribution #{cdn['name']} alias #{a}", MU::NOTICE, details: cdn['certificate']['id']
                end
              else
                if !MU::Cloud::AWS.nameMatchesCertificate(a, cdn['certificate']['id'])
                  MU.log "Alias #{a} in CloudFront distro #{cdn['name']} does not appear to fit any domains on our SSL certificate", MU::ERR, details: cert_domains
                  ok = false
                end
              end
            }
          end

          if cdn['dns_records'] and cdn['certificate']
            cdn['dns_records'].each { |rec|
              next if !rec['name']
              dnsname = MU::Cloud.resourceClass("AWS", "DNSZone").recordToName(rec)
              if MU::Cloud::AWS.nameMatchesCertificate(dnsname, cdn['certificate']['id'])
                cdn['aliases'] ||= []
                cdn['aliases'] << dnsname if !cdn['aliases'].include?(dnsname)
              end
            }
          end

          path_patterns = {}
          cdn['behaviors'].each { |b|
            b['path_pattern'] ||= "*"
            path_patterns[b['path_pattern']] ||= 0
            path_patterns[b['path_pattern']] += 1
          }
          path_patterns.each_pair { |pattern, origins|
            if origins > 1
              MU.log "CDN #{cdn['name']} has #{origins.to_s} uses of path_pattern '#{pattern}' in its behavior list (must be unique)", MU::ERR, details: cdn['behaviors']
              ok = false
            end
          }

          ok
        end

        private

        def get_properties
          params = {
            default_root_object: @config['default_object'],
            caller_reference: @mu_name, # eh, probably should be random
            origins: {
              quantity: @config['origins'].size,
              items: []
            },
            comment: @deploy.deploy_id,
            enabled: !(@config['disabled'])
          }

          if @config['certificate']
            params[:viewer_certificate] = {
              ssl_support_method: "sni-only"
            }
            if @config['certificate']['id'] =~ /^arn:aws(?:-us-gov)?:iam/
              params[:viewer_certificate][:iam_certificate_id] = @config['certificate']['id']
              params[:viewer_certificate][:certificate_source] = "iam"
            elsif @config['certificate']['id'] =~ /^arn:aws(?:-us-gov)?:acm/
              params[:viewer_certificate][:acm_certificate_arn] = @config['certificate']['id']
              params[:viewer_certificate][:certificate_source] = "acm"
            end

          end

          @config['origins'].each { |o|
            origin = {
              id: o['name'],
            }
            sib_obj = nil
            ['bucket', 'endpoint', 'loadbalancer'].each { |sib_type|
              if o[sib_type]
                sib_obj = MU::Config::Ref.get(o[sib_type]).kitten(@deploy, cloud: "AWS")
                if !sib_obj
                  raise MuError.new "Failed to resolve #{sib_type} referenced in CloudFront distribution #{@config['name']}", details: o[sib_type].to_h
                end
                break
              end
            }
            if o['bucket']
              origin[:domain_name] = sib_obj.cloud_desc["name"]+".s3.amazonaws.com"
              origin[:origin_path] = o['path'] if o['path']
              origin[:s3_origin_config] = {
                origin_access_identity: @origin_access_identity
              }
            elsif o['endpoint']
              origin[:domain_name] = sib_obj.cloud_id+".execute-api."+sib_obj.config['region']+".amazonaws.com"
              origin[:custom_origin_config] = {
                origin_protocol_policy: "https-only"
              }
              if sib_obj.config['deploy_to']
                origin[:origin_path] ||= "/"+sib_obj.config['deploy_to']
              end
            elsif o['loadbalancer']
              origin[:domain_name] = sib_obj.cloud_desc.dns_name
              origin[:origin_path] = o['path'] if o['path']
            else # XXX make sure parser guarantees these are present
              origin[:domain_name] = o['domain_name']
              origin[:origin_path] = o['path']
            end

            if o['custom_headers']
              origin[:custom_headers] = {
                quantity: o['custom_headers'].size,
                items: o['custom_headers'].map { |h|
                  {
                    header_name: h['key'],
                    header_value: h['value']
                  }
                }
              }
            end

            [:connection_attempts, :connection_timeout].each { |field|
              origin[field] ||= o[field.to_s]
            }
            if !origin[:s3_origin_config]
              maplet = {
                'protocol_policy' => :origin_protocol_policy,
                'ssl_protocols' => :origin_ssl_protocols,
                'http_port' => :http_port,
                'https_port' => :https_port
              }
              maplet.each_pair { |field, paramfield|
                next if !o[field]
                origin[:custom_origin_config] ||= {}
                origin[:custom_origin_config][paramfield] ||= if o[field.to_s].is_a?(Array)
                  {
                    quantity: o[field].size,
                    items: o[field]
                  }
                else
                  o[field]
                end
              }
            end

            params[:origins][:items] << origin
          }

          # if we have any placeholder DNS records that are intended to be
          # filled out with our runtime @mu_name, do so, and add an alias if
          # applicable
          if @config['dns_records']
            @config['dns_records'].each { |rec|
              if !rec['name']
                rec['name'] = @mu_name.downcase
                dnsname = MU::Cloud.resourceClass("AWS", "DNSZone").recordToName(rec)
                if @config['certificate'] and MU::Cloud::AWS.nameMatchesCertificate(dnsname, @config['certificate']['id'])
                  @config['aliases'] ||= []
                  @config['aliases'] << dnsname if !@config['aliases'].include?(dnsname)
                end
              end
            }
          end

          if @config['aliases']
            params[:aliases] = {
              items: @config['aliases'],
              quantity: @config['aliases'].size
            }
          end

          # XXX config parser should guarantee a default behavior
          @config['behaviors'].each { |b|
            b['origin'] ||= @config['origins'].first['name']
            behavior = {
              target_origin_id: b['origin'],
              viewer_protocol_policy: b['protocol_policy'],
              min_ttl: b['min_ttl'],
              max_ttl: b['max_ttl'],
              default_ttl: b['default_ttl'],
            }
            behavior[:trusted_signers] = {
              enabled: false,
              quantity: 0,
#              items: []
            }
            behavior[:forwarded_values] = {
              query_string: b['forwarded_values']['query_string'],
              cookies: {
                forward: b['forwarded_values']['cookies']['forward']
              }
            }
            if b['forwarded_values']['cookies']['whitelisted_names']
              behavior[:forwarded_values][:cookies][:whitelisted_names] = {
                quantity: b['forwarded_values']['cookies']['whitelisted_names'].size,
                items: b['forwarded_values']['cookies']['whitelisted_names']
              }
            end
            ['headers', 'query_string_cache_keys'].each { |field|
              if b['forwarded_values'][field]
                behavior[:forwarded_values][field.to_sym] = {
                  quantity: b['forwarded_values'][field].size,
                  items: b['forwarded_values'][field]
                }
              end
            }

            if @config['behaviors'].size == 1 or b['path_pattern'] == "*"
              params[:default_cache_behavior] = behavior
            else
              behavior[:path_pattern] = b['path_pattern']
              params[:cache_behaviors] ||= {
                quantity: (@config['behaviors'].size-1),
                items: []
              }
              params[:cache_behaviors][:items] << behavior
            end
          }

          params
        end

        def get_bucketref_from_domain(domain_name)
          buckets = MU::Cloud.resourceClass("AWS", "Bucket").find(credentials: @credentials, allregions: true, cloud_id: domain_name.sub(/\..*/, ''))
          if buckets and buckets.size == 1
            return MU::Config::Ref.get(
              id: buckets.keys.first,
              type: "buckets",
              region: buckets.values.first["region"],
              credentials: @credentials,
              cloud: "AWS"
            )
          else
            MU.log "Failed to locate or isolate a bucket object from #{domain_name}", MU::WARN, details: buckets.keys
          end

          nil
        end

      end
    end
  end
end
