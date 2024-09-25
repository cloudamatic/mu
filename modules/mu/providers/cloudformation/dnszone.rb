# Copyright:: Copyright (c) 2016 eGlobalTech, Inc., all rights reserved
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
    class CloudFormation
      # A log target as configured in {MU::Config::BasketofKittens::dnszones}
      class DNSZone < MU::Cloud::DNSZone

        @deploy = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        attr_reader :cfm_template
        attr_reader :cfm_name

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::dnszones}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          else
            @mu_name ||= @deploy.getResourceName(@config["name"])
          end
        end

        # Populate @cfm_template with a resource description for this dnszone
        # in CloudFormation language.
        def create
          @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase("dnszone", self, scrub_mu_isms: @config['scrub_mu_isms'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Name", @config['name'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "HostedZoneConfig", { "Comment" => MU.deploy_id })

          if @config['private']
            if @config['all_account_vpcs']
# XXX would need a way to add tails (CloudFormation paramaters, effectively) here in order to prompt the user for stuff like which pre-existing VPCs to plug in. Maybe we can have the config parser do that for is and pass it all in as @config['vpcs'], which would in turn be Refs to parameters? It'd need to know about the -c flag for AWS resources being converted on the fly.
#            MU::Config.getTail("#{parent_name}vpc_id", value: vpc_block["vpc_id"], prettyname: "#{parent_name} Target VPC",  cloudtype: "AWS::EC2::VPC::Id")
              raise MuCloudFlagNotImplemented, "DNSZone parameter 'all_account_vpcs' currently not supported for CloudFormation targets"
            else
              raise MuError, "DNS Zone #{@config['name']} is flagged as private, you must provide a VPC to allow access." if @config['vpcs'].nil? || @config['vpcs'].empty?
              @config['vpcs'].each { |vpc|
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "VPCs", { "VPCId" => vpc['vpc_id'], "VPCRegion" => vpc['region'] })
              }
            end
          end

          @config['records'].each { |dnsrec|
            dnsrec['realtarget'] =
              if dnsrec['mu_type'] == "loadbalancer"

                if @dependencies.has_key?("loadbalancer") && dnsrec['deploy_id'].nil?
                  if dnsrec['type'] == "R53ALIAS"
                    dnsrec['alias_zone'] = { "Fn::GetAtt" => [@dependencies["loadbalancer"][dnsrec['target']].cloudobj.cfm_name, "CanonicalHostedZoneNameID"] }
                  end
                  { "Fn::GetAtt" => [@dependencies["loadbalancer"][dnsrec['target']].cloudobj.cfm_name, "DNSName"] }
                elsif dnsrec['deploy_id']
                  found = MU::MommaCat.findStray("AWS", "loadbalancer", deploy_id: dnsrec["deploy_id"], mu_name: dnsrec["target"], region: @config["region"])
                  raise MuError, "Couldn't find #{dnsrec['mu_type']} #{dnsrec["target"]}" if found.nil? || found.empty?
                  found.first.deploydata['dns']
                end
              elsif dnsrec['mu_type'] == "server"
                public = true
                if dnsrec.has_key?("target_type")
                  public = dnsrec["target_type"] == "private" ? false : true
                end
                if @dependencies.has_key?("server") && dnsrec['deploy_id'].nil?
                  if dnsrec["type"] == "CNAME"
                    if public
                      { "Fn::GetAtt" => [@dependencies["server"][dnsrec['target']].cloudobj.cfm_name, "PublicDnsName"] }
                    else
                      { "Fn::GetAtt" => [@dependencies["server"][dnsrec['target']].cloudobj.cfm_name, "PrivateDnsName"] }
                    end
                  elsif dnsrec["type"] == "A"
                    if public
                      { "Fn::GetAtt" => [@dependencies["server"][dnsrec['target']].cloudobj.cfm_name, "PublicIp"] }
                    else
                      { "Fn::GetAtt" => [@dependencies["server"][dnsrec['target']].cloudobj.cfm_name, "PrivateIp"] }
                    end
                  end
                elsif dnsrec['deploy_id']
                  found = MU::MommaCat.findStray("AWS", "server", deploy_id: dnsrec["deploy_id"], mu_name: dnsrec["target"], region: @config["region"])
                  raise MuError, "Couldn't find #{dnsrec['mu_type']} #{dnsrec["target"]}" if found.nil? || found.empty?
                  deploydata = found.first.deploydata
                  if dnsrec["type"] == "CNAME"
                    if public
                      deploydata['public_dns_name'].empty? ? deploydata['private_dns_name'] : deploydata['public_dns_name']
                    else
                      deploydata['private_dns_name']
                    end
                  elsif dnsrec["type"] == "A"
                    if public
                      deploydata['public_ip_address'] ? deploydata['public_ip_address'] : deploydata['private_ip_address']
                    else
                      deploydata['private_ip_address']
                    end
                  end
                end
              elsif dnsrec['mu_type'] == "database"
                if @dependencies.has_key?(dnsrec['mu_type']) && dnsrec['deploy_id'].nil?
                  { "Fn::GetAtt" => [@dependencies["database"][dnsrec['target']].cloudobj.cfm_name, "Endpoint.Address"] }
                elsif dnsrec['deploy_id']
                  found = MU::MommaCat.findStray("AWS", "database", deploy_id: dnsrec["deploy_id"], mu_name: dnsrec["target"], region: @config["region"])
                  raise MuError, "Couldn't find #{dnsrec['mu_type']} #{dnsrec["target"]}" if found.nil? || found.empty?
                  found.first.deploydata['endpoint']
                end
              end
            if !dnsrec['hosted_zone_id']
              dnsrec['hosted_zone_id'] = { "Ref" => @cfm_name }
            end
            dnsrec['hosted_zone_name'] = @config['name']

            if dnsrec['append_environment_name']
              dnsrec['name'] = dnsrec['name'] + "." + @deploy.environment.downcase
            end
            dnsrec['name'] = dnsrec['name'] + "." + @config['name'] + "."
          }
          records = MU::Cloud::CloudFormation::DNSZone.createRecordsFromConfig(@config['records'])
          records.each_pair { |name, rec|
            MU::Cloud::CloudFormation.setCloudFormationProp(records[name], "DependsOn", @cfm_name)

          }
          @cfm_template.merge!(records)
        end

        # @param cfg [Array]: An array of parsed {MU::Config::BasketofKittens::dnszones::records} objects.
        # @param target [String]: Optional target for the records to be created. Overrides targets embedded in cfg records.
        def self.createRecordsFromConfig(cfg, target: nil)
          templates = {}
          counts = {}
          cfg.each { |dnsrec|
          target = dnsrec['realtarget'] ? dnsrec['realtarget'] : dnsrec['target']
            dnsrec['realtarget'] = target if !dnsrec['realtarget']
            if !counts.has_key?(target)
              counts[target] = 1
            else
              counts[target] = counts[target] + 1
            end
          }
          cfg.each { |dnsrec|
            rec_name, rec_template = MU::Cloud::CloudFormation.cloudFormationBase("dnsrecord", name: dnsrec['name']+dnsrec['target']+dnsrec['type'], scrub_mu_isms: dnsrec['scrub_mu_isms'])
            MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "Name", dnsrec['name'])

            if dnsrec['type'] == "R53ALIAS"
              alias_target = {
                "DNSName" => dnsrec['realtarget'],
                "HostedZoneId" => dnsrec['alias_zone']
              }
              MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "AliasTarget", alias_target)
              MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "Type", "A")
            else
              MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "ResourceRecords", dnsrec['realtarget'])
              MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "TTL", dnsrec['ttl'])
              MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "Type", dnsrec['type'])
            end

            if counts[dnsrec['realtarget']] > 1
              MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "SetIdentifier", rec_name)
            end

            if dnsrec['geo_location']
            MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "SetIdentifier", rec_name)
              loc = {}
              ["continent_code", "country_code", "subdivision_code"].each { |arg|
                if !dnsrec['geo_location'][arg].nil?
                  key = ""
                  arg.split(/_/).each { |chunk| key = key + chunk.capitalize }
                  loc[key] = dnsrec['geo_location'][arg]
                end
              }
              MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "GeoLocation", loc)
            end

            if dnsrec['healthcheck']
              check_name, check_template = MU::Cloud::CloudFormation.cloudFormationBase("dnshealthcheck", name: dnsrec['name']+dnsrec['target']+dnsrec['type'], scrub_mu_isms: dnsrec['scrub_mu_isms'])
              check = {
                "Type" => dnsrec['healthcheck']['method']
              }
              dnsrec['healthcheck']["request_interval"] = dnsrec['healthcheck']["check_interval"]
              dnsrec['healthcheck']["resource_path"] = dnsrec['healthcheck']["path"]
              ["failure_threshold", "resource_path", "port", "search_string", "request_internal"].each { |arg|
                if !dnsrec['healthcheck'][arg].nil?
                  key = ""
                  arg.split(/_/).each { |chunk| key = key + chunk.capitalize }
                  check[key] = dnsrec['healthcheck'][arg]
                end
              }
              if ["A", "AAAA"].include?(dnsrec['type'])
                check["IPAddress"] = dnsrec['realtarget']
              else
                check["FullyQualifiedDomainName"] = dnsrec['realtarget']
              end
              MU::Cloud::CloudFormation.setCloudFormationProp(check_template[check_name], "HealthCheckConfig", check)

              MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "HealthCheckId", { "Ref" => check_name })
              MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "DependsOn", check_name)
              rec_template.merge!(check_template)
            end

            MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "Failover", dnsrec['failover']) if dnsrec['failover']
            MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "Region", dnsrec['region']) if dnsrec['region']
            MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "Weight", dnsrec['weight']) if dnsrec['weight']
            if dnsrec['hosted_zone_id']
              MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "HostedZoneId", dnsrec['hosted_zone_id'])
            elsif dnsrec['hosted_zone_name']
              MU::Cloud::CloudFormation.setCloudFormationProp(rec_template[rec_name], "HostedZoneName", dnsrec['hosted_zone_name'])
            else
              raise MuError, "Records must have either hosted_zone_name or hosted_zone_id into MU::Clouds::CloudFormation::DNSZone.createRecordsFromConfig"
            end
            if rec_template[rec_name]["Properties"]["ResourceRecords"].size == 0
              rec_template[rec_name]["Properties"].delete("ResourceRecords")
            end
            templates.merge!(rec_template)
          }
          templates
        end

        # Return the metadata for this CacheCluster
        # @return [Hash]
        def notify
          {}
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
        def self.genericMuDNSEntry(**args)
          MU.log "find() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          MU::Cloud.resourceClass("AWS", "DNSZone").schema(config)
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::servers}, bare and unvalidated.
        # @param server [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(server, configurator)
          MU::Cloud.resourceClass("AWS", "DNSZone").validateConfig(server, configurator)
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          MU::Cloud.resourceClass("AWS", "DNSZone").isGlobal?
        end

      end
    end
  end
end
