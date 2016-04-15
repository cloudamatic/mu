# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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

require "net/http"
module MU
  class Cloud
    # Support for Amazon Web Services as a provisioning layer.
    class CloudFormation

      @@cloudformation_mode = false

      # Toggle ourselves into a mode that will emit a CloudFormation template
      # instead of actual infrastructure.
      # @param set [Boolean]: Set the mode
      def self.emitCloudFormation(set: @@cloudformation_mode)
        @@cloudformation_mode = set
        @@cloudformation_mode
      end

      # Generate and return a skeletal CloudFormation resource entry for the
      # caller.
      # param type [String]: The resource type, in Mu parlance
      # param cloudobj [MU::Clouds::AWS]: The resource object
      # param name [String]: An alternative name for resources which are not first-class Mu classes with their own objects
      def self.cloudFormationBase(type, cloudobj = nil, name: nil, tags: [])
        desc = {}
        tags = [] if tags.nil?
        realtags = []
        tags.each { |tag|
          if tag['value'].class.to_s == "MU::Config::Tail"
            tag['value'] = { "Ref" => "#{tag['value'].getPrettyName}" }
          end
          realtags << { "Key" => tag['key'], "Value" => tag['value'] }
        }
        tags = realtags
        MU::MommaCat.listStandardTags.each_pair { |key, val|
          next if ["MU-OWNER", "MU-MASTER-IP", "MU-MASTER-NAME"].include?(key)
          if key == "MU-ID"
            val = { "Fn::Join" => ["", [ { "Ref" => "Environment" }, "-", { "Ref" => "AWS::StackName" } ] ] }
          elsif key == "MU-ENV"
            val =  { "Ref" => "Environment" }
          end
          tags << { "Key" => key, "Value" => val }
        }

        res_name = ""
        res_name = cloudobj.config["name"] if !cloudobj.nil?
        if name.nil?
          nametag = { "Fn::Join" => ["", [ { "Ref" => "Environment" }, "-", { "Ref" => "AWS::StackName" }, "-", res_name.gsub(/[^a-z0-9]/i, "").upcase ] ] }
          basename = ""
          basename = cloudobj.mu_name if !cloudobj.nil? and !cloudobj.mu_name.nil?
          name = (type+basename).gsub!(/[^a-z0-9]/i, "")
          tags << { "Key" => "Name", "Value" => nametag }
        else
          name = (type+name).gsub(/[^a-z0-9]/i, "")
          tags << { "Key" => "Name", "Value" => name }
        end

        case type
        when "dnshealthcheck"
          desc = {
            "Type" => "AWS::Route53::HealthCheck",
            "Properties" => {
              "HealthCheckTags" => tags
            }
          }
        when "dnszone"
          desc = {
            "Type" => "AWS::Route53::HostedZone",
            "Properties" => {
              "HostedZoneTags" => tags,
              "VPCs" => [],
            }
          }
        when "dnsrecord"
          desc = {
            "Type" => "AWS::Route53::RecordSet",
            "Properties" => {
              "ResourceRecords" => []
            }
          }
        when "logmetricfilter"
          desc = {
            "Type" => "AWS::Logs::MetricFilter",
            "Properties" => {
              "MetricTransformations" => []
            }
          }
        when "loggroup"
          desc = {
            "Type" => "AWS::Logs::LogGroup",
            "Properties" => {
            }
          }
        when "logstream"
          desc = {
            "Type" => "AWS::Logs::LogStream",
            "Properties" => {
            }
          }
        when "alarm"
          desc = {
            "Type" => "AWS::CloudWatch::Alarm",
            "Properties" => {
              "AlarmActions" => [],
              "Dimensions" => [],
              "InsufficientDataActions" => [],
              "OKActions" => []
            }
          }
        when "notification"
          desc = {
            "Type" => "AWS::SNS::Topic",
            "Properties" => {
              "Subscription" => []
            }
          }
        when "vpc"
          desc = {
            "Type" => "AWS::EC2::VPC",
            "Properties" => {
              "Tags" => tags
            }
          }
        when "subnet"
          desc = {
            "Type" => "AWS::EC2::Subnet",
            "Properties" => {
              "Tags" => tags
            }
          }
        when "vpcgwattach"
          desc = {
            "Type" => "AWS::EC2::VPCGatewayAttachment",
            "Properties" => {
            }
          }
        when "loggroup"
          desc = {
            "Type" => "AWS::EC2::LogGroup",
            "Properties" => {
            }
          }
        when "cache_subnets"
          desc = {
            "Type" => "AWS::ElastiCache::SubnetGroup",
            "Properties" => {
              "Description" => name,
              "SubnetIds" => []
            }
          }
        when "cache_repl_group"
          desc = {
            "Type" => "AWS::ElastiCache::ReplicationGroup",
            "Properties" => {
              "SecurityGroupIds" => []
            }
          }
        when "cache_cluster"
          desc = {
            "Type" => "AWS::ElastiCache::CacheCluster",
            "Properties" => {
              "Tags" => tags,
              "VpcSecurityGroupIds" => []
            }
          }
        when "nat"
          desc = {
            "Type" => "AWS::EC2::NatGateway",
            "Properties" => {
            }
          }
        when "igw"
          desc = {
            "Type" => "AWS::EC2::InternetGateway",
            "Properties" => {
              "Tags" => tags
            }
          }
        when "rtb"
          desc = {
            "Type" => "AWS::EC2::RouteTable",
            "Properties" => {
              "Tags" => tags
            }
          }
        when "rtbassoc"
          desc = {
            "Type" => "AWS::EC2::SubnetRouteTableAssociation",
            "Properties" => {
            }
          }
        when "route"
          desc = {
            "Type" => "AWS::EC2::Route",
            "Properties" => {
            }
          }
        when "database"
          desc = {
            "Type" => "AWS::RDS::DBInstance",
            "Properties" => {
              "Tags" => tags,
              "VPCSecurityGroups" => [],
              "DBSecurityGroups" => []
            }
          }
        when "dbsubnetgroup"
          desc = {
            "Type" => "AWS::RDS::DBSubnetGroup",
            "Properties" => {
              "Tags" => tags,
              "SubnetIds" => []
            }
          }
        when "server"
          desc = {
            "Type" => "AWS::EC2::Instance",
            "Properties" => {
              "Volumes" => [],
              "Tags" => tags,
              "SecurityGroupIds" => [],
              "BlockDeviceMappings" => []
            }
          }
        when "launch_config"
          desc = {
            "Type" => "AWS::AutoScaling::LaunchConfiguration",
            "Properties" => {
              "SecurityGroups" => [],
              "BlockDeviceMappings" => []
            }
          }
        when "server_pool"
          pool_tags = tags.dup
          pool_tags.each { |tag|
            tag["PropagateAtLaunch"] = true
          }
          desc = {
            "Type" => "AWS::AutoScaling::AutoScalingGroup",
            "Properties" => {
              "Tags" => pool_tags,
              "VPCZoneIdentifier" => [],
              "TerminationPolicies" => [],
              "LoadBalancerNames" => []
            }
          }
        when "scaling_policy"
          desc = {
            "Type" => "AWS::AutoScaling::ScalingPolicy",
            "Properties" => {
              "StepAdjustments" => []
            }
          }
        when "loadbalancer"
          desc = {
            "Type" => "AWS::ElasticLoadBalancing::LoadBalancer",
            "Properties" => {
              "Tags" => tags,
              "SecurityGroups" => [],
              "LBCookieStickinessPolicy" => [],
              "Subnets" => [],
              "Listeners" => []
            }
          }
        when "firewall_rule"
          desc = {
            "Type" => "AWS::EC2::SecurityGroup",
            "Properties" => {
              "Tags" => tags,
              "SecurityGroupIngress" => []
            }
          }
        when "volume"
          desc = {
            "Type" => "AWS::EC2::Volume",
            "Properties" => {
              "Tags" => tags
            }
          }
        when "eip"
          desc = {
            "Type" => "AWS::EC2::EIP",
            "Properties" => {
            }
          }
        when "eipassoc"
          desc = {
            "Type" => "AWS::EC2::EIPAssociation",
            "Properties" => {
            }
          }
        when "iamprofile"
          desc = {
            "Type" => "AWS::IAM::InstanceProfile",
            "Properties" => {
              "Path" => "/",
              "Roles" => [],
            }
          }
        when "iamrole"
          desc = {
            "Type" => "AWS::IAM::Role",
            "Properties" => {
              "Path" => "/",
              "Policies" => [],
              "AssumeRolePolicyDocument" => JSON.parse('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}')
            }
          }
        else
          MU.log "Dunno how to make a CloudFormation chunk for #{type} yet", MU::WARN
          return
        end
        desc["DependsOn"] = []
        if !cloudobj.nil? and cloudobj.respond_to?(:dependencies) and type != "subnet"
          cloudobj.dependencies(use_cache: true).first.each_pair { |resource_classname, resources|
            resources.each_pair { |sibling_name, sibling_obj|
              next if sibling_obj == cloudobj
              desc["DependsOn"] << (resource_classname+sibling_obj.cloudobj.mu_name).gsub!(/[^a-z0-9]/i, "")
              # Common resource-specific references to dependencies
              if resource_classname == "firewall_rule"
                if type == "database" and cloudobj.config.has_key?("vpc")
                  desc["Properties"]["VPCSecurityGroups"] << { "Fn::GetAtt" => [(resource_classname+sibling_obj.cloudobj.mu_name).gsub!(/[^a-z0-9]/i, ""), "GroupId"] }
                else
                  ["VpcSecurityGroupIds", "SecurityGroupIds", "SecurityGroups"].each { |key|
                    if desc["Properties"].has_key?(key)
                      desc["Properties"][key] << { "Fn::GetAtt" => [(resource_classname+sibling_obj.cloudobj.mu_name).gsub!(/[^a-z0-9]/i, ""), "GroupId"] }
                    end
                  }
                end
              elsif resource_classname == "loadbalancer"
                if desc["Properties"].has_key?("LoadBalancerNames")
                  desc["Properties"]["LoadBalancerNames"] << { "Ref" => (resource_classname+sibling_obj.cloudobj.mu_name).gsub!(/[^a-z0-9]/i, "") }
                end
              end
            }
          }
        end
        return [name, { name => desc }]
      end

      def self.setCloudFormationProp(resource, name, value)
        realvalue = value
        is_list_element = false
        if value.class.to_s == "MU::Config::Tail"
          if value.is_list_element
            realvalue = { "Fn::Select" => [0, { "Ref" => "#{value.getPrettyName}" }] }
            is_list_element = true
          else
            realvalue = { "Ref" => "#{value.getPrettyName}" }
          end
        end

        if resource.has_key?(name) and name != "Type"
          if resource[name].is_a?(Array)
            realvalue["Fn::Select"][0] = resource[name].size if is_list_element
            resource[name] << realvalue if !resource[name].include?(realvalue)
          else
            resource[name] = realvalue
          end
        elsif !resource["Properties"][name].nil? and resource["Properties"][name].is_a?(Array)
          realvalue["Fn::Select"][0] = resource["Properties"][name].size if is_list_element
          if !resource["Properties"][name].include?(realvalue)
            resource["Properties"][name] << realvalue
          end
        else
          resource["Properties"][name] = realvalue
        end
      end

      # Generate a CloudFormation template that mimics what the "real" output
      # of this deployment would be.
      # @param tails [Array<MU::Config::Tail>]: Mu configuration "tails," which we turn into template parameters
      # @param config [Hash]: The fully resolved Basket of Kittens for this deployment
      # @param path [String]: An output path for the resulting template.
      def self.writeCloudFormationTemplate(tails: MU::Config.tails, config: {}, path: nil, mommacat: nil)
        cfm_template = {
          "AWSTemplateFormatVersion" => "2010-09-09",
          "Description" =>  "Automatically generated by Mu",
          "Parameters" => {
            "Environment" => {
              "Description" => "Typically DEV or PROD, this may be used at the application level to control certain behaviors.",
              "Type" => "String",
              "Default" => MU.environment,
              "MinLength" => "1",
              "MaxLength" => "25"
            }
          },
          "Resources" => {},
          "Outputs" => {}
        }
        if mommacat.nil? or mommacat.numKittens(types: ["Server", "ServerPool"]) > 0
          cfm_template["Parameters"]["SSHKeyName"] = {
            "Description" => "Name of an existing EC2 KeyPair to allow SSH access into hosts.",
            "Type" => "AWS::EC2::KeyPair::KeyName"
          }
        end
        tails.each_pair { |param, data|
          tail = data
          default = ""
          if data.is_a?(Array)
            realval = []
            tail = data.first.values.first
            data.each { |bit| realval << bit.values.first }
            default = realval.join(",")
          else
            default = tail.to_s
          end
          if cfm_template["Parameters"].has_key?(tail.getPrettyName)
            cfm_template["Parameters"][tail.getPrettyName]["Type"] = tail.getCloudType
            cfm_template["Parameters"][tail.getPrettyName]["Description"] = tail.description if !tail.description.nil? and !tail.description.empty?
            cfm_template["Parameters"][tail.getPrettyName]["Default"] = tail.to_s if !tail.to_s.nil? and !tail.to_s.empty?
          else
            cfm_template["Parameters"][tail.getPrettyName] = {
              "Type" => tail.getCloudType,
              "Description" => tail.description,
              "Default" => default
            }
          end
          if !tail.getCloudType.match(/^List<|^CommaDelimitedList</)
            cfm_template["Outputs"][tail.getPrettyName] = {
              "Value" => { "Ref" => tail.getPrettyName }
            }
          end
        }
        MU::Cloud.resource_types.each { |cloudclass, data|
          if !config[data[:cfg_plural]].nil? and
              config[data[:cfg_plural]].size > 0
            config[data[:cfg_plural]].each { |resource|
              namestr = resource['name'].gsub(/[^a-z0-9]/i, "")
              if resource['#MUOBJECT'].cloudobj.respond_to?(:cfm_template) and !resource['#MUOBJECT'].cloudobj.cfm_template.nil?
                cfm_template["Resources"].merge!(resource['#MUOBJECT'].cloudobj.cfm_template)
                if data[:cfg_name] == "loadbalancer"
                  cfm_template["Outputs"]["loadbalancer"+namestr] =
                    {
                      "Value" =>
                        { "Fn::GetAtt" =>
                          [ resource['#MUOBJECT'].cloudobj.cfm_name, "DNSName" ]
                        }
                    }
                elsif data[:cfg_name] == "database"
                  cfm_template["Outputs"]["database"+namestr] =
                    {
                      "Value" =>
                        { "Fn::GetAtt" =>
                          [ resource['#MUOBJECT'].cloudobj.cfm_name, "Endpoint.Address" ]
                        }
                    }
                elsif data[:cfg_name] == "cache_cluster" and resource["engine"] != "redis"
                  cfm_template["Outputs"]["cachecluster"+namestr+"endpoint"] =
                    {
                      "Value" =>
                        { "Fn::GetAtt" =>
                          [ resource['#MUOBJECT'].cloudobj.cfm_name, "ConfigurationEndpoint.Address" ]
                        }
                    }
                  cfm_template["Outputs"]["cachecluster"+namestr+"port"] =
                    {
                      "Value" =>
                        { "Fn::GetAtt" =>
                          [ resource['#MUOBJECT'].cloudobj.cfm_name, "ConfigurationEndpoint.Port" ]
                        }
                    }
                elsif data[:cfg_name] == "server"
                  cfm_template["Outputs"]["server"+namestr+"privateip"] =
                    {
                      "Value" =>
                        { "Fn::GetAtt" =>
                          [ resource['#MUOBJECT'].cloudobj.cfm_name, "PrivateIp" ]
                        }
                    }
                  cfm_template["Outputs"]["server"+namestr+"publicip"] =
                    {
                      "Value" =>
                        { "Fn::GetAtt" =>
                          [ resource['#MUOBJECT'].cloudobj.cfm_name, "PublicIp" ]
                        }
                    }
                else
                  cfm_template["Outputs"][data[:cfg_name].gsub(/[^a-z0-9]/i, "")+namestr] = {
                    "Value" => {
                      "Ref" => resource['#MUOBJECT'].cloudobj.cfm_name
                    }
                  }
                end
              end
            }
          end
        }
        if path.nil? or path == "-"
          puts JSON.pretty_generate(cfm_template)
        elsif path.match(/^s3:\/\/(.+?)\/(.*)/i)
          bucket = $1
          target = $2
          MU.log "Writing CloudFormation template to S3 bucket #{bucket} path /#{target}"
          begin
            MU::Cloud::AWS.s3.put_object(
              acl: "public-read",
              bucket: bucket,
              key: target,
              body: JSON.pretty_generate(cfm_template)
            )
          rescue Aws::S3::Errors::NoSuchBucket, Aws::S3::Errors::AccessDenied => e
            MU.log "Failed to write CloudFormation template to #{path} (#{e.inspect})", MU::ERR
            path = "/tmp/cloudformation-#{MU.deploy_id}.json"
            MU.log "Writing to #{path}", MU::WARN
            template = File.new(path, File::CREAT|File::TRUNC|File::RDWR, 0400)
            template.puts JSON.pretty_generate(cfm_template)
            template.close
          end
        else
          MU.log "Writing CloudFormation template to local file #{path}"
          template = File.new(path, File::CREAT|File::TRUNC|File::RDWR, 0400)
          template.puts JSON.pretty_generate(cfm_template)
          template.close
        end

        begin
          # XXX don't assume MU.deploy_id is actually set
          if cfm_template["Parameters"].has_key?("SSHKeyName")
            cfm_template["Parameters"]["SSHKeyName"]["Default"] = "deploy-"+MU.deploy_id
          end
          # Strip out extra properties that have no bearing on cost. There's a
          # very low size ceiling on templates.
          cfm_template["Resources"].each_value { |res|
            if res.has_key?("Properties")
              res["Properties"].delete("UserData")
              res["Properties"].delete("Tags")
              res["Properties"].delete("SecurityGroupIngress")
              res["Properties"].delete("BlockDeviceMappings")
              if res["Properties"].has_key?("Policies")
                res["Properties"]["Policies"] = []
              end
            end
          }
          resp = MU::Cloud::AWS.cloudformation.estimate_template_cost(
            template_body: JSON.generate(cfm_template)
          )
          MU.log "Review estimated monthly cost for AWS resources in this stack: #{resp.url}", MU::NOTICE
        rescue Aws::CloudFormation::Errors::ValidationError => e
          if !e.message.match(/Member must have length less than or equal to 51200/)
            MU.log "Unable to calculate resource costs: #{e.message}", MU::WARN
          else
            MU.log "Unable to calculate resource costs: deployment too complex to for CloudFormation to handle.", MU::WARN
          end
        end

      end

    end
  end
end
