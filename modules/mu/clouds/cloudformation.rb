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

require "net/http"
module MU
  class Cloud
    # Support for Amazon Web Services' CloudFormation as a dummy provisioning
    # layer. We essentially "provision" chunks of a CloudFormation template.
    class CloudFormation

      # Generate and return a skeletal CloudFormation resource entry for the
      # caller.
      # param type [String]: The resource type, in Mu parlance
      # param cloudobj [MU::Clouds::AWS]: The resource object
      # param name [String]: An alternative name for resources which are not first-class Mu classes with their own objects
      def self.cloudFormationBase(type, cloudobj = nil, name: nil)
        desc = {}
        tags = []
        MU::MommaCat.listStandardTags.each_pair { |key, val|
          next if ["MU-OWNER", "MU-MASTER-IP", "MU-MASTER-NAME"].include?(key)
          if key == "MU-ID"
            val = { "Fn::Join" => ["", [{ "Ref" => "AWS::StackName" }, "-", { "Ref" => "Environment" }, "-", { "Ref" => "DeployID" } ] ] }
          elsif key == "MU-ENV"
            val =  { "Ref" => "Environment" }
          end
          tags << { "Key" => key, "Value" => val }
        }

        res_name = ""
        res_name = cloudobj.config["name"] if !cloudobj.nil?
        if name.nil?
          nametag = { "Fn::Join" => ["", [{ "Ref" => "AWS::StackName" }, "-", { "Ref" => "Environment" }, "-", { "Ref" => "DeployID" }, "-", res_name.gsub(/[^a-z0-9]/i, "").upcase ] ] }
          basename = ""
          basename = cloudobj.mu_name if !cloudobj.nil? and !cloudobj.mu_name.nil?
          name = (type+basename).gsub!(/[^a-z0-9]/i, "")
          tags << { "Key" => "Name", "Value" => nametag }
        else
          name = (type+name).gsub(/[^a-z0-9]/i, "")
        end

        case type
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
              "AvailabilityZones" => [],
              "VPCZoneIdentifier" => [],
              "LoadBalancerNames" => []
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
              desc["DependsOn"] << (resource_classname+sibling_obj.cloudobj.mu_name).gsub!(/[^a-z0-9]/i, "")
              # Common resource-specific references to dependencies
              if resource_classname == "firewall_rule"
                if type == "database" and cloudobj.config.has_key?("vpc")
                  desc["Properties"]["VPCSecurityGroups"] << { "Fn::GetAtt" => [(resource_classname+sibling_obj.cloudobj.mu_name).gsub!(/[^a-z0-9]/i, ""), "GroupId"] }
                else
                  ["SecurityGroupIds", "SecurityGroups"].each { |key|
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
        if value.class.to_s == "MU::Config::Tail"
          realvalue = { "Ref" => "#{value.getPrettyName}" }
        end

        if resource.has_key?(name)
          if resource[name].is_a?(Array)
            resource[name] << realvalue
            resource[name].uniq!
          else
            resource[name] = realvalue
          end
        elsif !resource["Properties"][name].nil? and resource["Properties"][name].is_a?(Array)
          resource["Properties"][name] << realvalue
          resource["Properties"][name].uniq!
        else
          resource["Properties"][name] = realvalue
        end
      end

      # Generate a CloudFormation template that mimics what the "real" output
      # of this deployment would be.
      # @param tails [Array<MU::Config::Tail>]: Mu configuration "tails," which we turn into template parameters
      # @param config [Hash]: The fully resolved Basket of Kittens for this deployment
      # @param path [String]: An output path for the resulting template.
      def self.writeCloudFormationTemplate(tails: MU::Config.tails, config: {}, path: nil)
        cfm_template = {
          "AWSTemplateFormatVersion" => "2010-09-09",
          "Description" =>  "Automatically generated by Mu",
          "Parameters" => {
            "DeployID" => {
              "Description" => "A string to differentiate individual deployments of this stack when tagging.",
              "Type" => "String",
              "MinLength" => "1",
              "MaxLength" => "25"
            },
            "Environment" => {
              "Description" => "Typically DEV or PROD, this may be used at the application level to control certain behaviors.",
              "Type" => "String",
              "Default" => MU.environment,
              "MinLength" => "1",
              "MaxLength" => "25"
            },
# XXX only require this if we have a Server or ServerPool in this stack
            "SSHKeyName" => {
              "Description" => "Name of an existing EC2 KeyPair to enable SSH access to hosts",
              "Type" => "AWS::EC2::KeyPair::KeyName"#,
            }
          },
          "Resources" => {}
        }
        tails.each_pair { |param, data|
          cfm_template["Parameters"][data.getPrettyName] = {
            "Type" => data.getCloudType,
#            "MinLength" => "1",
#            "MaxLength" => "64",
            "Default" => data.to_s
          }
        }
        MU::Cloud.resource_types.each { |cloudclass, data|
          if !config[data[:cfg_plural]].nil? and
              config[data[:cfg_plural]].size > 0
            config[data[:cfg_plural]].each { |resource|
              if resource['#MUOBJECT'].cloudobj.respond_to?(:cfm_template) and !resource['#MUOBJECT'].cloudobj.cfm_template.nil?
                cfm_template["Resources"].merge!(resource['#MUOBJECT'].cloudobj.cfm_template)
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
          resp = MU::Cloud::AWS.s3.list_buckets
          uploaded = false
          resp.buckets.each { |b|
            if b['name'] == bucket
              MU::Cloud::AWS.s3.put_object(
                acl: "public-read",
                bucket: bucket,
                key: target,
                body: JSON.pretty_generate(cfm_template)
              )
              uploaded = true
              break
            end
          }
          if !uploaded
            MU.log "Failed to write CloudFormation template to #{path}", MU::ERR
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
      end

    end
  end
end
