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

module MU
  class Cloud
    class CloudFormation
      # A load balancer as configured in {MU::Config::BasketofKittens::loadbalancers}
      class LoadBalancer < MU::Cloud::LoadBalancer

        @deploy = nil
        @lb = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        attr_reader :cfm_template
        attr_reader :cfm_name

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::loadbalancers}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          else
            @mu_name = @deploy.getResourceName(@config["name"], max_length: 32, need_unique_string: true)
            @mu_name.gsub!(/[^\-a-z0-9]/i, "-") # AWS ELB naming rules
            @cfm_name, @cfm_template = MU::Cloud::AWS.cloudFormationBase(self.class.cfg_name, self)
            MU::Cloud::AWS.setCloudFormationProp(@cfm_template[@cfm_name], "LoadBalancerName", @mu_name)
          end
        end

        # Populate @cfm_template with a resource description for this load
        # balancer in CloudFormation language.
        def create
          @config["cross_zone"] = @config["cross_zone_unstickiness"]
          @config["health_check"] = @config["healthcheck"]
          @config["access_logging_policy"] = @config["access_log"]
          ["cross_zone", "health_check"].each { |arg|
            if !@config[arg].nil?
              key = ""
              val = @config[arg]
              arg.split(/_/).each { |chunk| key = key + chunk.capitalize }
              if val.is_a?(Hash)
                val = {}
                @config[arg].each_pair { |name, value|
                  newkey = ""
                  name.split(/_/).each { |chunk| newkey = newkey + chunk.capitalize }
                  val[newkey] = value.to_s
                }
              end
              MU::Cloud::AWS.setCloudFormationProp(@cfm_template[@cfm_name], key, val)
            end
          }

          @config['listeners'].each { |listener|
            prop = {
              "InstancePort" => listener['instance_port'].to_s,
              "InstanceProtocol" => listener['instance_protocol'],
              "LoadBalancerPort" => listener['lb_port'].to_s,
              "Protocol" => listener['lb_protocol']
            }
            if !listener['ssl_certificate_id'].nil?
              prop["SSLCertificateId"] = listener['ssl_certificate_id'] # XXX resolve ssl_certificate_name if we get that instead
            end
            MU::Cloud::AWS.setCloudFormationProp(
              @cfm_template[@cfm_name],
              "Listeners",
              prop
            )

          }

          ["lb_cookie_stickiness_policy", "app_cookie_stickiness_policy"].each { |policy|
            if @config[policy]
              key = ""
              policy.split(/_/).each { |chunk| key = key + chunk.capitalize }
              MU::Cloud::AWS.setCloudFormationProp(
                @cfm_template[@cfm_name],
                key,
                {
                  "PolicyName" => @config[policy]['name'],
                  "CookieExpirationPeriod" => @config[policy]['timeout']
                }
              )
            end
          }

          if @config['idle_timeout']
            MU::Cloud::AWS.setCloudFormationProp(@cfm_template[@cfm_name], "ConnectionSettings", { "IdleTimeout" => @config['idle_timeout'] })
          end

          if @config['private']
            MU::Cloud::AWS.setCloudFormationProp(@cfm_template[@cfm_name], "Scheme", "internal")
          else
            MU::Cloud::AWS.setCloudFormationProp(@cfm_template[@cfm_name], "Scheme", "internet-facing")
          end

          if @config['connection_draining_timeout'] and @config['connection_draining_timeout'] >= 0
            MU::Cloud::AWS.setCloudFormationProp(@cfm_template[@cfm_name], "ConnectionDrainingPolicy", { "Enabled" => true, "Timeout" => @config['connection_draining_timeout'] })
          end

          if !@config['vpc'].nil? and !@config["vpc"]["subnets"].nil? and @config["vpc"]["subnets"].size > 0
            @config["vpc"]["subnets"].each { |subnet|
              if !subnet["subnet_id"].nil?
                MU::Cloud::AWS.setCloudFormationProp(@cfm_template[@cfm_name], "Subnets", subnet["subnet_id"])
              elsif @dependencies.has_key?("vpc") and @dependencies["vpc"].has_key?(@config["vpc"]["vpc_name"])
                @dependencies["vpc"][@config["vpc"]["vpc_name"]].subnets.each { |subnet_obj|
                  if subnet_obj.name == subnet['subnet_name']
                    MU::Cloud::AWS.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", subnet_obj.cfm_name)
                    MU::Cloud::AWS.setCloudFormationProp(@cfm_template[@cfm_name], "Subnets", { "Ref" => subnet_obj.cfm_name } )
                  end
                }
              end
            }
# XXX cloudformation: something about AZs
          end
        end

        # Return the metadata for this LoadBalancer
        # @return [Hash]
        def notify
          {}
        end

      end
    end
  end
end
