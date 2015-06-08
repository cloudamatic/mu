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
	# A CloudWatch alaram as configured in {MU::Config::BasketofKittens::monitoring}
	class Monitor
		@monitor = nil
		# The {MU::Config::BasketofKittens} name for a single resource of this class.
		def self.cfg_name; "monitor".freeze end
		# The {MU::Config::BasketofKittens} name for a collection of resources of this class.
		def self.cfg_plural; "monitoring".freeze end
		# Whether {MU::Deploy} should hold creation of other resources which depend on this resource until the latter has been created.
		def self.deps_wait_on_my_creation; true.freeze end
		# Whether {MU::Deploy} should hold creation of this resource until resources on which it depends have been fully created and deployed.
		def self.waits_on_parent_completion; false.freeze end

		# @param deployer [MU::Deploy]: A {MU::Deploy} object, typically associated with an in-progress deployment.
		# @param alarm [Hash]: The full {MU::Config} resource declaration as defined in {MU::Config::BasketofKittens::monitoring}
		def initialize(deployer, alarm)
			@deploy = deployer
			@alarm = alarm
			MU.setVar("curRegion", @alarm['region']) if !@alarm['region'].nil?
		end

		# Called automatically by {MU::Deploy#createResources}
		def create
			MU.setVar("curRegion", @alarm['region']) if !@alarm['region'].nil?
			
			alarm_name = MU::MommaCat.getResourceName(@alarm["name"], max_length: 32, need_unique_string: true)
			alarm_name.gsub!(/[^\-a-z0-9]/i, "-") # CloudWatch alarm naming rules

			alarm_options = {
				alarm_name: alarm_name
			}
			
			alarms = Array.new
			@alarm["alarms"].each { |metric|
				metric_struct = {
					:alarm_name => metric["lb_port"],
					:alarm_description => metric["lb_protocol"],
					:actions_enabled => metric["instance_port"],
					:ok_actions => metric["instance_protocol"]
					:alarm_actions => metric["instance_protocol"]
					:insufficient_data_actions => metric["instance_protocol"]
					:metric_name => metric["instance_protocol"]
					:namespace => metric["instance_protocol"]
					:dimensions => metric["instance_protocol"]
					:period => metric["instance_protocol"]
					:evaluation_periods => metric["instance_protocol"]
					:threshold => metric["instance_protocol"]
					:comparison_operator => metric["instance_protocol"]
				}
			}
			alarm_options << metric_struct
		end
		
		#delete
resp = cloudwatch.delete_alarms(
  # required
  alarm_names: ["AlarmName", '...'],
)

desc_alarm
resp = cloudwatch.describe_alarms(
  alarm_names: ["AlarmName", '...'],
  alarm_name_prefix: "AlarmNamePrefix",
  state_value: "OK|ALARM|INSUFFICIENT_DATA",
  action_prefix: "ActionPrefix",
  max_records: 1,
  next_token: "NextToken",
)

# dsiable alaram action:
resp = cloudwatch.disable_alarm_actions(
  # required
  alarm_names: ["AlarmName", '...'],
)

#enable alarm action
resp = cloudwatch.enable_alarm_actions(
  # required
  alarm_names: ["AlarmName", '...'],
)


	end
end
