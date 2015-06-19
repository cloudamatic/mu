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
	# Plugins under this namespace serve as interfaces to configuration
	# management tools (Chef, Puppet, etc).
	class Groomer

		# List of known/supported grooming agents (configuration management tools)
		def self.supportedGroomers
			["Chef"]
		end
		MU::Groomer.supportedGroomers.each { |groomer|
			require "mu/groomers/#{groomer.downcase}"
		}
		# @param groomer [String]: The grooming agent to load. 
		# @return [Class]: The class object implementing this groomer agent
		def self.loadGroomer(groomer)
			if !File.size?(MU.myRoot+"/modules/mu/groomers/#{groomer.downcase}.rb")
				raise MuError, "Requested to use unsupported grooming agent #{groomer}"
			end
			require "mu/groomers/#{groomer.downcase}"
			return Object.const_get("MU").const_get("Groomer").const_get(groomer)
		end
	end
end
