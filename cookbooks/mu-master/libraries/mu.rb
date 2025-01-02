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
# 
# This library deals with volume creation and mounting


# Sets the $MU_CFG hash
if ENV.include?('MU_LIBDIR')
  require "#{ENV['MU_LIBDIR']}/modules/mu-load-config.rb"
elsif ENV.include?('MU_INSTALLDIR')
  require "#{ENV['MU_INSTALLDIR']}/lib/modules/mu-load-config.rb"
elsif File.readable?("/opt/mu/lib/modules/mu-load-config.rb")
  ENV['MU_INSTALLDIR'] = "/opt/mu"
  ENV['MU_LIBDIR'] = "/opt/mu/lib"
  require "/opt/mu/lib/modules/mu-load-config.rb"
end

# for some reason aaws-sigv4 isn't getting picked up by Mu's requires
require "aws-sigv4"
require "mu"

def baskets
  baskets = {}
  if Dir.exist?("/opt/mu/var/deployments")
    Dir.glob("/opt/mu/var/deployments/*/basket_of_kittens.json").each { |basket_json|
      basket_json =~ /^\/opt\/mu\/var\/deployments\/([^\/]+)\/basket_of_kittens.json$/
      baskets[Regexp.last_match[1]] = JSON.parse(File.read(basket_json))
    }
  end
  baskets
end

def deployments
  deploys = {}
  if Dir.exist?("/opt/mu/var/deployments")
    Dir.glob("/opt/mu/var/deployments/*/deployment.json").each { |dep_json|
      dep_json =~ /^\/opt\/mu\/var\/deployments\/([^\/]+)\/deployment.json$/
      deploys[Regexp.last_match[1]] = JSON.parse(File.read(dep_json))
    }
  end
  deploys
end
