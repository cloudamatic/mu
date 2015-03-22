#
# Cookbook Name:: mu-utility
# Recipe:: windows_basics
#
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
# Installs basic programs we want on a windows node.  Good for testing windows functionality

case node[:platform]

	when "windows"
		chef_gem "aws-sdk"
#		windows_package 'Mozilla Firefox 5.0 (x86 en-US)' do
#  			source 'http://archive.mozilla.org/pub/mozilla.org/mozilla.org/firefox/releases/5.0/win32/en-US/Firefox%20Setup%205.0.exe'
#  			options '-ms'
#  			installer_type :custom
#  			action :install
#		end
		windows_package "AWS Tools for Windows Powershell" do
			source 'http://sdk-for-net.amazonwebservices.com/latest/AWSToolsAndSDKForNet.msi'
		end
		windows_package "7-Zip" do
			source 'http://downloads.sourceforge.net/sevenzip/7z920-x64.msi'
		end

	else
		Chef::Log.info("Unsupported platform #{node[:platform]}")
end
