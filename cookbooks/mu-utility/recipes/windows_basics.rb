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

case node['platform']
  when "windows"
    windows_package "AWS Tools for Windows Powershell" do
      source 'http://sdk-for-net.amazonwebservices.com/latest/AWSToolsAndSDKForNet.msi'
    end

    windows_package 'Google Chrome' do
      source 'https://dl-ssl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B806F36C0-CB54-4A84-A3F3-0CF8A86575E0%7D%26lang%3Den%26browser%3D3%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dfalse/edgedl/chrome/install/GoogleChromeStandaloneEnterprise.msi'
    end

    windows_package "7-Zip" do
      source 'http://downloads.sourceforge.net/sevenzip/7z920-x64.msi'
    end

  else
    Chef::Log.info("Unsupported platform #{node['platform']}")
end
