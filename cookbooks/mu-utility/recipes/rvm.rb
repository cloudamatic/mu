#
# Cookbook Name:: mu-utility
# Recipe:: rvm
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

case node[:platform]

  when "centos"


  when "ubuntu"

    bash "install rvm on ubuntu" do
      user "root"
      code <<-EOH

curl -L https://get.rvm.io | bash -s stable

#if RVM is installed as user root it goes to /usr/local/rvm/ not ~/.rvm

if [ -f ~/.bash_profile ] ; then
	if [ -f ~/.profile ] ; then
		echo 'source ~/.profile' >> "$HOME/.bash_profile"
	fi
fi

echo "=> Loading RVM..."

if [ -f ~/.profile ] ; 
then
	source ~/.profile
fi
if [ -f ~/.bashrc ] ; 
then
	source ~/.bashrc
fi
if [ -f ~/.bash_profile ] ; 
then
	source ~/.bash_profile
fi
# use this if login in user
if [ -f /etc/profile.d/rvm.sh ] ; 
then
	source /etc/profile.d/rvm.sh
fi
# use this if login in root user
if [ -f /usr/local/rvm/scripts/rvm ] ; 
then
	source /usr/local/rvm/scripts/rvm
fi

# Install dependencies
rvm requirements

# Install ruby and set default
rvm install 1.9.3
rvm install 2.0.0
rvm install 2.1.0

# Install ruby gems
rvm rubygems current

gem install bundler --no-rdoc --no-ri

# Load RVM every time
if [ -f ~/.bashrc ] ; 
then

sudo cat >> ~/.bashrc << EOF
source /usr/local/rvm/scripts/rvm
source /etc/profile.d/rvm.sh
EOF

fi

# Set gem settings
sudo cat >> ~/.gemrc << EOF
gem: --no-document
gem: --no-rdoc --no-ri
EOF

sudo cat >> /etc/gemrc << EOF
gem: --no-document
gem: --no-rdoc --no-ri
EOF

# check version
ruby --version
			
      EOH
    end

  else
    Chef::Log.info("Unsupported platform #{node[:platform]}")
end

