#
# Cookbook Name:: mu-utility
# Recipe:: default
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

$vendor="oracle"
$javafile="jdk-7u51-linux-x64.tar.gz"
$javahome="/usr/java/jre1.7.0_45"

case node[:platform]

when "centos"
 case $vendor
 when "openjdk"
  bash "install open jdk " do
    user "root"
    code <<-EOH
    yum -y install java
    yum -y install java-1.7.0
    EOH
  end
when "oracle"  
  cookbook_file "/tmp/java.rpm" do
    source "#{$javafile}"
    mode 0755
    owner "root"
    group "root"
  end
  bash "Install java rpm" do
   user "root"
   code <<-EOH
   rpm -Uvh /tmp/java.rpm
   export JAVA_HOME=#{$javahome}

cat >> ~/.bash_profile << EOF
export JAVA_HOME=#{$javahome}
EOF

   EOH
 end
else
 raise '#{$vendor} not found'
end        
when "ubuntu"

  case $vendor            
  when "oracle"

    remote_file 'download java tar' do
     action :create_if_missing
     owner 'root'
     group 'root'
     mode '0644'
     path "/tmp/jdk-7.tar.gz"
     source "https://s3.amazonaws.com/cap-public/#{$javafile}"
   end

   bash "Install java tar" do
     user "root"
     code <<-EOH
     cd /tmp
     tar -xvf jdk-7.tar.gz
     sudo mkdir -p /usr/lib/jvm
     sudo mv ./jdk1.7* /usr/lib/jvm/jdk1.7.0
     sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jdk1.7.0/bin/java" 1
     sudo update-alternatives --install "/usr/bin/javac" "javac" "/usr/lib/jvm/jdk1.7.0/bin/javac" 1
     sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/usr/lib/jvm/jdk1.7.0/bin/javaws" 1
     sudo chmod a+x /usr/bin/java 
     sudo chmod a+x /usr/bin/javac 
     sudo chmod a+x /usr/bin/javaws
     sudo chown -R root:root /usr/lib/jvm/jdk1.7.0
     cd 

     EOH
   end
 end

else
  Chef::Log.info("Unsupported platform #{node[:platform]}")

end

