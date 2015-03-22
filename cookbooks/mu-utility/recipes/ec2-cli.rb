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

bash "install latest Amazon EC2 API Tools" do
    user "root"
    code <<-EOH
    
    rm -rf /root/.ec2 
    rm -rf /etc/profile.d/ec2.sh

    mkdir /root/.ec2

    mkdir -p /tmp/ec2-cli
    cd /tmp/ec2-cli

    wget http://s3.amazonaws.com/ec2-downloads/ec2-api-tools.zip
    unzip ec2-api-tools.zip
    cp -rf ec2-api-tools-1.6.12.2/bin /root/.ec2
    cp -rf ec2-api-tools-1.6.12.2/lib /root/.ec2

    rm -rf /tmp/ec2-cli

cat > /etc/profile.d/ec2.sh << EOF
#
# Set up ec2 tools Amazon access
#
export EC2_HOME=/root/.ec2
export PATH=\$PATH:/root/.ec2/bin
export JAVA_HOME=/usr/lib/jvm/jdk1.7.0/jre
export AWS_ACCESS_KEY=#{$aws_access}
export AWS_SECRET_KEY=#{$aws_secret}
EOF

    source /etc/profile.d/ec2.sh

    EOH
end
