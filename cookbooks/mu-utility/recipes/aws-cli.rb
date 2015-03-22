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
    
    rm -rf /etc/profile.d/awscli.sh
    mkdir -p /tmp/awscli
    cd /tmp/awscli
    wget https://s3.amazonaws.com/aws-cli/awscli-bundle.zip

    unzip awscli-bundle.zip
    ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
   
    rm -rf cd /tmp/awscli

cat > /etc/profile.d/awscli.sh << EOF
#
# Set up cli tools Amazon access
#
export AWS_ACCESS_KEY_ID=#{$aws_access}
export AWS_SECRET_ACCESS_KEY=#{$aws_secret}
export AWS_DEFAULT_REGION=#{$aws_region}
EOF


    source /etc/profile.d/awscli.sh

    EOH
end
