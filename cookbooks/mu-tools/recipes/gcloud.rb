#
# Cookbook Name::mu-tools
# Recipe::gcloud
#
# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
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

if platform_family?("rhel")
  if node[:platform_version].to_i >= 7
    yum_repository "google-cloud-sdk" do
      description 'Google Cloud SDK'
      url "https://packages.cloud.google.com/yum/repos/cloud-sdk-el#{node[:platform_version].to_i}-x86_64#{node[:platform_version].to_i == 6 ? "-unstable": ""}"
      enabled true
      gpgcheck true
      repo_gpgcheck true
      gpgkey ["https://packages.cloud.google.com/yum/doc/yum-key.gpg", "https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg"]
    end
    package "google-cloud-sdk"
  elsif node[:platform_version].to_i == 6
    rpm_package "IUS" do
      source "https://#{node[:platform]}#{node[:platform_version].to_i}.iuscommunity.org/ius-release.rpm"
    end
    package "python27"
    bash "install gcloud-cli" do
      cwd "/opt"
      code <<-EOH
        tar -xzf #{Chef::Config[:file_cache_path]}/gcloud-cli.tar.gz
        CLOUDSDK_PYTHON=/usr/bin/python2.7 ./google-cloud-sdk/install.sh -q
      EOH
      action :nothing
    end
    remote_file "#{Chef::Config[:file_cache_path]}/gcloud-cli.tar.gz" do
      source "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-155.0.0-linux-x86_64.tar.gz"
      notifies :run, "bash[install gcloud-cli]", :immediately
    end
    link "/etc/bash_completion.d/gcloud" do
      to "/opt/google-cloud-sdk/completion.bash.inc"
    end
    link "/etc/profile.d/gcloud.sh" do
      to "/opt/google-cloud-sdk/path.bash.inc"
    end
    file "/etc/profile.d/gcloud_python.sh" do
      content "export CLOUDSDK_PYTHON=/usr/bin/python2.7\n"
      mode 0644
    end
  end
elsif platform_family?("debian")
  bash "add google-cloud-sdk repo" do
    code <<-EOH
      export CLOUD_SDK_REPO="cloud-sdk-$(lsb_release -c -s)"
      echo "deb http://packages.cloud.google.com/apt $CLOUD_SDK_REPO main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
      curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
      sudo apt-get update
    EOH
    not_if { ::File.exists?("/etc/apt/sources.list.d/google-cloud-sdk.list") }
  end
  package "google-cloud-sdk"
else
end
