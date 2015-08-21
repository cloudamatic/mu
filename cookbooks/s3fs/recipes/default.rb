#
# Cookbook Name:: s3fs
# Recipe:: default
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

include_recipe "mu-utility::zip"
include_recipe "mu-utility::make"
include_recipe "build-essential"

case node[:platform]

  when "centos"

    ["curl", "curl-devel", "libxml2", "libxml2-devel", "openssl-devel", "mailcap"].each { |pkg| package pkg }

    cookbook_file "/usr/local/src/fuse-2.9.3.zip" do
      source "fuse-2.9.3.zip"
      mode 0755
      owner "root"
      group "root"
    end

    bash "install fuse" do
      user 'root'
      cwd '/usr/local/src/'
      code <<-EOH
        unzip fuse-2.9.3.zip
        mv fuse-2.9.3 fuse
        (cd fuse/ && ./configure --prefix=/usr && make && make install)
        rm -f fuse-2.9.3.zip
        echo '# Fuse\nexport PKG_CONFIG_PATH=/usr/lib/pkgconfig:/usr/lib64/pkgconfig/' >> /root/.bashrc
        source /root/.bashrc
        ldconfig
        modprobe fuse
      EOH
      not_if 'lsmod | grep fuse'
    end

    remote_file "/usr/local/src/s3fs-#{node[:s3fs][:version]}.tar.gz" do
      source "https://github.com/s3fs-fuse/s3fs-fuse/archive/v#{node[:s3fs][:version]}.tar.gz"
      notifies :run, 'bash[install s3fs]', :immediately
    end

    bash 'install s3fs' do
      user 'root'
      cwd '/usr/local/src'
      code <<-EOH
        source /root/.bashrc
        tar -zxf s3fs-#{node[:s3fs][:version]}.tar.gz
        (cd s3fs-fuse-#{node[:s3fs][:version]}/ && . autogen.sh && sh configure && make && make install)
      EOH
      not_if "s3fs --version | grep #{node[:s3fs][:version]}"
    end

  when "ubuntu"
    ["python-support", "pkg-config", "fuse", "libfuse-dev", "libcurl4-openssl-dev", "libxml2-dev", "libcrypto++-dev"].each { |pkg| package pkg }

    remote_file "/usr/local/src/s3fs-#{node[:s3fs][:version]}.tar.gz" do
      source "https://github.com/s3fs-fuse/s3fs-fuse/archive/v#{node[:s3fs][:version]}.tar.gz"
    end

    bash "install s3fs" do
      user "root"
      cwd '/usr/local/src/'
      code <<-EOH
        source /root/.bashrc
        tar xvzf s3fs-#{node[:s3fs][:version]}.tar.gz
        (cd s3fs-fuse-#{node[:s3fs][:version]}/ && ./autogen.sh && ./configure --prefix=/usr && make && make install)
      EOH
      not_if "s3fs --version | grep #{node[:s3fs][:version]}"
    end
  else
    Chef::Log.info("Unsupported platform #{node[:platform]}")
end

