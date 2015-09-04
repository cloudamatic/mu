#
# Cookbook Name:: rvm
# Recipe:: default
#
# Copyright 2013, eGlobalTech
#
# All rights reserved - Do Not Redistribute
#


case node[:platform]

  when "centos"

    bash "install rvm" do
      user "root"
      code <<-EOH

				curl -L https://get.rvm.io | bash -s stable --ruby
				source /usr/local/rvm/scripts/rvm
				source /etc/profile.d/rvm.sh

				yum install libyaml-devel
				rvm pkg install openssl

				rvm reinstall 2.0.0 --with-openssl-dir=$HOME/.rvm/usr --verify-downloads 1
				rvm --default use 2.0.0

      EOH
    end

  when "ubuntu"

    bash "install rvm" do
      user "root"
      code <<-EOH

      EOH
    end

  else
    Chef::Log.info("Unsupported platform #{node[:platform]}")

end




