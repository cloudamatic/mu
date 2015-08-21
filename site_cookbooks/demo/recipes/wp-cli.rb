#
# Cookbook Name:: mu_wordpress
# Recipe:: wp-cli
#
# Copyright 2015, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#

remote_file "/usr/local/bin/wp" do
  source "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
  mode 0755
end
