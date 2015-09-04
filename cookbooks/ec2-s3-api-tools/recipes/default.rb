#
# Cookbook Name:: ec2-s3-api-tools
# Recipe:: default
#
# Copyright 2013, eGlobalTech
#
# All rights reserved - Do Not Redistribute
#

# XXX don't commit access keys to github, chuckleheads
bash "install ec2-api-s3-tools" do
  user "root"
  code <<-EOH

	#get the s3 cli tool and install it
	cd /tmp
	curl https://raw.github.com/timkay/aws/master/aws -o aws
	perl aws --install
	cd

	# Add the environment variables to the bashrc for s3 cli tools
	echo -e '\n#Set up aws-s3 tools Amazon access\n' >> ~/.bashrc
	source ~/.bashrc

  EOH
end
