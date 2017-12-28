#
# Cookbook Name:: mu_wordpress
# Recipe:: iptables-port
#
# Copyright 2015
#
# All rights reserved - Do Not Redistribute
#


case node[:platform_family]

  when "rhel"

    ports=node.wordpress.global.ports

    puts "node.wordpress.global.ports #{ports}"

    node.wordpress.global.ports.each do |port|

      bash "Open Port" do
        user "root"
        code <<-EOH
	    
	    /sbin/iptables -I INPUT -p tcp --dport #{port} -j ACCEPT && service iptables save

        EOH
      end

    end


  when "debian"


  else

    raise '#{node[:platform_family]} not supported'

end 
