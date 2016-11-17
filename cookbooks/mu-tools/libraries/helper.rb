require 'chef/mixin/shell_out'
include Chef::Mixin::PowershellOut
include Chef::Mixin::ShellOut

require 'net/http'

module Mutools
  module Helper

    @region = nil
    def set_aws_cfg_params
      begin
        require 'aws-sdk-core'
        instance_identity = Net::HTTP.get(URI("http://169.254.169.254/latest/dynamic/instance-identity/document"))
        @region = JSON.parse(instance_identity)["region"]
        ENV['AWS_DEFAULT_REGION'] = @region

        if ENV['AWS_ACCESS_KEY_ID'] == nil or ENV['AWS_ACCESS_KEY_ID'].empty?
          ENV.delete('AWS_ACCESS_KEY_ID')
          ENV.delete('AWS_SECRET_ACCESS_KEY')
          Aws.config = {region: @region}
        else
          Aws.config = {access_key_id: ENV['AWS_ACCESS_KEY_ID'], secret_access_key: ENV['AWS_SECRET_ACCESS_KEY'], region: @region}
        end
      rescue LoadError
        Chef::Log.info("aws-sdk-gem hasn't been installed yet!")
      end
    end

    @ec2 = nil
    def ec2
      require 'aws-sdk-core'
      set_aws_cfg_params
      @ec2 ||= Aws::EC2::Client.new(region: @region)
      @ec2
    end
    @s3 = nil
    def s3
      require 'aws-sdk-core'
      set_aws_cfg_params
      @s3 ||= Aws::S3::Client.new(region: @region)
      @s3
    end

    def elversion
      return 6 if node['platform_version'].to_i == 2013
      return 6 if node['platform_version'].to_i == 2014
      return 6 if node['platform_version'].to_i == 2015
      return 6 if node['platform_version'].to_i == 2016
      node['platform_version'].to_i
    end

    # Extract the tags that Mu typically sticks in a node's Chef metadata
    def mu_get_tag_value(key,target_node=nil)
      if target_node.nil?
        target_node = node
      end
      if target_node.has_key?(:tags)
        if target_node[:tags].is_a?(Array)
          target_node[:tags].each { |tag|
            if tag.is_a?(Array)
              return tag[1] if tag[0] == key
            end
          }
        elsif target_node[:tags].is_a?(Hash)
          return target_node[:tags][key]
        end
      end
      nil
    end

    def get_sibling_nodes (prototype_node)
    # Return other nodes in the same deploy as the prototype_node based on MU-ID tag
      siblings = []
      mu_id = mu_get_tag_value('MU-ID',prototype_node)
      if mu_id.nil?
        return nil
      end
      all_nodes = search(:node, "*")
      all_nodes.each { |n|
        if  mu_get_tag_value('MU-ID', n) == mu_id
          siblings << n
         end
      }
      return siblings
    end

    def get_deploy_secret
      uri = URI("https://#{get_mu_master_ips.first}:2260/rest/bucketname")
      http = Net::HTTP.new(uri.hostname, uri.port)
      http.use_ssl = true
      http.verify_mode = ::OpenSSL::SSL::VERIFY_NONE # XXX this sucks
      response = http.get(uri)
      bucket = response.body

      resp = nil
      begin
        resp = s3.get_object(bucket: bucket, key: mu_get_tag_value("MU-ID")+"-secret")
      rescue ::Aws::S3::Errors::PermanentRedirect => e
        tmps3 = Aws::S3::Client.new(region: "us-east-1")
        resp = tmps3.get_object(bucket: bucket, key: mu_get_tag_value("MU-ID")+"-secret")
      end

      if node[:deployment] and node[:deployment][:public_key]
        deploykey = OpenSSL::PKey::RSA.new(node[:deployment][:public_key])
        Base64.urlsafe_encode64(deploykey.public_encrypt(resp.body.read))
      end
    end

    def mommacat_request(action, arg)
      uri = URI("https://#{get_mu_master_ips.first}:2260/")
      req = Net::HTTP::Post.new(uri)
      res_type = (node[:deployment].has_key?(:server_pools) and node[:deployment][:server_pools].has_key?(node[:service_name])) ? "server_pool" : "server"
      begin
        req.set_form_data(
          "mu_id" => mu_get_tag_value("MU-ID"),
          "mu_resource_name" => node[:service_name],
          "mu_resource_type" => res_type,
          "mu_user" => node[:deployment][:chef_user],
          "mu_deploy_secret" => get_deploy_secret,
          action => arg
        )
        http = Net::HTTP.new(uri.hostname, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE # XXX this sucks
        response = http.request(req)
      rescue EOFError => e
        # Sometimes deployment metadata is incomplete and missing a
        # server_pool entry. Try to help it out.
        if res_type == "server"
          res_type = "server_pool"
          retry
        end
        raise e
      end

    end

    def service_user_set?(service, user)
      cmd = powershell_out("$service = Get-WmiObject Win32_service | Where-Object {$_.Name -eq '#{service}'}; $service.startname -eq '#{user}'")
      return cmd.stdout.match(/True/)
    end

    def user_in_local_admin_group?(user)
      cmd = powershell_out("$group = [ADSI]('WinNT://./Administrators'); $group.IsMember('WinNT://#{new_resource.netbios_name}/#{user}')")
      return cmd.stdout.match(/True/)
    end

    def get_mu_master_ips
      master_ips = []
      master_ips << "127.0.0.1" if node[:name] == "MU-MASTER"
      master = search(:node, "name:MU-MASTER")
      master.each { |server|
        next if !server.has_key?("ec2")
        master_ips << server['ec2']['public_ipv4'] if server['ec2'].has_key?('public_ipv4') and !server['ec2']['public_ipv4'].nil? and !server['ec2']['public_ipv4'].empty?
        master_ips << server['ec2']['local_ipv4'] if !server['ec2']['local_ipv4'].nil? and !server['ec2']['local_ipv4'].empty?
      }

      return master_ips
    end
  end
end

Chef::Recipe.send(:include, Mutools::Helper)
Chef::Resource.send(:include, Mutools::Helper)
Chef::Provider.send(:include, Mutools::Helper)
