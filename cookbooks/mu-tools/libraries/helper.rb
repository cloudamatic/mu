require 'chef/mixin/shell_out'
include Chef::Mixin::PowershellOut
include Chef::Mixin::ShellOut

require 'net/http'
require 'timeout'
require 'open-uri'

module Mutools
  module Helper

    # Fetch a Google instance metadata parameter (example: instance/id).
    # @param param [String]: The parameter name to fetch
    # @return [String, nil]
    def get_google_metadata(param)
      base_url = "http://metadata.google.internal/computeMetadata/v1"
      begin
        Timeout.timeout(2) do
          response = open(
            "#{base_url}/#{param}",
            "Metadata-Flavor" => "Google"
          ).read
          return response
        end
      rescue Net::HTTPServerException, OpenURI::HTTPError, Timeout::Error, SocketError => e
        # This is fairly normal, just handle it gracefully
      end

      nil
    end
 
    # Fetch an Amazon instance metadata parameter (example: public-ipv4).
    # @param param [String]: The parameter name to fetch
    # @return [String, nil]
    def get_aws_metadata(param)
      base_url = "http://169.254.169.254/latest"
      begin
        Timeout.timeout(2) do
          response = open("#{base_url}/#{param}").read
          return response
        end
      rescue Net::HTTPServerException, OpenURI::HTTPError, Timeout::Error, SocketError => e
        # This is fairly normal, just handle it gracefully
      end
      nil
    end

    @project = nil
    @authorizer = nil
    def set_gcp_cfg_params
      begin
        require "google/cloud"
        require "googleauth"
        @project ||= get_google_metadata("project/project-id")
        @authorizer ||= ::Google::Auth.get_application_default(['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/compute.readonly'])
      rescue OpenURI::HTTPError, Timeout::Error, SocketError, JSON::ParserError
        Chef::Log.info("This node isn't in the Goolge Cloud, skipping GCP config")
        return false
      rescue LoadError
        Chef::Log.info("google-cloud-api hasn't been installed yet!")
        return false
      end
      true
    end

    @region = nil
    def set_aws_cfg_params
      begin
        require 'aws-sdk-core'
        instance_identity = get_aws_metadata("dynamic/instance-identity/document")
        return false if instance_identity.nil? # Not in AWS, most likely
        @region = JSON.parse(instance_identity)["region"]
        ENV['AWS_DEFAULT_REGION'] = @region

        if ENV['AWS_ACCESS_KEY_ID'] == nil or ENV['AWS_ACCESS_KEY_ID'].empty?
          ENV.delete('AWS_ACCESS_KEY_ID')
          ENV.delete('AWS_SECRET_ACCESS_KEY')
          Aws.config = {region: @region}
        else
          Aws.config = {access_key_id: ENV['AWS_ACCESS_KEY_ID'], secret_access_key: ENV['AWS_SECRET_ACCESS_KEY'], region: @region}
        end
        return true
      rescue OpenURI::HTTPError, Timeout::Error, SocketError, JSON::ParserError
        Chef::Log.info("This node isn't in Amazon Web Services, skipping AWS config")
        return false
      rescue LoadError
        Chef::Log.info("aws-sdk-gem hasn't been installed yet!")
        return false
      end
    end

    @ec2 = nil
    def ec2
      if set_aws_cfg_params
        @ec2 ||= Aws::EC2::Client.new(region: @region)
      end
      @ec2
    end
    @s3 = nil
    def s3
      if set_aws_cfg_params
        @s3 ||= Aws::S3::Client.new(region: @region)
      end
      @s3
    end

    @cloudstorage = nil
    # XXX does not work with google-api-client-0.13.1 and chef-12.20.3 because
    # they fight over what version of addressable they want.
    def cloudstorage
      if set_gcp_cfg_params
        require 'google/apis/storage_v1'
        @cloudstorage ||= Object.const_get("Google::Apis::StorageV1").new
        @cloudstorage.authorization = @authorizer
      end
      @cloudstorage
    end

    def elversion
      return 6 if node['platform_version'].to_i >= 2013 and node['platform_version'].to_i <= 2017
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
      secret = nil
      filename = mu_get_tag_value("MU-ID")+"-secret"

      if !get_aws_metadata("meta-data/instance-id").nil?
        resp = nil
        begin
          resp = s3.get_object(bucket: bucket, key: filename)
        rescue ::Aws::S3::Errors::PermanentRedirect => e
          tmps3 = Aws::S3::Client.new(region: "us-east-1")
          resp = tmps3.get_object(bucket: bucket, key: filename)
        end
        Chef::Log.info("Fetch deploy secret from s3://#{bucket}/#{filename}")
        secret = resp.body.read
      elsif !get_google_metadata("instance/name").nil?
        include_recipe "mu-tools::gcloud"
        ["/opt/google-cloud-sdk/bin/gsutil", "/bin/gsutil"].each { |gsutil|
          next if !File.exists?(gsutil)
          Chef::Log.info("Fetching deploy secret: #{gsutil} cp gs://#{bucket}/#{filename} -")
          if File.exists?("/usr/bin/python2.7")
            secret = %x{CLOUDSDK_PYTHON=python2.7 #{gsutil} cp gs://#{bucket}/#{filename} -}
          else
            secret = %x{#{gsutil} cp gs://#{bucket}/#{filename} -}
          end
          break if !secret.nil? and !secret.empty?
        }
        if secret.nil? or secret.empty?
          raise "Didn't find gsutil on this machine, and I can't fetch Google deploy secrets without it!"
        end
      else
        raise "I don't know how to fetch deploy secrets without either AWS or Google!"
      end

      return nil if secret.nil? or secret.empty?

      if node[:deployment] and node[:deployment][:public_key]
        deploykey = OpenSSL::PKey::RSA.new(node[:deployment][:public_key])
        Base64.urlsafe_encode64(deploykey.public_encrypt(secret))
      end
    end

    def mommacat_request(action, arg)
      uri = URI("https://#{get_mu_master_ips.first}:2260/")
      req = Net::HTTP::Post.new(uri)
      res_type = (node[:deployment].has_key?(:server_pools) and node[:deployment][:server_pools].has_key?(node[:service_name])) ? "server_pool" : "server"
      response = nil
      begin
        secret = get_deploy_secret
        if secret.nil?
          raise "Failed to fetch deploy secret, and I can't communicate with Momma Cat without it"
        end
        Chef::Log.info("Sending Momma Cat #{action} request to #{uri}")
        req.set_form_data(
          "mu_id" => mu_get_tag_value("MU-ID"),
          "mu_resource_name" => node[:service_name],
          "mu_resource_type" => res_type,
          "mu_user" => node[:deployment][:chef_user],
          "mu_deploy_secret" => secret,
          action => arg
        )
        http = Net::HTTP.new(uri.hostname, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE # XXX this sucks
        response = http.request(req)
        if response.code != "200"
          Chef::Log.error("Got #{response.code.to_s} back from #{uri} on #{action} => #{arg}")
        end
      rescue EOFError => e
        # Sometimes deployment metadata is incomplete and missing a
        # server_pool entry. Try to help it out.
        if res_type == "server"
          res_type = "server_pool"
          retry
        end
        raise e
      end
      response
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
        if server.has_key?("ec2")
          master_ips << server['ec2']['public_ipv4'] if server['ec2'].has_key?('public_ipv4') and !server['ec2']['public_ipv4'].nil? and !server['ec2']['public_ipv4'].empty?
          master_ips << server['ec2']['local_ipv4'] if !server['ec2']['local_ipv4'].nil? and !server['ec2']['local_ipv4'].empty?
        end
        master_ips << server['ipaddress'] if !server['ipaddress'].nil? and !server['ipaddress'].empty?
      }
      if master_ips.size == 0
        master_ips <<  mu_get_tag_value("MU-MASTER-IP")
      end

      return master_ips.uniq
    end
  end
end

Chef::Recipe.send(:include, Mutools::Helper)
Chef::Resource.send(:include, Mutools::Helper)
Chef::Provider.send(:include, Mutools::Helper)
