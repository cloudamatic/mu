# Copyright:: Copyright (c) 2020 eGlobalTech, Inc., all rights reserved
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

module MU
  # Plugins under this namespace serve as interfaces to cloud providers and
  # other provisioning layers.
  class Cloud

    # The public AWS S3 bucket where we expect to find YAML files listing our
    # standard base images for various platforms.
    BASE_IMAGE_BUCKET = "cloudamatic"
    # The path in the AWS S3 bucket where we expect to find YAML files listing
    # our standard base images for various platforms.
    BASE_IMAGE_PATH = "/images"

    # Aliases for platform names, in case we don't have actual images built for
    # them.
    PLATFORM_ALIASES = {
      "linux" => "amazon2023",
      "windows" => "win2k12r2",
      "win2k12" => "win2k12r2",
      "ubuntu" => "ubuntu16",
      "centos" => "centos7",
      "rhel7" => "rhel71",
      "rhel" => "rhel71",
      "amazon" => "amazon2023"
    }

    @@image_fetch_cache = {}
    @@platform_cache = []
    @@image_fetch_semaphore = Mutex.new

    # Rifle our image lists from {MU::Cloud.getStockImage} and return a list
    # of valid +platform+ names.
    # @return [Array<String>]
    def self.listPlatforms
      return @@platform_cache if @@platform_cache and !@@platform_cache.empty?
      @@platform_cache = MU::Cloud.supportedClouds.map { |cloud|
        begin
          resourceClass(cloud, :Server)
        rescue MU::Cloud::MuCloudResourceNotImplemented, MU::MuError
          next
        end

        images = MU::Cloud.getStockImage(cloud, quiet: true)
        if images
          images.keys
        else
          nil
        end
      }.flatten.uniq
      @@platform_cache.delete(nil)
      @@platform_cache.sort
      @@platform_cache
    end

    # Locate a base image for a {MU::Cloud::Server} resource. First we check
    # Mu's public bucket, which should list the latest and greatest. If we can't
    # fetch that, then we fall back to a YAML file that's bundled as part of Mu,
    # but which will typically be less up-to-date.
    # @param cloud [String]: The cloud provider for which to return an image list
    # @param platform [String]: The supported platform for which to return an image or images. If not specified, we'll return our entire library for the appropriate cloud provider.
    # @param region [String]: The region for which the returned image or images should be supported, for cloud providers which require it (such as AWS).
    # @param fail_hard [Boolean]: Raise an exception on most errors, such as an inability to reach our public listing, lack of matching images, etc.
    # @return [Hash,String,nil]
    def self.getStockImage(cloud = MU::Config.defaultCloud, platform: nil, region: nil, fail_hard: false, quiet: false)

      if !MU::Cloud.supportedClouds.include?(cloud)
        MU.log "'#{cloud}' is not a supported cloud provider! Available providers:", MU::ERR, details: MU::Cloud.supportedClouds
        raise MuError, "'#{cloud}' is not a supported cloud provider!"
      end

      urls = ["http://"+BASE_IMAGE_BUCKET+".s3-website-us-east-1.amazonaws.com"+BASE_IMAGE_PATH]
      if $MU_CFG and $MU_CFG['custom_images_url']
        urls << $MU_CFG['custom_images_url']
      end
      
      images = nil
# XXX no ability to update this cache anymore, and it's pointless now anyway
#      urls.each { |base_url|
#        @@image_fetch_semaphore.synchronize {
#          if @@image_fetch_cache[cloud] and (Time.now - @@image_fetch_cache[cloud]['time']) < 30
#            images = @@image_fetch_cache[cloud]['contents'].dup
#          else
#            begin
#              Timeout.timeout(2) do
#                response = URI.open("#{base_url}/#{cloud}.yaml").read
#                images ||= {}
#                images.deep_merge!(YAML.load(response))
#                break
#              end
#            rescue StandardError => e
#              if fail_hard
#                raise MuError, "Failed to fetch stock images from #{base_url}/#{cloud}.yaml (#{e.message})"
#              else
#                MU.log "Failed to fetch stock images from #{base_url}/#{cloud}.yaml (#{e.message})", MU::WARN if !quiet
#              end
#            end
#          end
#        }
#      }

      @@image_fetch_semaphore.synchronize {
        @@image_fetch_cache[cloud] = {
          'contents' => images.dup,
          'time' => Time.now
        }
      }

      backwards_compat = {
        "AWS" => "amazon_images",
        "Google" => "google_images",
      }

      # Load from inside our repository, if we didn't get images elsewise
      if images.nil?
        [backwards_compat[cloud], cloud].each { |file|
          next if file.nil?
          if File.exist?("#{MU.myRoot}/modules/mu/defaults/#{file}.yaml")
            images = YAML.load(File.read("#{MU.myRoot}/modules/mu/defaults/#{file}.yaml"), aliases: true)
            break
          end
        }
      end

      # Now overlay local overrides, both of the systemwide (/opt/mu/etc) and
      # per-user (~/.mu/etc) variety.
      [backwards_compat[cloud], cloud].each { |file|
        next if file.nil?
        if File.exist?("#{MU.etcDir}/#{file}.yaml")
          images ||= {}
          images.deep_merge!(YAML.load(File.read("#{MU.etcDir}/#{file}.yaml")))
        end
        if Process.uid != 0
          basepath = Etc.getpwuid(Process.uid).dir+"/.mu/etc"
          if File.exist?("#{basepath}/#{file}.yaml")
            images ||= {}
            images.deep_merge!(YAML.load(File.read("#{basepath}/#{file}.yaml")))
          end
        end
      }

      if images.nil?
        if fail_hard
          raise MuError, "Failed to find any base images for #{cloud}"
        else
          MU.log "Failed to find any base images for #{cloud}", MU::WARN if !quiet
          return nil
        end
      end

      PLATFORM_ALIASES.each_pair { |a, t|
        if images[t] and !images[a]
          images[a] = images[t]
        end
      }

      if platform
        if !images[platform]
          if fail_hard
            raise MuError, "No base image for platform #{platform} in cloud #{cloud}"
          else
            MU.log "No base image for platform #{platform} in cloud #{cloud}", MU::WARN if !quiet
            return nil
          end
        end
        images = images[platform]

        if region
          # We won't fuss about the region argument if this isn't a cloud that
          # has regions, just quietly don't bother.
          if images.is_a?(Hash)
            if images[region]
              images = images[region]
            else
              if fail_hard
                raise MuError, "No base image for platform #{platform} in cloud #{cloud} region #{region} found"
              else
                MU.log "No base image for platform #{platform} in cloud #{cloud} region #{region} found", MU::WARN if !quiet
                return nil
              end
            end
          end
        end
      else
        if region
          images.values.each { |regions|
            # Filter to match our requested region, but for all the platforms,
            # since we didn't specify one.
            if regions.is_a?(Hash)
              regions.delete_if { |r| r != region }
            end
          }
        end
      end

      images
    end

  end

end
