# Copyright:: Copyright (c) 2018 eGlobalTech, Inc., all rights reserved
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
  class Config
    # Basket of Kittens config schema and parser logic. See modules/mu/clouds/*/function.rb
    class Function

      # Base configuration schema for a Function
      # @return [Hash]
      def self.schema
      {
        "type" => "object",
        "title" => "Function",
        "description" => "Create a cloud function.",
        "required" => ["name", "cloud","runtime","iam_role","handler","code","region"],
        "additionalProperties" => false,
        "properties" => {
          "cloud" => MU::Config.cloud_primitive,
          "name" => {"type" => "string"},
          "runtime" => {
            "type" => "string",
            "enum" => %w{nodejs nodejs4.3 nodejs6.10 nodejs8.10 java8 python2.7 python3.6 dotnetcore1.0 dotnetcore2.0 dotnetcore2.1 nodejs4.3-edge go1.x}
          },
          "iam_role" => {"type" => "string"},
          "region" => MU::Config.region_primitive,
          "vpc" => MU::Config::VPC.reference(MU::Config::VPC::ONE_SUBNET+MU::Config::VPC::MANY_SUBNETS, MU::Config::VPC::NO_NAT_OPTS, "all_private"),
          "handler" => {
            "type" => "string",
            "description" => "The function within your code that Lambda calls to begin execution. For Node.js, it is the module-name.export value in your function. For Java, it can be package.class-name::handler or package.class-name. For more information, see https://docs.aws.amazon.com/lambda/latest/dg/java-programming-model-handler-types.html"
          }, 
          "timeout" => {
            "type" => "integer",
            "description" => "Maximum run time for an invocation of this function, in seconds",
            "default" => 3
          },
          "tags" => MU::Config.tags_primitive,
          "memory" => {
            "type" => "integer",
            "default" => 128,
            "description" => "Memory to allocation for function, in MB. The value must be a multiple of 64 MB."
          },
          "dependencies" => MU::Config.dependencies_primitive,
          "optional_tags" => {
            "type" => "boolean",
            "description" => "Tag the resource with our optional tags (MU-HANDLE, MU-MASTER-NAME, MU-OWNER)."
          },
          "triggers" => {
            "type" => "array",
            "items" => {
              "type" => "object",
              "description" => "Trigger for lambda function",
              "required" => ["service"],
              "additionalProperties" => false,
              "properties" => {
                "service" => {
                  "type" => "string",
                  "enum" => %w{apigateway events s3 sns sqs dynamodb kinesis ses cognito alexa iot},
                  "description" => "The name of the AWS service that will trigger this function"
                },
                "name" => {
                  "type" => "string",
                  "description" => "The name of the API Gateway, Cloudwatch Event, or other event trigger object"
                }
              }
            }
          },
          "code" => {
            "type" => "object",  
            "description" => "Zipped deployment package to upload to Lambda. You must specify either s3_bucket+s3_key or zip_file.", 
            "additionalProperties" => false,
            "properties" => {  
              "s3_bucket" => {
                "type" => "string",
                "description" => "An S3 bucket where the deployment package can be found. Must be used in conjunction with s3_key."
              }, 
              "s3_key" => {
                "type" => "string",
                "description" => "Key in s3_bucket where the deployment package can be found. Must be used in conjunction with s3_bucket."
              }, 
              "s3_object_version" => {
                "type" => "string",
                "description" => "Specify an S3 object version for the deployment package, instead of the current default"
              }, 
              "zip_file" => {
                "type" => "string",
                "description" => "Path to a zipped deployment package to upload."
              } 
            }
          },
          "environment_variable" => {
            "type" => "array", 
            "minItems" => 1, 
            "items" => { 
              "description" => "environment variables",  
              "type" => "object",  
              "title" => "tags", 
              "required" => ["key", "value"],  
              "additionalProperties" => false, 
              "properties" => {  
                "key" => { 
                  "type" => "string",  
                }, 
                "value" => { 
                  "type" => "string",  
                }  
              }  
            }  
          }
        }
      } 
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::functions}, bare and unvalidated.
      # @param function [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(function, configurator)
        ok = true
        if function['code']['zip_file']
          if !File.readable?(function['code']['zip_file'])
            MU.log "Can't read deployment package #{function['code']['zip_file']}", MU::ERR
            ok = false
          end
        end

        ok
      end

    end
  end
end
