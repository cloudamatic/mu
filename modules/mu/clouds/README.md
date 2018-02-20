This is where we implement provisioning layers. This can be a full-featured
cloud provider, like Amazon Web Services, or a simple node virtualization
or containerization layer, like VMWare or Docker.

Implementing a New Cloud Resource Type
--------------------------------------

The following is a walkthrough for developers adding an entirely new cloud
resource type (e.g. `Server`, `Alarm`, etc), one which has not yet been defined
or implemented for **any** cloud layer. For this example we'll discuss the
`Function` resource type, which in cloud provider terms will be an implemention
for serverless code services such as AWS Lambda, Google Cloud Functions, etc.


1. Add stubs to `modules/mu/cloud.rb`. Edit files file, and you'll see a
`@@resource_types` hash describing each cloud resource type Mu supports. The
configuration here governs a lot of Mu deployment engine behaviors, as well as
interaction with the configuration parser. For our `Function` type, we'll keep
it simple:


```
      :Function => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "function",
        :cfg_plural => "functions",
        :interface => self.const_get("Function"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => generic_class_methods,
        :instance => generic_instance_methods
      }

```

2. Add our new type to the configuration schema in `modules/mu/config.rb`. This is where our parser learns to look for our type when loading Basket of Kittens YAML or JSON files. Let's start by adding to the top-level of the `@@schema` hash, which is actually a [http://json-schema.org/](JSON Schema) definition.

Part way down, you'll see where our resource types are listed, such as:

```
            "server_pools" => {
                "type" => "array",
                "items" => @server_pool_primitive
            },
            "cache_clusters" => {
                "type" => "array",
                "items" => @cache_cluster_primitive
            }

```

Note that the `items` parameter points to a variable elsewhere, so that we
don't try to define our schema entirely inline. We're going to add one for our new type:

```
            "functions" => {
                "type" => "array",
                "items" => @function_primitive
            }
```

...and since we've said that we're going to look for `@function_primitive`, let's go ahead and define that with a minimal set of properties.

```
    @function_primitive = {
      "type" => "object",
      "title" => "Function",
      "description" => "Create a serverless function.",
      "required" => ["name", "cloud"],
      "additionalProperties" => false,
      "properties" => {
        "cloud" => @cloud_primitive,
        "name" => {"type" => "string"},
        "region" => MU::Config.region_primitive,
        "vpc" => vpc_reference_primitive(ONE_SUBNET+MANY_SUBNETS, NO_NAT_OPTS, "all_private"),
        "tags" => @tags_primitive,
        "optional_tags" => {
          "type" => "boolean",
          "description" => "Tag the resource with our optional tags (MU-HANDLE, MU-MASTER-NAME, MU-OWNER). Defaults to true",
        },
      }
    }

```

3. Define an empty implemention. Remember in step 1 where we had a couple configuration variables in our little hash (`:class => generic_class_methods`, `:instance => generic_instance_methods`)? Well those are lists of class methods and instance methods that our implemention will be required to have.

Looking elsewhere in `cloud.rb` let's see what all we have to do:

```
    generic_class_methods = [:find, :cleanup, :validateConfig, :schema]
    generic_instance_methods = [:create, :notify, :mu_name, :cloud_id, :config]
```

Just the basics, for now. Here's what that will look like in the AWS layer, in the file `modules/mu/clouds/aws/function.rb`:

```
module MU
  class Cloud
    class AWS
      # A function as configured in {MU::Config::BasketofKittens::functions}
      class Function < MU::Cloud::Function
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        @cloudformation_data = {}
        attr_reader :cloudformation_data

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::functions}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
        end

        # Return the metadata for this Function rule
        # @return [Hash]
        def notify
          deploy_struct = {
          }
          return deploy_struct
        end

        # Remove all functions associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
        end

        # Locate an existing function.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching function.
        def self.find(cloud_id: nil, region: MU.curRegion, flags: {})
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {}
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::functions}, bare and unvalidated.
        # @param function [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(function, configurator)
          ok = true
#          if something_bad
#            ok = false
#          end

          ok
        end

      end
    end
  end
end
```

As you press forward in your implementation, you may find that it makes sense
to add other requirements to this resource type.  For example, many resource
types, such as `Servers`, have a `groom` phase that is invoked after initial
creation, but which can be run asynchronously with dependent child resources.
Others have methods that are peculiar to the resource type, such as the
`addRule` method for the `FirewallRule` type.

Most of these methods are self-explanatory, and you can look at other resource types for examples of actual implementation.

A bit about the purpose of the `self.schema` class method. This is for
injecting cloud-specific properties into the schema we defined in
step 2. Cloud providers often have nuanced functionality that doesn't map to
similar behavior in other providers, so we insert that here in the cloud layer
rather than the global config schema. Here's an example in the AWS `Server` implementation:

```
        def self.schema(config)
          toplevel_required = []
          schema = {
            "ami_id" => {
              "type" => "string",
              "description" => "The Amazon EC2 AMI on which to base this instance. Will use the default appropriate for the platform, if not specified."
            }
          }
          [toplevel_required, schema]
        end

```
