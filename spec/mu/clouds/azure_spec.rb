require 'spec_helper'
require 'mu/clouds/azure'

describe MU::Cloud::Azure do

	before(:all) do
		$MU_CFG = YAML.load(File.read("spec/mu.yml"))
	end

	is_azure_for_rizzle = MU::Cloud::Azure.hosted?

	p "It is #{is_azure_for_rizzle} that I am hosted in Azure I will test accordingly"

	describe ".hosted?" do
		
		it "responds with #{is_azure_for_rizzle}" do
			expect(MU::Cloud::Azure.hosted?).to be(is_azure_for_rizzle)
		end

	end

	describe ".hosted" do
		
		it "responds with #{is_azure_for_rizzle}" do
			expect(MU::Cloud::Azure.hosted?).to be(is_azure_for_rizzle)
		end

	end

	describe ".required_instance_methods" do
		it "responds with an empty array of required methods" do
			methods = MU::Cloud::Azure.required_instance_methods
			expect(methods).to eql([])
		end
	end

	describe ".default_subscription" do
		it "returns a subscription string" do
			expect(MU::Cloud::Azure.default_subscription()).to be_a(String)
		end
	end

	describe ".listRegions" do
		before(:all) do
			@regionList = MU::Cloud::Azure.listRegions()
		end

		it "responds with an array" do
			expect(@regionList.class).to eql(Array)
		end

		it "responds with an array of strings" do
			expect(@regionList).to all( be_a(String) )
		end
	end

	describe ".listAZs" do
		listAZs = MU::Cloud::Azure.listAZs
		it "responds with an array" do
			expect(listAZs.class).to eql(Array)
		end
		if is_azure_for_rizzle
			it "responds with TODO" do
				expect(listAZs).to eql(["TODO"])
			end
		else
			it "responds with empty array" do
				expect(listAZs).to eql([])
			end
		end
	end

	describe ".hosted_config" do
		if is_azure_for_rizzle
			it "responds with a valid configuation hash" do
				example = MU::Cloud::Azure.hosted_config()
				#TODO DETERMINE WHAT ARE REQUIRED CONFIGURATIONS
				#expect(example).to have_key('credentials_file')
				#expect(example).to have_key('log_bucket_name')
				expect(example).to have_key('region')
				expect(example).to have_key('subscriptionId')
			end
		else
			it "responds with nil" do
				expect(MU::Cloud::Azure.hosted_config).to eql(nil)
			end
		end
	end

	describe ".config_example" do
		if is_azure_for_rizzle
			it "responds with a valid configuation hash" do
				example = MU::Cloud::Azure.config_example()
				expect(example).to have_key('credentials_file')
				expect(example).to have_key('log_bucket_name')
				expect(example).to have_key('region')
				expect(example).to have_key('subscriptionId')
			end
			it "responds with the correct region" do
				example = MU::Cloud::Azure.config_example()
				expect(example['region']).to eql(MU::Cloud::Azure.myRegion())
			end
		else
			default_sample = {"credentials_file"=>"~/.azure/credentials", "log_bucket_name"=>"my-mu-s3-bucket", "region"=>"eastus", "subscriptionId"=>"99999999-9999-9999-9999-999999999999"}
			
			it "example matches sample" do
				expect(MU::Cloud::Azure.config_example).to eql(default_sample)
			end
		end
	end

	describe ".writeDeploySecret" do
		it "responds with TODO" do
			expect(MU::Cloud::Azure.writeDeploySecret).to eql("TODO")
		end
	end

	describe ".listCredentials" do
		it "responds with TODO" do
			expect(MU::Cloud::Azure.listCredentials).to eql("TODO")
		end
	end

	# describe ".credConfig" do
	# 	if is_azure_for_rizzle
	# 		it "responds with TODO" do
	# 			expect(MU::Cloud::Azure.credConfig).to eql({"TODO":"TODO"})
	# 		end
	# 	else
	# 		it "returns nil because no credentials are configured" do
	# 			expect(MU::Cloud::Azure.credConfig).to be_nil
	# 		end
	# 	end
	# end
	
	describe ".listInstanceTypes" do
		it "responds with TODO" do
			expect(MU::Cloud::Azure.listInstanceTypes).to eql("TODO")
		end
	end

	describe ".get_metadata" do
		if is_azure_for_rizzle
			it "responds with a hash of expected metadata" do
				metadata = MU::Cloud::Azure.get_metadata()
				expect(metadata).to have_key('compute')
				expect(metadata).to have_key('network')
				expect(metadata['compute']).to have_key('location')
				expect(metadata['compute']).to have_key('name')
				expect(metadata['compute']).to have_key('osType')
				expect(metadata['compute']).to have_key('subscriptionId')
				expect(metadata['compute']).to have_key('vmId')
			end
		else
			it "responds with nil if not hosted in azure" do
				expect(MU::Cloud::Azure.get_metadata).to be_nil
			end
		end
	end

	describe ".list_subscriptions" do
		subscriptions = MU::Cloud::Azure.list_subscriptions

		it "responds with an array" do
			expect(subscriptions.class).to eql(Array)
		end

		it "responds with an array of strings" do
			expect(subscriptions).to all( be_a(String) )
		end
	end

end