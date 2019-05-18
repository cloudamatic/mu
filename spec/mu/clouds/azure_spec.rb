require 'spec_helper'
require 'mu/clouds/azure'

describe MU::Cloud::Azure do

	is_azure_for_rizzle = MU::Cloud::Azure.hosted?

	p "It is #{is_azure_for_rizzle} that I am hosted in Azure I will test accordingly"

	# 	before(:all) do
	# 		@azure = MU::Cloud::Azure.new
	# 	end

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

	describe ".listRegions" do
		listRegions = MU::Cloud::Azure.listRegions
		it "responds with an array" do
			expect(listRegions.class).to eql(Array)
		end
		if is_azure_for_rizzle
			it "responds with TODO" do
				expect(listRegions).to eql(["TODO"])
			end
		else
			it "responds with empty array" do
				expect(listRegions).to eql([])
			end
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
			it "responds with TODO" do
				expect(MU::Cloud::Azure.hosted_config).to eql("TODO")
			end
		else
			it "responds with TODO" do
				expect(MU::Cloud::Azure.hosted_config).to eql(nil)
			end
		end
	end

	describe ".config_example" do
		if is_azure_for_rizzle
			it "responds with TODO" do
				expect(MU::Cloud::Azure.config_example).to eql({"TODO":"TODO"})
			end
		else
			default_sample = {"credentials_file"=>"~/.azure/credentials", "log_bucket_name"=>"my-mu-s3-bucket", "region"=>"eastus", "subscriptionId"=>"b8f6ed82-98b5-4249-8d2f-681f636cd787"}
			
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

	describe ".credConfig" do
		if is_azure_for_rizzle
			it "responds with TODO" do
				expect(MU::Cloud::Azure.credConfig).to eql({"TODO":"TODO"})
			end
		else
			it "returns nil because no credentials are configured" do
				expect(MU::Cloud::Azure.credConfig).to be_nil
			end
		end
	end
	
	describe ".listInstanceTypes" do
		it "responds with TODO" do
			expect(MU::Cloud::Azure.listInstanceTypes).to eql("TODO")
		end
	end

	describe ".get_metadata" do
		if is_azure_for_rizzle
			it "responds with a hash of expected metadata" do
				metadata = MU::Cloud::Azure.get_metadata()
				expect(metadata).to have_key(:compute)
				expect(metadata['compute']).to include(:location, :name, :osType, :subscriptionId, :vmId)
			end
		else
			it "responds with nil if not hosted in azure" do
				expect(MU::Cloud::Azure.get_metadata).to be_nil
			end
		end
	end

	describe ".myRegion" do
		if is_azure_for_rizzle
			it "responds with a valid region" do
				expect(MU::Cloud::Azure.myRegion).to eql('westus') #TODO Provide a valid list of regions
			end
		else
			it "responds with nil if not hosted in azure" do
				expect(MU::Cloud::Azure.myRegion).to be_nil
			end
		end
	end
end