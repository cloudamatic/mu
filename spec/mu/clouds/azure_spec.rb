require 'spec_helper'
require 'mu/clouds/azure'

describe MU::Cloud::Azure do

	@@is_azure = MU::Cloud::Azure.hosted?

	# 	before(:all) do
	# 		@azure = MU::Cloud::Azure.new
	# 	end

	describe ".hosted?" do
		
		it "responds with #{@@is_azure}" do
			expect(MU::Cloud::Azure.hosted?).to be(@@is_azure)
		end

	end

	describe ".hosted" do
		
		it "responds with true or false" do
			expect(MU::Cloud::Azure.hosted?).to be(true).or be(false)
		end

	end

	describe ".required_instance_methods" do
		it "responds with an empty array of required methods" do
			methods = MU::Cloud::Azure.required_instance_methods
			expect(methods).to eql([])
		end
	end

	describe ".listRegions" do
		it "responds with false" do
			expect(MU::Cloud::Azure.listRegions).to eql(["TODO"])
		end
	end

	describe ".listAZs" do
		it "responds with false" do
			expect(MU::Cloud::Azure.listAZs).to eql(["TODO"])
		end
	end

	describe ".hosted_config" do
		it "responds with false" do
			expect(MU::Cloud::Azure.hosted_config).to eql("TODO")
		end
	end

	describe ".config_example" do
		it "responds with false" do
			expect(MU::Cloud::Azure.config_example).to eql({"TODO":"TODO"})
		end
	end

	describe ".writeDeploySecret" do
		it "responds with false" do
			expect(MU::Cloud::Azure.writeDeploySecret).to eql("TODO")
		end
	end

	describe ".listCredentials" do
		it "responds with false" do
			expect(MU::Cloud::Azure.listCredentials).to eql("TODO")
		end
	end

	describe ".credConfig" do
		it "responds with false" do
			expect(MU::Cloud::Azure.credConfig).to eql("TODO")
		end
	end
	
	describe ".listInstanceTypes" do
		it "responds with false" do
			expect(MU::Cloud::Azure.listInstanceTypes).to eql("TODO")
		end
	end
end