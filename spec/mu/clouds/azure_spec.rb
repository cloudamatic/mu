require 'spec_helper'
require 'mu/clouds/azure'

describe MU::Cloud::Azure do

	describe ".hello" do
		before do
			@azure = MU::Cloud::Azure.new
		end

		it "responds with hello" do
			expect(MU::Cloud::Azure.hello).to eql('hello')
		end

	end

	describe ".hosted?" do
		before do
			@@azure = MU::Cloud::Azure.new
		end
		
		it "responds with false" do
			expect(MU::Cloud::Azure.hosted?).to eql(false)
		end

	end

end