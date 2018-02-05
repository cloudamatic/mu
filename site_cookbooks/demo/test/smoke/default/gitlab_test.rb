# # encoding: utf-8

# Inspec test for recipe my_cookbook::default

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

unless os.windows?
  # This is an example test, replace with your own test.
  describe user('root') do
    it { should exist }
  end
end

# describe package('nginx') do
#   it { should be_installed }
# end

# This is an example test, replace it with your own test.
describe port(80), :skip do
  it { should be_listening }
end

describe port(443) do
  it { should be_listening }
end
