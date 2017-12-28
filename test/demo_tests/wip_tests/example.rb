# encoding: utf-8
# copyright: 2017, The Authors

title 'Smoke Tests'

# you can also use plain tests
describe file('/tmp') do
  it { should be_directory }
end

# you add controls here
control 'tmp-1.0' do                        # A unique ID for this control
  impact 0.7                                # The criticality, if this control fails.
  title 'Create /tmp directory'             # A human-readable title
  desc 'An optional description...'
end



apache = 'httpd'

describe package('httpd') do
  it { should be_installed }
end

describe package('amrit') do
  it { should_not be_installed }
end

describe directory('/tmp/dir_1') do
  it { should exist}
end
