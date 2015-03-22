require 'spec_helper'

describe 'mysql-chef_gem_test::default' do
  let(:chef_run) do
    ChefSpec::Runner.new do |node|
      node.set['mysql_chef_gem']['resource_name'] = 'default'
    end.converge('mysql-chef_gem_test::default')
  end

  context 'when using default parameters' do
    it 'creates mysql-chef_gem[default]' do
      expect(chef_run).to install_mysql_chef_gem('default')
    end
  end
end
