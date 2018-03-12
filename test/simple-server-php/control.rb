node =json('/tmp/chef_node.json').params
control 'apache' do
    title 'This will test apache2 recipe'
        # inspec-resources to test apache2 recipe
end

control 'php' do 
  title 'This will test the php recipe'
  # do something
end
