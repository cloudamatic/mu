# Run this recipe at the end of any deploy that will be tested with inspec
# Required to produce node attributes for inspec to look at

ruby_block "Save node attributes" do
  block do
      IO.write("/tmp/chef_node.json", node.to_json)
  end
end
