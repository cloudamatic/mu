
ruby_block "Save node attributes" do
  block do
    IO.write("/tmp/chef_node.json", node.to_json)
 end
end
