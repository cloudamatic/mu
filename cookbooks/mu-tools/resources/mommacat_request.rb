
property :request, String, name_property: true
property :passparams, Hash

actions :run # ~FC092
default_action :run

action :run do
  mommacat_request(new_resource.request, new_resource.passparams)
end
