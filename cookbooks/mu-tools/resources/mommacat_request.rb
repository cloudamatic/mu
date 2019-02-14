
property :request, String, name_property: true
property :passparams, Hash

actions :run # ~FC092
default_action :run

action :run do
  params = Base64.urlsafe_encode64(JSON.generate(new_resource.passparams))
  mommacat_request(new_resource.request, params)
end
