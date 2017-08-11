
property :request, String, name_property: true
property :params, Hash

actions :run
default_action :run

action :run do
  params = Base64.urlsafe_encode64(JSON.generate(new_resource.params))
  mommacat_request(new_resource.request, params)
end
