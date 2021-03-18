# Temporary workarounds for the very broken Azure KeyVault gem

module Azure::KeyVault::V7_1
  #
  # A service client - single point of access to the REST API.
  #
  class KeyVaultClient < MsRestAzure::AzureServiceClient

    # Sets a secret in a specified key vault.
    #
    # The SET operation adds a secret to the Azure Key Vault. If the named secret
    # already exists, Azure Key Vault creates a new version of that secret. This
    # operation requires the secrets/set permission.
    #
    # @param vault_base_url [String] The vault name, for example
    # https://myvault.vault.azure.net.
    # @param secret_name [String] The name of the secret.
    # @param value [String] The value of the secret.
    # @param tags [Hash{String => String}] Application specific metadata in the
    # form of key-value pairs.
    # @param content_type [String] Type of the secret value such as a password.
    # @param secret_attributes [SecretAttributes] The secret management attributes.
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def set_secret_async(vault_base_url, secret_name, value, tags:nil, content_type:nil, secret_attributes:nil, custom_headers:nil)
      fail ArgumentError, 'vault_base_url is nil' if vault_base_url.nil?
      fail ArgumentError, 'secret_name is nil' if secret_name.nil?
      fail ArgumentError, "'secret_name' should satisfy the constraint - 'Pattern': '^[0-9a-zA-Z-]+$'" if !secret_name.nil? && secret_name.match(Regexp.new('^^[0-9a-zA-Z-]+$$')).nil?
      fail ArgumentError, 'api_version is nil' if api_version.nil?
      fail ArgumentError, 'value is nil' if value.nil?

      parameters = Azure::KeyVault::V7_1::Models::SecretSetParameters.new
      unless value.nil? && tags.nil? && content_type.nil? && secret_attributes.nil?
        parameters.value = value
        parameters.tags = tags
        parameters.content_type = content_type
        parameters.secret_attributes = secret_attributes
      end

      request_headers = {}
      request_headers['Content-Type'] = 'application/json; charset=utf-8'

      # Set Headers
      request_headers['x-ms-client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = accept_language unless accept_language.nil?

      # Serialize Request
      request_mapper = Azure::KeyVault::V7_1::Models::SecretSetParameters.mapper()
      request_content = self.serialize(request_mapper,  parameters)
      request_content = request_content != nil ? JSON.generate(request_content, quirks_mode: true) : nil

      path_template = 'secrets/{secret-name}'

      request_url = @base_url || self.base_url
    request_url = request_url.gsub('{vaultBaseUrl}', vault_base_url)

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          path_params: {'secret-name' => secret_name},
          query_params: {'api-version' => api_version},
          body: request_content,
          headers: request_headers.merge(custom_headers || {}),
          base_url: request_url
      }
      promise = self.make_request_async(:put, path_template, options)

      promise = promise.then do |result|
        http_response = result.response
        status_code = http_response.status
        response_content = http_response.body
        unless status_code == 200
          error_model = JSON.load(response_content)
          fail MsRest::HttpOperationError.new(result.request, http_response, error_model)
        end

        result.request_id = http_response['x-ms-request-id'] unless http_response['x-ms-request-id'].nil?
        result.correlation_request_id = http_response['x-ms-correlation-request-id'] unless http_response['x-ms-correlation-request-id'].nil?
        result.client_request_id = http_response['x-ms-client-request-id'] unless http_response['x-ms-client-request-id'].nil?
        # Deserialize Response
        if status_code == 200
          begin
            parsed_response = response_content.to_s.empty? ? nil : JSON.load(response_content)
            result_mapper = Azure::KeyVault::V7_1::Models::SecretBundle.mapper()
            result.body = self.deserialize(result_mapper, parsed_response)
          rescue Exception => e
            fail MsRest::DeserializationError.new('Error occurred in deserializing the response', e.message, e.backtrace, result)
          end
        end

        result
      end

      promise.execute
    end

  end
end
