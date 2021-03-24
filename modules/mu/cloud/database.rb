# Copyright:: Copyright (c) 2020 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#     http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

module MU
  # Plugins under this namespace serve as interfaces to cloud providers and
  # other provisioning layers.
  class Cloud

    # Generic methods for all Database implementations
    class Database

      # Getting the password for a database's master user, and saving it in a database / cluster specific vault
      # @param complex [Boolean]: When generating passwords, use {Password}.random} instead of {Password}.pronounceable
      def getPassword(complex: false)
        if @config['password'].nil?
          if @config['auth_vault'] && !@config['auth_vault'].empty?
            @config['password'] = @groomclass.getSecret(
              vault: @config['auth_vault']['vault'],
              item: @config['auth_vault']['item'],
              field: @config['auth_vault']['password_field']
            )
          else
            begin
              @config['password'] = @groomclass.getSecret(
                vault: @mu_name,
                item: "database_credentials",
                field: "password"
              )
            rescue MuNoSuchSecret
              MU.log "Generating a password for database #{@mu_name}"
              @config['password'] = complex ? Password.random(12..14) : Password.pronounceable(10..12)
            end
          end
        end
  
        creds = {
          "username" => @config["master_user"],
          "password" => @config["password"]
        }
        @groomclass.saveSecret(vault: @mu_name, item: "database_credentials", data: creds)
      end

    end

  end

end
