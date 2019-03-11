# Copyright:: Copyright (c) 2019 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#    http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


module MU
  # Plugins under this namespace serve as interfaces to host configuration
  # management tools, like Ansible or Puppet.
  class Groomer
    # Support for Ansible as a host configuration management layer.
    class Ansible

      # @param node [MU::Cloud::Server]: The server object on which we'll be operating
      def initialize(node)
      end

      # Indicate whether our server has been bootstrapped with Ansible
      def haveBootstrapped?
        true
      end

      # @param vault [String]: A repository of secrets to create/save into.
      # @param item [String]: The item within the repository to create/save.
      # @param data [Hash]: Data to save
      # @param permissions [String]: An implementation-specific string describing what node or nodes should have access to this secret.
      def self.saveSecret(vault: @server.mu_name, item: nil, data: nil, permissions: nil)
      end

      # see {MU::Groomer::Ansible.saveSecret}
      def saveSecret(vault: @server.mu_name, item: nil, data: nil, permissions: "name:#{@server.mu_name}")
        self.class.saveSecret(vault: vault, item: item, data: data, permissions: permissions)
      end

      # Retrieve sensitive data, which hopefully we're storing and retrieving
      # in a secure fashion.
      # @param vault [String]: A repository of secrets to search
      # @param item [String]: The item within the repository to retrieve
      # @param field [String]: OPTIONAL - A specific field within the item to return.
      # @return [Hash]
      def self.getSecret(vault: nil, item: nil, field: nil)
      end

      # see {MU::Groomer::Ansible.getSecret}
      def getSecret(vault: nil, item: nil, field: nil)
        self.class.getSecret(vault: vault, item: item, field: field)
      end

      # Delete a Ansible data bag / Vault
      # @param vault [String]: A repository of secrets to delete
      def self.deleteSecret(vault: nil, item: nil)
      end

      # see {MU::Groomer::Ansible.deleteSecret}
      def deleteSecret(vault: nil)
        self.class.deleteSecret(vault: vault)
      end

      # Invoke the Ansible client on the node at the other end of a provided SSH
      # session.
      # @param purpose [String]: A string describing the purpose of this client run.
      # @param max_retries [Integer]: The maximum number of attempts at a successful run to make before giving up.
      # @param output [Boolean]: Display Ansible's regular (non-error) output to the console
      # @param override_runlist [String]: Use the specified run list instead of the node's configured list
      def run(purpose: "Ansible run", update_runlist: true, max_retries: 5, output: true, override_runlist: nil, reboot_first_fail: false, timeout: 1800)
      end

      # Expunge
      def preClean(leave_ours = false)
      end

      # Forcibly (re)install Ansible. Useful for upgrading or overwriting a
      # broken existing install.
      def reinstall
      end

      # Bootstrap our server with Ansible
      def bootstrap
      end

      # Synchronize the deployment structure managed by {MU::MommaCat} to Ansible,
      # so that nodes can access this metadata.
      # @return [Hash]: The data synchronized.
      def saveDeployData
      end

      # Expunge Ansible resources associated with a node.
      # @param node [String]: The Mu name of the node in question.
      # @param vaults_to_clean [Array<Hash>]: Some vaults to expunge
      # @param noop [Boolean]: Skip actual deletion, just state what we'd do
      # @param nodeonly [Boolean]: Just delete the node and its keys, but leave other artifacts
      def self.cleanup(node, vaults_to_clean = [], noop = false, nodeonly: false)
      end

      private

    end # class Ansible
  end # class Groomer
end # Module Mu
