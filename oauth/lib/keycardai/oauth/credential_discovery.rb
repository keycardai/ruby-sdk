# frozen_string_literal: true

module Keycardai
  # OAuth primitives and application credentials for Keycard.
  module OAuth
    # Builds the application credential described by the environment.
    #
    # @param env [#[]] mapping with environment variable names as string keys
    # @param web_identity_server_name [String, nil] name used for the WebIdentity key id
    # @return [ClientSecret, WorkloadIdentity, WebIdentity]
    # @raise [CredentialDiscoveryError] the configuration does not select a usable credential
    # @raise [WorkloadIdentityConfigurationError] the selected token file is missing or empty
    def self.discover_application_credential(env: ENV, web_identity_server_name: nil)
      CredentialDiscovery.new(env).discover(web_identity_server_name)
    end

    # Resolves and constructs a credential from one environment mapping.
    class CredentialDiscovery
      include PrintedForm

      SELECTOR = "KEYCARD_APPLICATION_CREDENTIAL_TYPE"
      STORAGE_DIR = "KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR"
      TYPES = %w[client_secret workload_identity web_identity].freeze

      def initialize(env)
        @client_id = value(env, "KEYCARD_CLIENT_ID")
        @client_secret = value(env, "KEYCARD_CLIENT_SECRET")
        @token_file = FileTokenSource::DEFAULT_ENV_VARS.lazy.filter_map { |name| value(env, name) }.first
        @storage_dir = value(env, STORAGE_DIR)
        @selector = value(env, SELECTOR)
        @resolvable = []
        @resolvable << "client_secret" if @client_id && @client_secret
        @resolvable << "workload_identity" if @token_file
        @resolvable << "web_identity" if @storage_dir
      end

      def discover(web_identity_server_name)
        case @selector ? selected_type : inferred_type
        when "client_secret"
          ClientSecret.new(@client_id, @client_secret)
        when "workload_identity"
          WorkloadIdentity.new(source: FileTokenSource.new(token_file_path: @token_file), client_id: @client_id)
        when "web_identity"
          WebIdentity.new(server_name: web_identity_server_name, storage_dir: @storage_dir)
        end
      end

      def inspect
        "#<#{self.class} client_id=#{@client_id.inspect}, resolvable=#{@resolvable.inspect}>"
      end

      private

      def value(env, name)
        value = env[name]
        value if value && !value.empty?
      end

      def selected_type
        type = @selector == "eks_workload_identity" ? "workload_identity" : @selector
        fail_discovery(:unknown_type, "Unknown #{SELECTOR}; use one of #{TYPES.join(", ")}") unless TYPES.include?(type)
        return type if type == "web_identity" || @resolvable.include?(type)

        inputs = if type == "client_secret"
                   "both KEYCARD_CLIENT_ID and KEYCARD_CLIENT_SECRET"
                 else
                   "a token file path in one of #{FileTokenSource::DEFAULT_ENV_VARS.join(", ")}"
                 end
        fail_discovery(:not_satisfiable, "#{SELECTOR}=#{type} requires #{inputs}")
      end

      def inferred_type
        if @client_secret && !@client_id
          fail_discovery(:incomplete, "KEYCARD_CLIENT_SECRET is set without KEYCARD_CLIENT_ID")
        end
        if @resolvable.empty?
          fail_discovery(:absent, "No application credential found in the environment. Set KEYCARD_CLIENT_ID " \
                                  "and KEYCARD_CLIENT_SECRET, a token file variable, or #{STORAGE_DIR}")
        end
        if @resolvable.size > 1
          fail_discovery(:ambiguous, "The environment configures #{@resolvable.join(" and ")}. " \
                                     "Set #{SELECTOR} to choose one")
        end
        @resolvable.first
      end

      def fail_discovery(reason, message)
        raise CredentialDiscoveryError.new(message, reason: reason, resolvable: @resolvable)
      end
    end
    private_constant :CredentialDiscovery
  end
end
