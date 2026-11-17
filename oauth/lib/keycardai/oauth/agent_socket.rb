# frozen_string_literal: true

require "pathname"

module Keycardai
  module OAuth
    # Resolves the Unix socket an AgentTokenSource dials, by the first rule
    # that applies: the caller's explicit socket, then +KEYCARD_SOCKET+, then
    # the +keycard agent+ daemon's default socket. Not public API.
    #
    # The default socket transcribes the Keycard CLI's own resolution
    # (+Config.AgentSocketPath+), so an SDK and a daemon started with the same
    # environment agree on the path. Only the given environment is read, never
    # +keycard.toml+, and nothing on disk is created or checked.
    module AgentSocket
      # A resolved socket path and the rule that chose it: +:socket+,
      # +:keycard_socket+, or +:default+.
      Resolved = Data.define(:path, :rule) do
        # @return [String] the rule, as a network error names it
        def rule_description
          case rule
          when :socket then "the socket option"
          when :keycard_socket then "KEYCARD_SOCKET"
          else "the default agent socket"
          end
        end
      end

      # @param socket [String, nil] the caller's explicit path
      # @param env [#[]] where the variables are read from
      # @return [Resolved]
      # @raise [ConfigurationError] when the default socket is needed and cannot
      #   be resolved
      def self.resolve(socket:, env:)
        return Resolved.new(path: socket, rule: :socket) if set?(socket)

        from_env = env["KEYCARD_SOCKET"]
        return Resolved.new(path: from_env, rule: :keycard_socket) if set?(from_env)

        Resolved.new(path: default_path(env), rule: :default)
      end

      def self.default_path(env)
        if Gem.win_platform?
          raise ConfigurationError,
                "KEYCARD_SOCKET is not set, and the Keycard agent's default socket does not exist on Windows; " \
                "pass socket: or set KEYCARD_SOCKET"
        end

        # filepath.Join in the CLI cleans the joined path; cleanpath is its analogue.
        Pathname.new(File.join(agent_dir(env), "agent.sock")).cleanpath.to_s
      end

      def self.agent_dir(env)
        variable(env, "KEYCARD_AGENT_DIR") || run_dir(env)
      end

      def self.run_dir(env)
        runtime = variable(env, "XDG_RUNTIME_DIR")
        runtime ? File.join(runtime, "keycard") : File.join(state_dir(env), "run")
      end

      def self.state_dir(env)
        state = variable(env, "XDG_STATE_HOME")
        state ? File.join(state, "keycard") : File.join(home_dir(env), ".local", "state", "keycard")
      end

      def self.home_dir(env)
        variable(env, "KEYCARD_HOME") || variable(env, "HOME") ||
          raise(ConfigurationError,
                "KEYCARD_SOCKET is not set, and neither KEYCARD_HOME nor HOME is set to locate the Keycard " \
                "agent's default socket; pass socket: or set KEYCARD_SOCKET")
      end

      def self.variable(env, name)
        value = env[name]
        value if set?(value)
      end

      def self.set?(value)
        !value.nil? && !value.empty?
      end

      private_class_method :default_path, :agent_dir, :run_dir, :state_dir, :home_dir, :variable, :set?
    end
  end
end
