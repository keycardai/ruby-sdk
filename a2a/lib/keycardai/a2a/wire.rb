# frozen_string_literal: true

module Keycardai
  module A2A
    # A2A protocol version spoken by default: the 1.0 generation, which is
    # what keycardai-a2a (Python) and @keycardai/a2a (TypeScript) serve.
    PROTOCOL_VERSION = "1.0"

    # The 0.3 generation, for agents not yet on 1.0. Pass it as
    # DelegationClient's protocol_version: to send 0.3-shaped requests.
    LEGACY_PROTOCOL_VERSION = "0.3"

    # JSON-RPC method that delivers a message to a 1.0 agent.
    MESSAGE_SEND_METHOD = "SendMessage"

    # JSON-RPC method that delivers a message to a 0.3 agent.
    LEGACY_MESSAGE_SEND_METHOD = "message/send"

    # Header carrying the protocol version on a 1.0 request.
    PROTOCOL_VERSION_HEADER = "A2A-Version"

    # Header carrying the protocol version on a 0.3 request.
    LEGACY_PROTOCOL_VERSION_HEADER = "X-A2A-Protocol-Version"

    # Message roles as the 1.0 protocol names them (0.3 used "user"/"agent").
    ROLE_USER = "ROLE_USER"
    ROLE_AGENT = "ROLE_AGENT"

    # One protocol generation's wire conventions: the JSON-RPC method, the
    # version header, and how message roles and text parts are spelled. The
    # version selects the whole envelope, never only the header.
    class Wire
      LEGACY_ROLES = { ROLE_USER => "user", ROLE_AGENT => "agent" }.freeze

      # @param version [String] PROTOCOL_VERSION or LEGACY_PROTOCOL_VERSION
      # @raise [ArgumentError] any other value
      def self.for(version)
        case version
        when PROTOCOL_VERSION
          new(version: version, header: PROTOCOL_VERSION_HEADER, method_name: MESSAGE_SEND_METHOD)
        when LEGACY_PROTOCOL_VERSION
          new(version: version, header: LEGACY_PROTOCOL_VERSION_HEADER, method_name: LEGACY_MESSAGE_SEND_METHOD)
        else
          raise ArgumentError, "unsupported A2A protocol version #{version.inspect} " \
                               "(supported: #{PROTOCOL_VERSION}, #{LEGACY_PROTOCOL_VERSION})"
        end
      end

      attr_reader :version, :header, :method_name

      def initialize(version:, header:, method_name:)
        @version = version
        @header = header
        @method_name = method_name
      end

      def legacy?
        version == LEGACY_PROTOCOL_VERSION
      end

      # Encode 1.0-shaped params (as built by A2A.text_message) for the wire.
      # On 1.0 they pass through; on 0.3 the message role takes its 0.3 name
      # and text parts gain the kind tag 0.3 requires.
      def encode_params(params)
        message = params.is_a?(Hash) ? params["message"] : nil
        return params unless legacy? && message.is_a?(Hash)

        params.merge("message" => message.merge(
          "role" => LEGACY_ROLES.fetch(message["role"], message["role"]),
          "parts" => Array(message["parts"]).map { |part| legacy_part(part) }
        ))
      end

      # The invocation endpoint from an agent card: a 1.0 card's JSONRPC
      # interface (preferring the one matching this version), else a 0.3
      # card's url, else nil.
      def endpoint_from(card)
        interfaces = Array(card["supportedInterfaces"]).select { |iface| jsonrpc_interface?(iface) }
        matching = interfaces.find { |iface| iface["protocolVersion"] == version } || interfaces.first
        return matching["url"] if matching

        card["url"] if card["url"].is_a?(String) && !card["url"].empty?
      end

      private

      def legacy_part(part)
        return part unless part.is_a?(Hash) && part.key?("text") && !part.key?("kind")

        { "kind" => "text" }.merge(part)
      end

      def jsonrpc_interface?(iface)
        iface.is_a?(Hash) && iface["protocolBinding"].to_s.casecmp?("JSONRPC") &&
          iface["url"].is_a?(String) && !iface["url"].empty?
      end
    end
  end
end
