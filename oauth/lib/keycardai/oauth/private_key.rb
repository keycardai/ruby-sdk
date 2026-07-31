# frozen_string_literal: true

require "fileutils"
require "jwt"
require "openssl"
require "securerandom"

module Keycardai
  module OAuth
    # Pluggable keypair persistence for WebIdentity. The duck type is
    # load(key_id) returning a PEM string or nil, and store(key_id, pem).
    # This default stores PEM files on disk, checking legacy directories on
    # load so existing keys keep working.
    class FilePrivateKeyStorage
      DEFAULT_DIR = "./server_keys"
      LEGACY_DIRS = ["./mcp_keys"].freeze

      # @param dir [String] directory for new and existing keys
      def initialize(dir: DEFAULT_DIR)
        @dir = dir
      end

      # @param key_id [String]
      # @return [String, nil] the stored PEM, or nil when absent
      def load(key_id)
        [@dir, *LEGACY_DIRS].each do |dir|
          path = File.join(dir, "#{key_id}.pem")
          return File.read(path) if File.file?(path)
        end
        nil
      end

      # @param key_id [String]
      # @param pem [String]
      # @return [void]
      def store(key_id, pem)
        FileUtils.mkdir_p(@dir)
        path = File.join(@dir, "#{key_id}.pem")
        File.write(path, pem)
        File.chmod(0o600, path)
      end
    end

    # Generates, persists, and loads an RSA-2048 keypair, and signs RFC 7523
    # private_key_jwt client assertions with it. WebIdentity composes this;
    # it is also usable standalone.
    class PrivateKeyManager
      ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
      DEFAULT_ASSERTION_LIFETIME = 300

      # @return [String] the key id (the JWT kid)
      attr_reader :key_id

      # @param key_id [String]
      # @param storage [#load, #store] keypair persistence
      # @param clock [#call] returns the current Time; override in tests
      def initialize(key_id:, storage: FilePrivateKeyStorage.new, clock: -> { Time.now })
        @key_id = key_id
        @storage = storage
        @clock = clock
        @key = nil
        @mutex = Mutex.new
      end

      # Load the persisted keypair, generating and storing one on first use.
      #
      # @return [OpenSSL::PKey::RSA]
      def key
        @mutex.synchronize do
          @key ||= begin
            pem = @storage.load(@key_id)
            pem ? OpenSSL::PKey::RSA.new(pem) : generate
          end
        end
      end

      # Sign a short-lived client assertion (RFC 7523 §3).
      #
      # @param client_id [String] becomes iss and sub
      # @param audience [String] the authorization server's token endpoint
      # @param expiry_seconds [Integer]
      # @return [String] the signed assertion
      def create_client_assertion(client_id:, audience:, expiry_seconds: DEFAULT_ASSERTION_LIFETIME)
        now = @clock.call.to_i
        claims = {
          "iss" => client_id, "sub" => client_id, "aud" => audience,
          "jti" => SecureRandom.uuid, "iat" => now, "exp" => now + expiry_seconds
        }
        JWTSigner.new(key: key, kid: @key_id).sign(claims)
      end

      # The public half as a JWKS document, for the authorization server to
      # verify assertions against.
      #
      # @return [Hash] {"keys" => [...]}
      def public_jwks
        jwk = JWT::JWK.new(key.public_key, { kid: @key_id, use: "sig", alg: "RS256" })
        { "keys" => [jwk.export.transform_keys(&:to_s)] }
      end

      private

      def generate
        key = OpenSSL::PKey::RSA.new(2048)
        @storage.store(@key_id, key.to_pem)
        key
      end
    end
  end
end
