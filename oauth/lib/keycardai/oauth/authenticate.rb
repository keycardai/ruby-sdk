# frozen_string_literal: true

require "json"
require "securerandom"
require "socket"
require "uri"

module Keycardai
  # The high-level authorization-code convenience: open the browser, receive
  # the redirect on a loopback server (RFC 8252), exchange the code.
  module OAuth
    DEFAULT_CALLBACK_PORT = 8765
    DEFAULT_CALLBACK_TIMEOUT = 300

    # Run the full authorization-code + PKCE login flow: generate the PKCE
    # pair and a CSRF state, build the authorize URL, open the user's
    # browser, receive the redirect on a local loopback server, validate the
    # state, and exchange the code for a token.
    #
    # @param issuer [String] the zone's issuer URL
    # @param client_id [String]
    # @param scope [String, nil] space-separated scopes
    # @param resource [String, nil] RFC 8707 resource indicator
    # @param port [Integer] loopback port; 0 binds an ephemeral port
    # @param callback_timeout [Numeric] seconds to wait for the redirect
    # @param client_secret [String, nil] confidential clients only
    # @param verifier_length [Integer] PKCE verifier length, 43 to 128
    # @param http_client [#get, #post_form] pluggable transport
    # @param browser_opener [#call, nil] receives the authorize URL; defaults
    #   to the platform opener (open / xdg-open / cmd start), shell-free
    # @param timeout [Numeric, nil] HTTP timeout for discovery and exchange
    # @return [TokenResponse]
    # @raise [InteractionTimeoutError] the user did not complete the redirect
    # @raise [OAuthError] the authorization server denied the request
    # @raise [ProtocolError] the redirect's state did not match (code state_mismatch)
    def self.authenticate(issuer:, client_id:, scope: nil, resource: nil, port: DEFAULT_CALLBACK_PORT,
                          callback_timeout: DEFAULT_CALLBACK_TIMEOUT, client_secret: nil,
                          verifier_length: PKCE::DEFAULT_VERIFIER_LENGTH,
                          http_client: HTTP::NetHTTPClient.new, browser_opener: nil, timeout: nil)
      authorization_endpoint = authorization_endpoint_for(issuer, http_client, timeout)
      pair = PKCE.generate_pair(length: verifier_length)
      state = SecureRandom.urlsafe_base64(24)

      Loopback::CallbackServer.open(port: port) do |server|
        open_authorize_page(server, authorization_endpoint, pair, state,
                            client_id: client_id, scope: scope, resource: resource,
                            browser_opener: browser_opener)
        code = server.wait_for_code(state: state, timeout: callback_timeout)
        exchange_authorization_code(
          issuer,
          code: code, code_verifier: pair.code_verifier, redirect_uri: server.redirect_uri,
          client_id: client_id, client_secret: client_secret, resource: resource,
          http_client: http_client, timeout: timeout
        )
      end
    end

    def self.authorization_endpoint_for(issuer, http_client, timeout)
      metadata = fetch_authorization_server_metadata(issuer, http_client: http_client, timeout: timeout)
      metadata.authorization_endpoint ||
        raise(ProtocolError.new("metadata for #{issuer} has no authorization_endpoint", code: "invalid_metadata"))
    end
    private_class_method :authorization_endpoint_for

    def self.open_authorize_page(server, endpoint, pair, state, client_id:, scope:, resource:, browser_opener:)
      url = build_authorize_url(
        endpoint,
        client_id: client_id, redirect_uri: server.redirect_uri, code_challenge: pair.code_challenge,
        code_challenge_method: pair.code_challenge_method, scope: scope, state: state, resource: resource
      )
      (browser_opener || Loopback.method(:open_browser)).call(url)
    end
    private_class_method :open_authorize_page

    # Resolve the issuer from a resource's WWW-Authenticate challenge
    # (RFC 9728): fetch the challenge's resource_metadata document and return
    # its first authorization server.
    #
    # @param www_authenticate [String] the WWW-Authenticate header value
    # @param http_client [#get] pluggable transport
    # @param timeout [Numeric, nil]
    # @return [String] the issuer URL
    # @raise [ProtocolError] no resource_metadata parameter, or a metadata
    #   document without authorization_servers
    def self.resolve_issuer_from_challenge(www_authenticate, http_client: HTTP::NetHTTPClient.new, timeout: nil)
      metadata_url = www_authenticate.to_s[/resource_metadata="([^"]+)"/, 1]
      unless metadata_url
        raise ProtocolError.new("challenge carries no resource_metadata parameter", code: "invalid_metadata")
      end

      document = Loopback.fetch_resource_metadata(metadata_url, http_client, timeout)
      issuer = Array(document["authorization_servers"]).first
      issuer || raise(ProtocolError.new("resource metadata lists no authorization_servers", code: "invalid_metadata"))
    end

    # Challenge-driven entry to the login flow: resolve the issuer from a
    # WWW-Authenticate challenge, then run authenticate against it.
    #
    # @param www_authenticate [String] the WWW-Authenticate header value
    # @param options [Hash] forwarded to authenticate
    # @return [TokenResponse]
    def self.authenticate_from_challenge(www_authenticate, http_client: HTTP::NetHTTPClient.new, **options)
      issuer = resolve_issuer_from_challenge(www_authenticate, http_client: http_client,
                                                               timeout: options[:timeout])
      authenticate(issuer: issuer, http_client: http_client, **options)
    end

    # Internals of the loopback flow. Not public API.
    module Loopback
      SUCCESS_PAGE = "<html><body><p>Authentication complete. You can close this window.</p></body></html>"

      module_function

      def fetch_resource_metadata(url, http_client, timeout)
        response = http_client.get(url, headers: { "Accept" => "application/json" }, timeout: timeout)
        unless response.success?
          raise HTTPError.new("resource metadata fetch returned HTTP #{response.status}",
                              status: response.status, body: response.body)
        end

        JSON.parse(response.body)
      rescue JSON::ParserError
        raise ProtocolError.new("resource metadata is not valid JSON", code: "invalid_metadata")
      end

      # Open the system browser without a shell.
      def open_browser(url)
        command = case RUBY_PLATFORM
                  when /darwin/ then ["open", url]
                  when /mswin|mingw/ then ["cmd", "/c", "start", "", url]
                  else ["xdg-open", url]
                  end
        Process.spawn(*command, %i[out err] => File::NULL)
      end

      # A single-shot loopback HTTP server receiving the OAuth redirect.
      class CallbackServer
        PATH = "/callback"

        # @return [String] the redirect URI registered for this flow
        attr_reader :redirect_uri

        def self.open(port:)
          server = new(port: port)
          begin
            yield server
          ensure
            server.close
          end
        end

        def initialize(port:)
          @server = TCPServer.new("127.0.0.1", port)
          @redirect_uri = "http://127.0.0.1:#{@server.addr[1]}#{PATH}"
        end

        def close
          @server.close unless @server.closed?
        end

        # Wait for the redirect, validate its state, and return the code.
        #
        # @raise [InteractionTimeoutError] no redirect within the timeout
        # @raise [ProtocolError] state mismatch (code state_mismatch)
        # @raise [OAuthError] the redirect carried an OAuth error
        def wait_for_code(state:, timeout:)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          loop do
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            raise InteractionTimeoutError, "no redirect received within #{timeout}s" if remaining <= 0
            next unless @server.wait_readable(remaining)

            params = accept_redirect
            next unless params

            return validate(params, state)
          end
        end

        private

        def accept_redirect
          client = @server.accept
          request_line = client.gets.to_s
          drain_headers(client)
          client.write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" \
                       "Content-Length: #{SUCCESS_PAGE.bytesize}\r\nConnection: close\r\n\r\n#{SUCCESS_PAGE}")
          client.close
          parse_target(request_line)
        end

        def drain_headers(client)
          loop do
            line = client.gets
            break if line.nil? || line.strip.empty?
          end
        end

        def parse_target(request_line)
          target = request_line.split[1].to_s
          uri = URI("http://127.0.0.1#{target}")
          return nil unless uri.path == PATH

          URI.decode_www_form(uri.query.to_s).to_h
        end

        def validate(params, state)
          if params["error"]
            raise OAuthError.new("authorization was denied: #{params["error"]}",
                                 error: params["error"], error_description: params["error_description"],
                                 status: 400)
          end
          unless params["state"] == state
            raise ProtocolError.new("redirect state does not match the authorization request",
                                    code: "state_mismatch")
          end

          params["code"] || raise(ProtocolError.new("redirect carries no code", code: "invalid_response"))
        end
      end
    end
  end
end
