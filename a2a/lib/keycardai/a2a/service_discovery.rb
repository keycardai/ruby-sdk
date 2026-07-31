# frozen_string_literal: true

require "json"

module Keycardai
  module A2A
    # Resolves an agent's base URL to its agent card, fetched from
    # /.well-known/agent-card.json and cached (default 15 minutes,
    # refreshable). A card must carry a name to be valid.
    class ServiceDiscovery
      DEFAULT_CACHE_TTL = 900

      # @param http_client [#get] pluggable transport
      # @param cache_ttl [Numeric] card cache lifetime in seconds
      # @param timeout [Numeric, nil] fetch timeout
      # @param clock [#call] returns the current Time; override in tests
      def initialize(http_client: OAuth::HTTP::NetHTTPClient.new, cache_ttl: DEFAULT_CACHE_TTL,
                     timeout: nil, clock: -> { Time.now })
        @http_client = http_client
        @cache_ttl = cache_ttl
        @timeout = timeout
        @clock = clock
        @cards = {}
        @mutex = Mutex.new
      end

      # The agent card for a base URL, served from cache while fresh.
      #
      # @param base_url [String] the agent's base URL
      # @return [Hash] the agent card
      # @raise [DiscoveryError]
      def get_card(base_url)
        key = base_url.chomp("/")
        cached = @mutex.synchronize do
          entry = @cards[key]
          entry[:card] if entry && @clock.call - entry[:fetched_at] <= @cache_ttl
        end
        return cached if cached

        refresh(key)
      end

      # Fetch a fresh card, replacing any cached one.
      #
      # @param base_url [String]
      # @return [Hash]
      # @raise [DiscoveryError]
      def refresh(base_url)
        key = base_url.chomp("/")
        card = fetch_card(key)
        @mutex.synchronize { @cards[key] = { card: card, fetched_at: @clock.call } }
        card
      end

      # Drop all cached cards.
      #
      # @return [void]
      def clear_cache
        @mutex.synchronize { @cards.clear }
      end

      private

      def fetch_card(base_url)
        url = "#{base_url}#{AGENT_CARD_PATH}"
        response = begin
          @http_client.get(url, headers: { "Accept" => "application/json" }, timeout: @timeout)
        rescue OAuth::NetworkError => e
          raise DiscoveryError, "agent card fetch from #{url} failed: #{e.message}"
        end
        raise DiscoveryError, "agent card fetch from #{url} returned HTTP #{response.status}" unless response.success?

        parse_card(url, response.body)
      end

      def parse_card(url, body)
        card = begin
          JSON.parse(body)
        rescue JSON::ParserError
          raise DiscoveryError, "agent card from #{url} is not valid JSON"
        end
        unless card.is_a?(Hash) && card["name"].is_a?(String) && !card["name"].empty?
          raise DiscoveryError, "agent card from #{url} is missing the required name"
        end

        card
      end
    end
  end
end
