# frozen_string_literal: true

require "uri"

module Keycardai
  module OAuth
    # A validated resource identifier: either an absolute HTTP(S) URL (with host,
    # no userinfo, no fragment) or an RFC 8141 URN. Preserves the raw string
    # verbatim for audience matching and RFC 9728 metadata documents.
    class ResourceIdentifier
      PROTECTED_RESOURCE_PREFIX = "/.well-known/oauth-protected-resource"
      URN_PATTERN = /\Aurn:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,30}[a-zA-Z0-9])?:\S+\z/i
      USERINFO_PATTERN = %r{\Ahttps?://[^/?#]*@}i

      attr_reader :raw, :origin, :metadata_path, :metadata_url, :query, :target

      def self.parse(value)
        unless value.is_a?(String) && !value.empty?
          raise ConfigurationError, "resource_identifier must be a non-empty HTTP(S) URL or URN"
        end
        return new(raw: value, kind: :urn) if value.match?(URN_PATTERN)

        parse_http(value)
      end

      def self.parse_http(value)
        uri = URI.parse(value)
        validate_http_uri!(uri, value)
        origin = format_origin(uri)
        path_suffix = empty_or_root_path?(uri.path) ? "" : uri.path
        metadata_path = "#{PROTECTED_RESOURCE_PREFIX}#{path_suffix}"
        query_suffix = uri.query ? "?#{uri.query}" : ""
        target_path = uri.path.nil? || uri.path.empty? ? "/" : uri.path
        new(raw: value, kind: :http, origin: origin, metadata_path: metadata_path,
            metadata_url: "#{origin}#{metadata_path}#{query_suffix}",
            query: uri.query, target: "#{target_path}#{query_suffix}")
      rescue URI::InvalidURIError => e
        raise ConfigurationError, "invalid resource_identifier #{value.inspect}: #{e.message}"
      end

      def self.validate_http_uri!(uri, value)
        raise ConfigurationError, "resource_identifier must be an absolute HTTP(S) URL with a host or a URN" unless
          http_with_host?(uri)
        if uri.userinfo || value.match?(USERINFO_PATTERN)
          raise ConfigurationError, "resource_identifier must not contain userinfo"
        end
        return unless uri.fragment || value.include?("#")

        raise ConfigurationError, "resource_identifier must not contain a fragment"
      end

      def self.http_with_host?(uri)
        uri.is_a?(URI::HTTP) && !uri.host.to_s.empty?
      end
      private_class_method :parse_http, :validate_http_uri!, :http_with_host?

      def self.format_origin(uri)
        port = uri.port && uri.port != uri.default_port ? ":#{uri.port}" : ""
        "#{uri.scheme}://#{uri.host}#{port}"
      end
      private_class_method :format_origin

      def self.empty_or_root_path?(path)
        path.nil? || path.empty? || path == "/"
      end
      private_class_method :empty_or_root_path?

      def initialize(raw:, kind:, origin: nil, metadata_path: nil, metadata_url: nil, query: nil, target: nil)
        @raw = raw
        @kind = kind
        @origin = origin
        @metadata_path = metadata_path
        @metadata_url = metadata_url
        @query = query
        @target = target
        freeze
      end

      def http?
        @kind == :http
      end

      def urn?
        @kind == :urn
      end

      def matches_request?(path:, query: "")
        return false unless http?

        request_target = query.empty? ? path : "#{path}?#{query}"
        @target == request_target
      end

      def matches_metadata_request?(path:, query: "")
        http? && @metadata_path == path && @query.to_s == query
      end

      def ==(other)
        other.is_a?(self.class) && @raw == other.raw
      end
      alias eql? ==

      def hash
        @raw.hash
      end
    end

    # Internal option validation and mode resolution for ResourceBinding.
    module ResourceBindingResolver
      ZONE_ID_PATTERN = /\A[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z/

      module_function

      def derive_zone_issuer(base_issuer, zone_id)
        validate_zone_id!(zone_id)
        uri = parse_base_issuer(base_issuer)
        port = uri.port && uri.port != uri.default_port ? ":#{uri.port}" : ""
        "#{uri.scheme}://#{zone_id}.#{uri.host}#{port}"
      end

      def validate_zone_id!(zone_id)
        return if zone_id.is_a?(String) && zone_id.match?(ZONE_ID_PATTERN)

        raise ConfigurationError, "invalid zone ID #{zone_id.inspect}"
      end

      def parse_base_issuer(base_issuer)
        if base_issuer.nil? || base_issuer.empty?
          raise ConfigurationError, "base issuer is required for zone issuer derivation"
        end

        uri = URI.parse(base_issuer)
        unless uri.is_a?(URI::HTTP) && uri.host && !uri.host.empty?
          raise ConfigurationError, "issuer must be an absolute HTTP(S) URL with a host"
        end

        uri
      rescue URI::InvalidURIError => e
        raise ConfigurationError, "invalid issuer #{base_issuer.inspect}: #{e.message}"
      end

      def check_conflicts!(resource_id, zone_map, multi_resource, allow_any, audiences)
        check_flag_conflicts!(resource_id, zone_map, multi_resource, allow_any)
        check_audience_conflicts!(resource_id, zone_map, multi_resource, allow_any, audiences)
      end

      def check_flag_conflicts!(resource_id, zone_map, multi_resource, allow_any)
        if multi_resource && allow_any
          raise ConfigurationError, "multi_resource and allow_any_audience cannot both be true"
        end

        check_identifier_conflicts!(resource_id, zone_map, multi_resource, allow_any)
      end

      def check_identifier_conflicts!(resource_id, zone_map, multi_resource, allow_any)
        unless resource_id.nil?
          unless zone_map.nil?
            raise ConfigurationError,
                  "resource_identifier and resource_identifiers_by_zone cannot both be set"
          end
          if multi_resource || allow_any
            raise ConfigurationError, "resource_identifier cannot be combined with multi_resource or allow_any_audience"
          end
        end
        return unless !zone_map.nil? && allow_any

        raise ConfigurationError, "resource_identifiers_by_zone cannot be combined with allow_any_audience"
      end

      def check_audience_conflicts!(resource_id, zone_map, multi_resource, allow_any, audiences)
        return if audiences.nil?
        raise ConfigurationError, "audiences cannot be combined with resource_identifier" unless resource_id.nil?
        raise ConfigurationError, "audiences cannot be combined with allow_any_audience" if allow_any
        return unless !zone_map.nil? && !multi_resource

        raise ConfigurationError,
              "audiences cannot be combined with resource_identifiers_by_zone without multi_resource"
      end

      def parse_zone_map(zone_map)
        unless zone_map.is_a?(Hash) && !zone_map.empty?
          raise ConfigurationError, "resource_identifiers_by_zone must be a non-empty Hash"
        end

        zone_map.each_with_object({}) do |(zone_id, identifier), parsed|
          validate_zone_id!(zone_id)
          parsed[zone_id] = ResourceIdentifier.parse(identifier)
        end.freeze
      end

      def valid_audience_list?(audiences)
        audiences.is_a?(Array) && !audiences.empty? &&
          audiences.all? { |item| item.is_a?(String) && !item.empty? }
      end

      def emit_legacy_warning(component, audiences)
        if audiences.is_a?(Hash)
          warn "#{component} is using a deprecated legacy audience map; pass resource_identifiers_by_zone: " \
               "(or resource_identifier: for single-resource mode) instead.", uplevel: 2
        else
          warn "#{component} is using deprecated legacy resource configuration; pass resource_identifier:, " \
               "resource_identifiers_by_zone:, multi_resource: true, or allow_any_audience: true.", uplevel: 2
        end
      end
    end

    # Validated resource-binding mode shared by TokenVerifier, AuthProvider,
    # RequireBearerAuth, and MetadataApp. Selects exactly one of:
    # :single_resource, :per_zone, :multi_resource, :shared_discovery,
    # :allow_any_audience, or :legacy (with a one-time deprecation warning).
    class ResourceBinding
      attr_reader :mode, :identifier, :zone_identifiers, :audiences

      def self.derive_zone_issuer(base_issuer, zone_id)
        ResourceBindingResolver.derive_zone_issuer(base_issuer, zone_id)
      end

      def self.resolve(resource_identifier: nil, resource_identifiers_by_zone: nil,
                       multi_resource: false, allow_any_audience: false, audiences: nil,
                       accept_audiences: true, require_issuer_for_zones: false, base_issuer: nil,
                       warn_legacy: true, component: "Keycardai")
        ResourceBindingResolver.check_conflicts!(
          resource_identifier, resource_identifiers_by_zone, multi_resource, allow_any_audience, audiences
        )
        return build_single(resource_identifier) unless resource_identifier.nil?
        unless resource_identifiers_by_zone.nil?
          return build_zone_binding(resource_identifiers_by_zone, multi_resource: multi_resource,
                                                                  audiences: audiences,
                                                                  accept_audiences: accept_audiences,
                                                                  require_issuer: require_issuer_for_zones,
                                                                  base_issuer: base_issuer)
        end
        return build_multi_resource(audiences, accept_audiences: accept_audiences) if multi_resource
        return new(mode: :allow_any_audience) if allow_any_audience

        build_legacy(audiences, accept_audiences: accept_audiences, warn_legacy: warn_legacy, component: component)
      end

      def self.build_single(resource_id)
        parsed = ResourceIdentifier.parse(resource_id)
        new(mode: :single_resource, identifier: parsed, audiences: [parsed.raw].freeze)
      end

      def self.build_zone_binding(zone_map, multi_resource:, audiences:, accept_audiences:,
                                  require_issuer:, base_issuer:)
        parsed_map = ResourceBindingResolver.parse_zone_map(zone_map)
        if require_issuer && parsed_map.values.any?(&:http?) && (base_issuer.nil? || base_issuer.empty?)
          raise ConfigurationError, "issuer is required when resource_identifiers_by_zone contains HTTP(S) identifiers"
        end
        if multi_resource
          return build_shared_discovery(parsed_map, audiences: audiences, accept_audiences: accept_audiences)
        end

        new(mode: :per_zone, zone_identifiers: parsed_map)
      end

      def self.build_shared_discovery(parsed_map, audiences:, accept_audiences:)
        values = parsed_map.values.uniq
        unless values.length == 1 && values.first.http?
          raise ConfigurationError,
                "shared discovery requires every zone in resource_identifiers_by_zone to share one HTTP(S) URL"
        end
        shared = values.first
        if accept_audiences && !(audiences.is_a?(Array) && audiences == [shared.raw])
          raise ConfigurationError,
                "shared discovery requires audiences to be a singleton list containing the shared identifier"
        end
        new(mode: :shared_discovery, identifier: shared, zone_identifiers: parsed_map, audiences: [shared.raw].freeze)
      end

      def self.build_multi_resource(audiences, accept_audiences:)
        if accept_audiences && !ResourceBindingResolver.valid_audience_list?(audiences)
          raise ConfigurationError, "multi_resource requires a non-empty audiences array"
        end

        new(mode: :multi_resource, audiences: accept_audiences ? audiences.dup.freeze : nil)
      end

      def self.build_legacy(audiences, accept_audiences:, warn_legacy:, component:)
        if accept_audiences && audiences.is_a?(Array) && audiences.empty?
          raise ConfigurationError, "audiences must not be empty"
        end

        ResourceBindingResolver.emit_legacy_warning(component, audiences) if warn_legacy
        new(mode: :legacy, audiences: audiences)
      end
      private_class_method :build_single, :build_zone_binding, :build_shared_discovery,
                           :build_multi_resource, :build_legacy

      def initialize(mode:, identifier: nil, zone_identifiers: nil, audiences: nil)
        @mode = mode
        @identifier = identifier
        @zone_identifiers = zone_identifiers
        @audiences = audiences
        freeze
      end

      def explicit?
        @mode != :legacy
      end

      def legacy?
        @mode == :legacy
      end

      def single_resource?
        @mode == :single_resource
      end

      def per_zone?
        @mode == :per_zone
      end

      def multi_resource?
        @mode == :multi_resource
      end

      def shared_discovery?
        @mode == :shared_discovery
      end

      def allow_any_audience?
        @mode == :allow_any_audience
      end

      def zone_mode?
        per_zone? || shared_discovery?
      end

      def publishes_metadata?
        case @mode
        when :single_resource then @identifier.http?
        when :shared_discovery, :legacy then true
        when :per_zone then @zone_identifiers.values.any?(&:http?)
        else false
        end
      end

      def zone_issuers(base_issuer)
        return {} unless @zone_identifiers

        @zone_identifiers.keys.to_h { |zone_id| [zone_id, self.class.derive_zone_issuer(base_issuer, zone_id)] }
      end

      def compatible_with?(other)
        return false unless other.is_a?(self.class)

        @mode == other.mode &&
          @identifier == other.identifier &&
          @zone_identifiers == other.zone_identifiers &&
          @audiences == other.audiences
      end
    end
  end
end
