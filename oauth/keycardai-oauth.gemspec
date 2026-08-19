# frozen_string_literal: true

require_relative "lib/keycardai/oauth/version"

Gem::Specification.new do |spec|
  spec.name = "keycardai-oauth"
  spec.version = Keycardai::OAuth::VERSION
  spec.authors = ["Keycard"]
  spec.email = ["support@keycard.ai"]
  spec.summary = "OAuth 2.0 primitives for the Keycard platform"
  spec.description = "Token exchange (RFC 8693), client credentials, authorization code + PKCE, " \
                     "dynamic client registration (RFC 7591), authorization server discovery " \
                     "(RFC 8414), JWT/JWKS verification, application credentials, and the " \
                     "AccessContext delegated-access container."
  spec.homepage = "https://github.com/keycardai/ruby-sdk"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"

  spec.metadata["rubygems_mfa_required"] = "true"
  spec.metadata["source_code_uri"] = "https://github.com/keycardai/ruby-sdk/tree/main/oauth"

  spec.files = Dir["lib/**/*.rb", "CHANGELOG.md", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]

  spec.add_dependency "jwt", ">= 2.7"
end
