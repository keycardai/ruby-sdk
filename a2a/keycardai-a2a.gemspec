# frozen_string_literal: true

require_relative "lib/keycardai/a2a/version"

Gem::Specification.new do |spec|
  spec.name = "keycardai-a2a"
  spec.version = Keycardai::A2A::VERSION
  spec.authors = ["Keycard"]
  spec.email = ["support@keycard.ai"]
  spec.summary = "Agent-to-agent delegation with Keycard"
  spec.description = "The A2A delegation contract: agent card discovery, per-hop RFC 8693 " \
                     "token exchange carrying the user's identity, and JSON-RPC invocation. " \
                     "Framework glue for hosting agents is out of scope."
  spec.homepage = "https://github.com/keycardai/ruby-sdk"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"

  spec.metadata["rubygems_mfa_required"] = "true"
  spec.metadata["source_code_uri"] = "https://github.com/keycardai/ruby-sdk/tree/main/a2a"

  spec.files = Dir["lib/**/*.rb", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]

  spec.add_dependency "keycardai-oauth", ">= 0.1.0.pre"
end
