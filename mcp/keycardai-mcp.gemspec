# frozen_string_literal: true

require_relative "lib/keycardai/mcp/version"

Gem::Specification.new do |spec|
  spec.name = "keycardai-mcp"
  spec.version = Keycardai::MCP::VERSION
  spec.authors = ["Keycard"]
  spec.email = ["support@keycard.ai"]
  spec.summary = "Keycard MCP server integration at the Rack seam"
  spec.description = "Rack bearer-token middleware (RFC 6750), OAuth protected-resource and " \
                     "authorization-server metadata endpoints (RFC 9728 / RFC 8414), and an " \
                     "AuthProvider for delegated token exchange in MCP servers. Wraps no MCP " \
                     "SDK; attaches to any Rack app, including servers built on the official " \
                     "mcp gem."
  spec.homepage = "https://github.com/keycardai/ruby-sdk"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"

  spec.metadata["rubygems_mfa_required"] = "true"
  spec.metadata["source_code_uri"] = "https://github.com/keycardai/ruby-sdk/tree/main/mcp"

  spec.files = Dir["lib/**/*.rb", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]

  spec.add_dependency "keycardai-oauth", ">= 0.1.0.pre"
  spec.add_dependency "rack", ">= 2.2"
end
