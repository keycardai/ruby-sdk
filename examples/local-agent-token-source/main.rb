# frozen_string_literal: true

# Call a third-party API with a token from the local Keycard agent, holding no
# application credential: no client secret, refresh token, or session.
#
# Keycard setup:
#
#   1. Install the Keycard CLI and sign in to a zone:
#        keycard auth signin --org <org-id> --zone <zone-id>
#   2. Register the resource you want to call in that zone, with a credential
#      provider that can issue tokens for it (for example, GitHub as
#      https://api.github.com).
#   3. Optionally, declare the Keycard application this script acts for by
#      setting APP_ID to that application's identifier (not its public id).
#
# Run it from this directory, either under `keycard run`, which hands the
# script its per-session socket in KEYCARD_SOCKET:
#
#   bundle install
#   RESOURCE=https://api.github.com RESOURCE_URL=https://api.github.com/user \
#     keycard run -- bundle exec ruby main.rb
#
# or against the long-running multi-zone daemon on its default socket, naming
# the org and zone:
#
#   keycard agent start
#   KEYCARD_ORG=<org-id> KEYCARD_ZONE=<zone-id> \
#   RESOURCE=https://api.github.com RESOURCE_URL=https://api.github.com/user \
#     bundle exec ruby main.rb
#
# The first request for a resource and scope set prompts you to approve it.
# Approve the prompt, and the agent answers later requests from its cache.

require "bundler/setup"
require "keycardai/oauth"

resource = ENV.fetch("RESOURCE") { abort "set RESOURCE to the resource indicator, e.g. https://api.github.com" }
resource_url = ENV.fetch("RESOURCE_URL") { abort "set RESOURCE_URL to a URL on that resource to GET" }
scopes = ENV.fetch("SCOPES", "").split

# With no socket: the source reads KEYCARD_SOCKET from the process
# environment, falling back to the daemon's default socket.
source = Keycardai::OAuth::AgentTokenSource.new(
  workload: "local-agent-token-source example",
  app_id: ENV.fetch("APP_ID", ""),
  org: ENV.fetch("KEYCARD_ORG", ""),
  zone: ENV.fetch("KEYCARD_ZONE", ""),
)

begin
  token = source.resource_token(resource: resource, scopes: scopes)
  puts "minted a token for #{resource}"
  puts "  expires in: #{token.expires_in.nil? ? "never" : "#{token.expires_in}s"}"
  puts "  granted scopes: #{token.scope ? token.scope.join(" ") : "not reported"}"

  transport = Keycardai::OAuth::ResourceTransport.new(source: source, resource: resource, scopes: scopes)
  response = transport.get(resource_url, headers: { "Accept" => "application/json" })
  puts "GET #{resource_url}: HTTP #{response.status}"
  puts response.body[0, 500]
rescue Keycardai::OAuth::AgentError => e
  if Keycardai::OAuth.declined?(e)
    abort "declined: #{e.message}"
  elsif Keycardai::OAuth.application_not_found?(e)
    abort "APP_ID names no application in the zone: #{e.message}"
  elsif Keycardai::OAuth.authorization_required?(e)
    abort "act first, then retry: #{e.message}"
  else
    abort "the agent refused (#{e.code}): #{e.message}"
  end
rescue Keycardai::OAuth::NetworkError, Keycardai::OAuth::ConfigurationError => e
  abort e.message
end
