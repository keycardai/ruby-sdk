# frozen_string_literal: true

require "json"

# Build a minimal Rack env for driving middleware directly.
def rack_env(path: "/mcp", method: "GET", scheme: "https", host: "tool.example.com", headers: {})
  env = { "REQUEST_METHOD" => method, "PATH_INFO" => path, "rack.url_scheme" => scheme, "HTTP_HOST" => host }
  headers.each { |name, value| env["HTTP_#{name.upcase.tr("-", "_")}"] = value }
  env
end

def parse_body(response)
  JSON.parse(response[2].join)
end

# A downstream Rack app recording whether and with what env it ran.
class ProbeApp
  attr_reader :seen_env

  def call(env)
    @seen_env = env
    [200, { "content-type" => "text/plain" }, ["ok"]]
  end

  def ran?
    !@seen_env.nil?
  end
end
