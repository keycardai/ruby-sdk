# frozen_string_literal: true

require "json"

# Test transport implementing the pluggable HTTP surface (see the oauth gem's
# spec support; duplicated so each gem's suite stands alone).
class FakeHTTPClient
  Call = Struct.new(:verb, :url, :params, :headers, keyword_init: true)

  attr_reader :calls

  def initialize(&handler)
    @handler = handler
    @calls = []
  end

  def get(url, headers: {}, timeout: nil)
    @calls << Call.new(verb: :get, url: url, params: nil, headers: headers)
    @handler.call(url, nil)
  end

  def post_form(url, params, headers: {}, timeout: nil)
    @calls << Call.new(verb: :post, url: url, params: params, headers: headers)
    @handler.call(url, params)
  end

  def post_json(url, payload, headers: {}, timeout: nil)
    @calls << Call.new(verb: :post_json, url: url, params: payload, headers: headers)
    @handler.call(url, payload)
  end

  def request_count(url)
    @calls.count { |call| call.url == url }
  end
end

def http_json(payload, status: 200)
  Keycardai::OAuth::HTTP::Response.new(status: status, headers: {}, body: JSON.dump(payload))
end
