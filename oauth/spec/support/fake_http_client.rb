# frozen_string_literal: true

# Test transport implementing the pluggable HTTP surface. Routes every request
# through the handler given at construction (called with url and form params,
# nil for GETs) and records each call. `requests` keeps the URL list for
# order/count assertions; `calls` carries the full method/url/params/headers
# records.
class FakeHTTPClient
  Call = Struct.new(:verb, :url, :params, :headers, keyword_init: true)

  attr_reader :requests, :calls

  def initialize(&handler)
    @handler = handler
    @requests = []
    @calls = []
    @mutex = Mutex.new
  end

  def get(url, headers: {}, timeout: nil)
    record(:get, url, nil, headers)
    @handler.call(url, nil)
  end

  def post_form(url, params, headers: {}, timeout: nil)
    record(:post, url, params, headers)
    @handler.call(url, params)
  end

  def request_count(url)
    @mutex.synchronize { @requests.count(url) }
  end

  private

  def record(verb, url, params, headers)
    @mutex.synchronize do
      @requests << url
      @calls << Call.new(verb: verb, url: url, params: params, headers: headers)
    end
  end
end

def json_response(payload, status: 200)
  Keycardai::OAuth::HTTP::Response.new(status: status, headers: {}, body: JSON.dump(payload))
end
