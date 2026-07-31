# frozen_string_literal: true

# Test transport implementing the pluggable HTTP surface. Routes each GET
# through the handler given at construction and records every requested URL.
class FakeHTTPClient
  attr_reader :requests

  def initialize(&handler)
    @handler = handler
    @requests = []
    @mutex = Mutex.new
  end

  def get(url, headers: {}, timeout: nil)
    @mutex.synchronize { @requests << url }
    @handler.call(url)
  end

  def request_count(url)
    @mutex.synchronize { @requests.count(url) }
  end
end

def json_response(payload, status: 200)
  Keycardai::OAuth::HTTP::Response.new(status: status, headers: {}, body: JSON.dump(payload))
end
