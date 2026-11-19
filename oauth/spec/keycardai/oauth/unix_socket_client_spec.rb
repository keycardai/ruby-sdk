# frozen_string_literal: true

# UnixSocketClient's HTTP/1.1 framing, against a peer on a real Unix socket
# that writes raw response bytes. The peer is not authenticated, so every cap
# and every refusal here is a defence against what it may send.
RSpec.describe Keycardai::OAuth::HTTP::UnixSocketClient do
  let(:url) { "http://localhost/svc/Method?x=1" }

  # Serves one connection: records the raw request, then writes +response+.
  def serve_raw(response)
    FakeAgent.short_tmpdir do |dir|
      path = File.join(dir, "peer.sock")
      server = UNIXServer.new(path)
      request = +""
      thread = Thread.new { answer(server.accept, request, response) }
      yield described_class.new(path), request
    ensure
      thread&.kill
      thread&.join
      server&.close
    end
  end

  def answer(client, request, response)
    request << client.readpartial(64 * 1024) until request.include?("\r\n\r\n")
    length = request[/^Content-Length: (\d+)/i, 1].to_i
    request << client.readpartial(64 * 1024) while request.split("\r\n\r\n", 2)[1].bytesize < length
    client.write(response)
  ensure
    client.close
  end

  def response_from(raw)
    serve_raw(raw) { |client, _request| return client.post_json(url, { "a" => "é" }) }
  end

  def expect_refused(raw, message)
    expect { response_from(raw) }.to raise_error(Keycardai::OAuth::NetworkError, message)
  end

  def ok(headers, body)
    "HTTP/1.1 200 OK\r\n#{headers}\r\n#{body}"
  end

  describe "request" do
    it "sends the path and query, Host, the byte length of a multibyte body, and Connection: close" do
      serve_raw(ok("Content-Length: 2\r\n", "{}")) do |client, request|
        client.post_json(url, { "a" => "é" })

        head, body = request.split("\r\n\r\n", 2)
        expect(head.lines.first).to eq("POST /svc/Method?x=1 HTTP/1.1\r\n")
        # '{"a":"é"}' is 9 characters and 10 bytes.
        expect(head).to include("Host: localhost", "Connection: close", "Content-Type: application/json",
                                "Content-Length: 10")
        expect(body).to eq('{"a":"é"}'.b)
      end
    end

    [["a name", "X-Bad\r\nInjected", "v"], ["a value", "X-Bad", "v\r\nInjected: 1"],
     ["a NUL", "X-Bad", "v\0"], ["a bare LF", "X-Bad", "v\nx"]].each do |label, name, value|
      it "refuses a header with a line break or NUL in #{label}" do
        client = described_class.new("/unused.sock")
        expect(UNIXSocket).not_to receive(:new)

        expect { client.get(url, headers: { name => value }) }.to raise_error(ArgumentError, /line break or NUL/)
      end
    end
  end

  describe "response" do
    it "reads a Content-Length body and forces it to UTF-8" do
      body = '{"k":"é"}'.b
      response = response_from(ok("Content-Length: #{body.bytesize}\r\nX-Multi: a\r\nx-multi: b\r\n", body))

      expect(response.status).to eq(200)
      expect(response.headers["x-multi"]).to eq(%w[a b])
      expect(response.body).to eq('{"k":"é"}')
      expect(response.body.encoding).to eq(Encoding::UTF_8)
    end

    it "reads an unframed body until the peer closes" do
      expect(response_from(ok("", "unframed body")).body).to eq("unframed body")
    end

    it "decodes chunks with extensions and stops at the last chunk without reading trailers" do
      body = "3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nTrailer: x\r\n\r\n"

      expect(response_from(ok("Transfer-Encoding: chunked\r\n", body)).body).to eq("abcde")
    end

    it "refuses a malformed status line, including a four-digit status" do
      expect_refused("HTTP/1.1 2000 OK\r\n\r\n", /malformed status line/)
      expect_refused("HTTX/1.1 200 OK\r\n\r\n", /malformed status line/)
    end

    {
      "no colon" => "NoColon\r\n",
      "whitespace before the colon" => "Name : v\r\n",
      "an obs-fold continuation" => "A: b\r\n c: d\r\n",
      "an empty name" => ": v\r\n"
    }.each do |label, header|
      it "refuses a header line with #{label}" do
        expect_refused(ok(header, ""), /malformed header/)
      end
    end

    it "refuses more than MAX_HEADER_COUNT headers" do
      headers = Array.new(described_class::MAX_HEADER_COUNT + 1) { |i| "h#{i}: v\r\n" }.join

      expect_refused(ok(headers, ""), /more than #{described_class::MAX_HEADER_COUNT} headers/)
    end

    it "refuses more than MAX_HEADER_BYTES of headers" do
      value = "v" * 1000
      headers = Array.new((described_class::MAX_HEADER_BYTES / 1000) + 1) { |i| "h#{i}: #{value}\r\n" }.join

      expect_refused(ok(headers, ""), /bytes of them/)
    end

    # The peer writes the line and its CRLF at once, so the CRLF is already
    # buffered when the length is checked.
    it "refuses a line over MAX_LINE_BYTES and accepts one just under it" do
      over = "X-Long: #{"x" * described_class::MAX_LINE_BYTES}\r\n"
      under = "X-Ok: #{"x" * (described_class::MAX_LINE_BYTES - 10)}\r\nContent-Length: 0\r\n"

      expect_refused(ok(over, ""), /exceeds #{described_class::MAX_LINE_BYTES} bytes/)
      expect { response_from(ok(under, "")) }.not_to raise_error
    end

    describe "body over MAX_BODY_BYTES" do
      let(:over) { described_class::MAX_BODY_BYTES + 1 }

      it "is refused when Content-Length declares it" do
        expect_refused(ok("Content-Length: #{over}\r\n", ""), /body over/)
      end

      it "is refused when an unframed body runs past it" do
        expect_refused(ok("", "x" * over), /body over/)
      end

      it "is refused when chunks add up past it" do
        chunk = "x" * described_class::MAX_BODY_BYTES
        body = "#{chunk.bytesize.to_s(16)}\r\n#{chunk}\r\n1\r\nx\r\n0\r\n\r\n"

        expect_refused(ok("Transfer-Encoding: chunked\r\n", body), /body over/)
      end

      it "is accepted at exactly the cap" do
        exact = "x" * described_class::MAX_BODY_BYTES

        expect(response_from(ok("Content-Length: #{exact.bytesize}\r\n", exact)).body.bytesize).to eq(exact.bytesize)
      end
    end

    {
      "a signed Content-Length" => ["Content-Length: +2\r\n", "{}"],
      "an underscored Content-Length" => ["Content-Length: 1_0\r\n", "0123456789"],
      "Content-Length values that disagree" => ["Content-Length: 2\r\nContent-Length: 3\r\n", "{}"],
      "a listed Content-Length that disagrees" => ["Content-Length: 2, 3\r\n", "{}"],
      "a 0x chunk size" => ["Transfer-Encoding: chunked\r\n", "0x2\r\n{}\r\n0\r\n\r\n"],
      "a signed chunk size" => ["Transfer-Encoding: chunked\r\n", "+2\r\n{}\r\n0\r\n\r\n"],
      "chunk data not followed by CRLF" => ["Transfer-Encoding: chunked\r\n", "2\r\n{}junk\r\n0\r\n\r\n"],
      "a final coding other than chunked" => ["Transfer-Encoding: chunked, gzip\r\n", "2\r\n{}\r\n0\r\n\r\n"],
      "a coding that merely contains chunked" => ["Transfer-Encoding: notchunked\r\n", "{}"]
    }.each do |label, (headers, body)|
      it "refuses #{label} as malformed body framing" do
        expect_refused(ok(headers, body), /malformed body framing/)
      end
    end

    it "accepts a repeated Content-Length that agrees" do
      expect(response_from(ok("Content-Length: 2\r\nContent-Length: 2\r\n", "{}")).body).to eq("{}")
    end

    it "wraps a peer closing mid-body as a NetworkError" do
      expect_refused(ok("Content-Length: 10\r\n", "short"), /connection closed before the response completed/)
    end

    it "wraps a socket path longer than sun_path as a NetworkError naming the path" do
      path = "/#{"a" * 200}/peer.sock"

      expect { described_class.new(path).get(url) }
        .to raise_error(Keycardai::OAuth::NetworkError, /cannot dial #{Regexp.escape(path)}/)
    end
  end
end
