# frozen_string_literal: true

module Keycardai
  module OAuth
    module HTTP
      # Net::HTTP can read multiple times before yielding a body chunk, for
      # example while parsing a header or the framing around a chunk.
      module DeadlineSocket
        attr_writer :deadline_session

        def read_nonblock(...)
          request_deadline&.remaining
          super
        end

        def write_nonblock(...)
          request_deadline&.remaining
          super
        end

        def wait_readable(timeout = nil)
          super(bounded_wait(timeout))
        end

        def wait_writable(timeout = nil)
          super(bounded_wait(timeout))
        end

        private

        def request_deadline
          @deadline_session.request_deadline
        end

        def bounded_wait(timeout)
          remaining = request_deadline&.remaining
          [timeout, remaining].compact.min
        end
      end
      private_constant :DeadlineSocket

      # Applies a fresh budget to connections and sockets on a reused session.
      module DeadlineSession
        attr_accessor :request_deadline

        def apply_deadline
          remaining = request_deadline.remaining
          self.open_timeout = self.read_timeout = self.write_timeout = remaining
        end

        private

        def connect
          apply_deadline
          super
          bound_socket(@socket.io)
        end

        def timeouted_connect(...)
          super.tap { |socket| bound_socket(socket) }
        end

        def ssl_socket_connect(socket, _timeout)
          super(socket, request_deadline.remaining)
        end

        def bound_socket(socket)
          [socket, socket.to_io].uniq.each do |io|
            io.extend(DeadlineSocket)
            io.deadline_session = self
          end
        end
      end
      private_constant :DeadlineSession
    end
  end
end
