# frozen_string_literal: true

# Test clock for the device authorization grant: +now+ is fixed until a sleep
# advances it. Each sleep is appended to +events+ as [:wait, seconds], so a
# test can share +events+ with its HTTP handler and assert the order of waits
# and requests.
class FakeClock
  attr_reader :now, :events

  def initialize(now: Time.utc(2026, 1, 1), events: [])
    @now = now
    @events = events
  end

  def sleep(seconds)
    @events << [:wait, seconds]
    @now += seconds
  end
end
