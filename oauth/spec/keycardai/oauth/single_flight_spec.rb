# frozen_string_literal: true

# Each test blocks the first caller's fetch on a queue so the other callers
# arrive while it runs. A queue also counts the fetches, since fetches can
# run on several threads.
RSpec.describe Keycardai::OAuth::SingleFlight do
  subject(:flights) { described_class.new }

  shared_value = Object.new
  shared_error = Keycardai::OAuth::NetworkError.new("connection refused")

  [
    { name: "a value", finish: -> { shared_value }, expected: shared_value },
    { name: "a Keycardai error", finish: -> { raise shared_error }, expected: shared_error }
  ].each do |c|
    it "gives every caller that joins a running fetch the same #{c[:name]}, from one fetch" do
      gate = Queue.new
      fetches = Queue.new
      first, others = start_shared_callers do
        flights.run(:zone) do
          fetches << :fetch
          gate.pop
          c[:finish].call
        end
      end
      gate << :go

      expect([first, *others].map { |thread| outcome(thread) }).to all(equal(c[:expected]))
      expect(fetches.size).to eq(1)
    end
  end

  [
    { name: "Thread#raise", interrupt: ->(thread) { thread.raise(Timeout::Error, "deadline") },
      first_outcome: Timeout::Error },
    { name: "Thread#kill", interrupt: lambda(&:kill), first_outcome: NilClass }
  ].each do |c|
    it "lets the waiting callers fetch again when #{c[:name]} interrupts the first caller" do
      gates = [Queue.new, Queue.new]
      fetches = Queue.new
      value = Object.new
      first, others = start_shared_callers do
        flights.run(:zone) do
          fetches << :fetch
          gates.fetch(fetches.size - 1).pop
          value
        end
      end

      c[:interrupt].call(first)
      expect(outcome(first)).to be_a(c[:first_outcome])
      wait_for("the second fetch") { fetches.size == 2 }
      wait_until_blocked(others)
      gates[1] << :go

      expect(others.map { |thread| outcome(thread) }).to all(equal(value))
      expect(fetches.size).to eq(2)
    end
  end

  it "keeps no outcome, so the next run after a failure fetches again" do
    fetches = 0
    failing = lambda do
      fetches += 1
      raise shared_error
    end

    expect { flights.run(:zone, &failing) }.to raise_error(shared_error)
    expect(flights.run(:zone) { fetches += 1 }).to eq(2)
  end

  it "runs fetches for different keys at the same time" do
    gate = Queue.new
    first = quiet_thread { flights.run(:zone_a) { gate.pop } }
    wait_until_blocked([first])

    expect(flights.run(:zone_b) { :b }).to eq(:b)
    gate << :a
    expect(outcome(first)).to eq(:a)
  end
end
