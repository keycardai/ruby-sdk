# frozen_string_literal: true

# Helpers for tests that run callers on several threads and need them all
# blocked at a known point before the test continues.

# A thread whose exception the test reads with `outcome`, so Ruby does not
# also print it.
def quiet_thread(&block)
  Thread.new do
    Thread.current.report_on_exception = false
    block.call
  end
end

# Waits until the block returns true. Fails after 5 seconds, so a broken
# fetch fails the test instead of hanging the suite.
def wait_for(description)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
  until yield
    raise "timed out waiting for #{description}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

    Thread.pass
  end
end

# Waits until every thread is blocked: in Queue#pop, ConditionVariable#wait
# or Mutex#lock.
def wait_until_blocked(threads)
  wait_for("threads to block") { threads.all? { |thread| thread.status == "sleep" } }
end

# Starts one caller and waits until it blocks in its fetch, then starts
# `waiters` more callers and waits until they block behind it.
# @return [Array(Thread, Array<Thread>)] the first caller and the others
def start_shared_callers(waiters: 3, &call)
  first = quiet_thread(&call)
  wait_until_blocked([first])
  others = Array.new(waiters) { quiet_thread(&call) }
  wait_until_blocked([first, *others])
  [first, others]
end

# The thread's return value, or the exception it raised. Fails if the
# thread has not finished within 5 seconds.
def outcome(thread)
  wait_for("the thread to finish") { !thread.alive? }
  begin
    thread.value
  rescue Exception => e # rubocop:disable Lint/RescueException
    e
  end
end
