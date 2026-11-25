# frozen_string_literal: true

module Keycardai
  module OAuth
    # Makes to_s and pp print the same text as inspect. A type that holds a
    # secret defines inspect to leave the secret out, then includes this so
    # every printed form leaves it out (keycard-sdk-spec base.md, Printed
    # forms). #to_h and the readers still return the values. Not public API.
    module PrintedForm
      # @return [String] the same text as inspect
      def to_s
        inspect
      end

      # Used by pp.
      def pretty_print(printer)
        printer.text(inspect)
      end

      # The class name of an object the SDK does not define, such as a
      # caller's credential, which may print its own secrets.
      #
      # @return [String] the class name, or "nil"
      def self.type_of(value)
        value.nil? ? "nil" : value.class.name || value.class.to_s
      end
    end
  end
end
