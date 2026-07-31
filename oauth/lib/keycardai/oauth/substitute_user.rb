# frozen_string_literal: true

require "json"

module Keycardai
  # The substitute-user token builder for impersonation exchanges.
  module OAuth
    # Build the unsigned substitute-user JWT used as the subject token of an
    # impersonation exchange. The authorization server derives the acting
    # party from client authentication; this token only names the target user.
    #
    # Shape: header {"typ": "vnd.kc.su+jwt", "alg": "none"}, payload
    # {"sub": user_identifier}, encoded header.payload. with a trailing dot
    # and no signature.
    #
    # @param user_identifier [String] the target user (becomes sub)
    # @return [String]
    def self.build_substitute_user_token(user_identifier)
      if user_identifier.nil? || user_identifier.empty?
        raise ArgumentError, "user_identifier must be a non-empty string"
      end

      header = { "typ" => "vnd.kc.su+jwt", "alg" => "none" }
      payload = { "sub" => user_identifier }
      encode = ->(part) { [JSON.dump(part)].pack("m0").tr("+/", "-_").delete("=") }
      "#{encode.call(header)}.#{encode.call(payload)}."
    end
  end
end
