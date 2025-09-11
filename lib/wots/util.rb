module WOTS
  module Util

    # Check whether +data+ is hex string or not.
    # @param [String] data
    # @return [Boolean]
    # @raise [ArgumentError]
    def hex_string?(data)
      raise ArgumentError, 'data must be string' unless data.is_a?(String)
      data.match?(/\A[0-9a-fA-F]+\z/)
    end

    # Convert hex string +data+ to binary.
    # @param [String] data
    # @return [String]
    # @raise [ArgumentError]
    def hex_to_bin(data)
      raise ArgumentError, 'data must be string' unless data.is_a?(String)
      hex_string?(data) ? [data].pack('H*') : data
    end

    # Convert binary string +data+ to hex string.
    # @param [String] data
    # @return [String]
    # @raise [ArgumentError]
    def bin_to_hex(data)
      raise ArgumentError, 'data must be string' unless data.is_a?(String)
      hex_string?(data) ? data : data.unpack1('H*')
    end

  end
end