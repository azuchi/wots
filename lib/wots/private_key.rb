module WOTS
  class PrivateKey
    include Util

    attr_reader :param
    attr_reader :keys

    def initialize(param, keys)
      raise ArgumentError "param must be WOTS::Param." unless param.is_a?(WOTS::Param)
      raise ArgumentError "keys must be Array." unless keys.is_a?(Array)
      raise ArgumentError, "The length of keys must be the same as param#len." unless keys.length == param.len
      keys.each do |key|
        raise ArgumentError, "key must be hex string." unless hex_string?(key)
      end

      @param = param
      @keys = keys
    end

    # Generate private key using +seed+.
    # @param [WOTS::Param] param
    # @param [String] seed
    def self.from_seed(param, seed)
      raise ArgumentError "param must be WOTS::Param." unless param.is_a?(WOTS::Param)
      raise ArgumentError "seed must be String." unless seed.is_a?(String)
      raise ArgumentError "len parameter too large." if param.len.bit_length > 16
      ctr = Array.new(30, 0).pack('C*')

      keys = param.len.times.map do |i|
        param.prf(seed, ctr + [i].pack('n'))
      end

      PrivateKey.new(param, keys)
    end
  end
end