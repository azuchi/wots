module WOTS
  # WOTS+ private key.
  class PrivateKey
    include Util
    extend Util

    attr_reader :param
    attr_reader :keys

    def initialize(param, keys)
      raise ArgumentError, "param must be WOTS::Param." unless param.is_a?(WOTS::Param)
      raise ArgumentError, "keys must be Array." unless keys.is_a?(Array)
      raise ArgumentError, "The length of keys must be the same as param#len." unless keys.length == param.len
      keys.each do |key|
        raise ArgumentError, "key must be hex string." unless hex_string?(key)
        raise ArgumentError, "key must be #{param.n} bytes." unless hex_to_bin(key).bytesize == param.n
      end

      @param = param
      @keys = keys
    end

    # Generate private key using +seed+.
    # @param [WOTS::Param] param
    # @param [String] seed
    # @raise ArgumentError
    def self.from_seed(param, seed)
      raise ArgumentError, "param must be WOTS::Param." unless param.is_a?(WOTS::Param)
      raise ArgumentError, "seed must be String." unless seed.is_a?(String)
      raise ArgumentError, "seed must be #{param.n} bytes." unless hex_to_bin(seed).bytesize == param.n
      raise ArgumentError, "len parameter too large." if param.len.bit_length > 16

      keys = param.len.times.map do |i|
        param.prf(seed, param.to_byte(i, 32))
      end

      PrivateKey.new(param, keys)
    end

    # Generate signature.
    # @param [String] pub_seed The Public seed.
    # @param [String] message The message to be signed.
    # @return [WOTS::Signature]
    # @raise ArgumentError
    def sign(pub_seed, message)
      raise ArgumentError, 'pub_seed must be hex string.' unless hex_string?(pub_seed)
      raise ArgumentError, "pub_seed must be #{param.n} bytes." unless hex_to_bin(pub_seed).bytesize == param.n
      raise ArgumentError, "message must be string." unless message.is_a?(String)
      raise ArgumentError, "message must be #{param.n} bytes." unless hex_to_bin(message).bytesize == param.n

      addr = Address.new

      # Convert message to base w
      base_w = param.base_w(message, param.len1)

      # Compute checksum
      c_sum = param.compute_checksum(base_w)

      base_w = base_w + param.base_w(c_sum, param.len2)

      sigs = param.len.times.map do |i|
        addr.chain_addr = i
        param.chain(keys[i], 0, base_w[i], pub_seed, addr)
      end

      Signature.new(param, sigs)
    end
  end
end