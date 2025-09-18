module WOTS
  # WOTS+ public key.
  class PublicKey
    include Util
    extend Util

    attr_reader :param
    attr_reader :keys

    def initialize(param, keys)
      raise ArgumentError "param must be WOTS::Param." unless param.is_a?(WOTS::Param)
      raise ArgumentError "keys must be Array." unless keys.is_a?(Array)
      raise ArgumentError, "The length of keys must be the same as param#len." unless keys.length == param.len
      keys.each do |key|
        raise ArgumentError, "key must be hex string." unless hex_string?(key)
        raise ArgumentError, "key must be #{param.n} bytes." unless hex_to_bin(key).bytesize == param.n
      end
      @param = param
      @keys = keys
    end

    # Generate public key from +private_key+ and +pub_seed+.
    # @param [WOTS::PrivateKey] private_key
    # @param [String] pub_seed
    def self.from_private_key(private_key, pub_seed)
      raise ArgumentError, 'private_key must be WOTS::PrivateKey.' unless private_key.is_a?(WOTS::PrivateKey)
      param = private_key.param
      raise ArgumentError, 'pub_seed must be hex string.' unless hex_string?(pub_seed)
      raise ArgumentError, "pub_seed must be #{param.n} bytes." unless hex_to_bin(pub_seed).bytesize == param.n
      addr = WOTS::Address.new
      keys = param.len.times.map do |i|
        addr.chain_addr = i
        sk = private_key.keys[i]
        param.chain(sk, 0, param.w - 1, pub_seed, addr)
      end
      PublicKey.new(private_key.param, keys)
    end

    # Generate public key from +signature+.
    # @param [WOTS::Signature] signature
    # @param [String] pub_seed
    # @param [String] message
    # @return [WOTS::PublicKey]
    # @raise ArgumentError
    def self.from_signature(signature, pub_seed, message)
      param = signature.param
      raise ArgumentError, 'pub_seed must be hex string.' unless hex_string?(pub_seed)
      raise ArgumentError, "pub_seed must be #{param.n} bytes." unless hex_to_bin(pub_seed).bytesize == param.n
      raise ArgumentError, "message must be string." unless message.is_a?(String)
      raise ArgumentError, "message must be #{param.n} bytes." unless hex_to_bin(message).bytesize == param.n

      base_w = param.base_w(message, param.len1)
      c_sum = param.compute_checksum(base_w)
      base_w = base_w + param.base_w(c_sum, param.len2)

      addr = WOTS::Address.new

      keys = param.len.times.map do |i|
        addr.chain_addr = i
        param.chain(signature.sigs[i], base_w[i], param.w - 1 - base_w[i], pub_seed, addr)
      end

      PublicKey.new(param, keys)
    end

    def ==(other)
      return false unless other.is_a?(PublicKey)
      param == other.param && keys == other.keys
    end
  end
end