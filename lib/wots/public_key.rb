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
      raise ArgumentError, 'pub_seed must be hex string.' unless hex_string?(pub_seed)
      param = private_key.param
      addr = WOTS::Address.new
      keys = param.len.times.map do |i|
        addr.chain_addr = i
        sk = private_key.keys[i]
        param.chain(sk, 0, param.w - 1, pub_seed, addr)
      end
      PublicKey.new(private_key.param, keys)
    end
  end
end