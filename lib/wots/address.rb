module WOTS
  class Address
    attr_accessor :layer_addr
    attr_accessor :tree_addr
    attr_accessor :ots_addr
    attr_accessor :chain_addr
    attr_accessor :hash_addr
    attr_accessor :key_and_mask # 0: key generation, 1: bitmask generation

    def initialize(layer_addr: 0, tree_addr: 0, ots_addr: 0, chain_addr: 0, hash_addr: 0, key_and_mask: 0)
      @layer_addr = layer_addr
      @tree_addr = tree_addr
      @ots_addr = ots_addr
      @chain_addr = chain_addr
      @hash_addr = hash_addr
      @key_and_mask = key_and_mask
    end

    def type
      0
    end

    def to_payload
      [layer_addr, tree_addr, type, ots_addr, chain_addr, hash_addr, key_and_mask].pack('NQ>NNNNN')
    end
  end
end