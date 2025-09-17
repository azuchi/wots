module WOTS
  # WOTS+ parameters defined in rfc8391.
  # https://datatracker.ietf.org/doc/html/rfc8391
  class Param
    include Util

    autoload :SHA256, 'wots/param/sha256'
    autoload :SHA512, 'wots/param/sha512'
    autoload :SHAKE256, 'wots/param/shake256'
    autoload :SHAKE512, 'wots/param/shake512'

    attr_reader :name
    attr_reader :n
    attr_reader :w

    # @param [Hash] opts
    # @option opts [Integer] :n the message length as well as the length of a private key,
    # public key, or signature element in bytes.
    # @option opts [Integer] :w the Winternitz parameter; it is a member of the set {4, 16}.
    # @option opts [Integer] :len the number of n-byte string elements in a WOTS+ private key, public key, and signature.
    def initialize(opts)
      raise ArgumentError, 'name must be string.' unless opts[:name].is_a?(String)
      raise ArgumentError, 'n must be integer.' unless opts[:n].is_a?(Integer)
      raise ArgumentError, 'w must be integer.' unless opts[:w].is_a?(Integer)

      @name = opts[:name]
      @n = opts[:n]
      @w = opts[:w]
    end

    def len1
      @len1 ||= (8.0 * n / Math.log2(w)).ceil
    end

    def len2
      @len2 ||= (Math.log2(len1 * (w - 1)) / Math.log2(w)).floor + 1
    end

    def len
      @len ||= len1 + len2
    end

    def f(k, m)
      keyed_hash(0, k, m)
    end

    def h(k, m)
      keyed_hash(1, k, m)
    end

    def h_msg(k, m)
      keyed_hash(2, k, m)
    end

    # PRF function.
    # @param [String] k key
    # @param [String] m message
    # @return [String] Hex string.
    def prf(k, m)
      keyed_hash(3, k, m)
    end

    # Convert data as base w representation.
    # @param [String] data The data to be converted.
    # @return [Array] An array of integer.
    def base_w(data)
      x = hex_to_bin(data)

      basew = []
      in_idx = 0
      total = 0
      bits = 0
      lg_w = Math.log2(w).to_i  # lg(w): 4→2, 16→4, 256→8

      len1.times do
        if bits == 0
          break if in_idx >= x.bytesize
          total = x.getbyte(in_idx)
          in_idx += 1
          bits += 8
        end

        bits -= lg_w
        basew << ((total >> bits) & (w - 1))
      end

      basew
    end

    # Compute checksum for +base_w+.
    # @param [Array] base_w
    # @return [String] Checksum binary string.
    def compute_checksum(base_w)
      c_sum = 0
      len1.times do |i|
        c_sum = (c_sum + w - 1 - base_w[i])
      end
      c_sum = (c_sum << (8 - ((len2 * Math.log2(w).to_i) % 8)))
      len_2_bytes = ((len2 * Math.log2(w).to_i) / 8.0).ceil
      to_byte(c_sum, len_2_bytes)
    end

    # WOTS+ Chaining Function.
    # @see https://datatracker.ietf.org/doc/html/rfc8391#autoid-16
    # @param [String] x Input string.
    # @param [Integer] start_idx Start index.
    # @param [Integer] steps Number of steps.
    # @param [String] seed Seed.
    # @param [WOTS::Address] addr Address.
    # @return [String] Result.
    def chain(x, start_idx, steps, seed, addr)
      return x if steps == 0
      raise "Invalid range" if (start_idx + steps) > (w - 1)

      result = x.dup

      steps.times do |i|
        addr.hash_addr = (start_idx + i)

        addr.key_and_mask = 0
        key = prf(seed, addr.to_payload)

        addr.key_and_mask = 1
        mask = prf(seed, addr.to_payload)

        masked = xor_bytes(result, mask)
        result = f(key, masked)
      end

      result
    end

    def ==(other)
      return false unless other.is_a?(Param)
      name == other.name && n == other.n && w == other.w
    end

    private

    def xor_bytes(a, b)
      [a].pack('H*').unpack('C*').zip(
        [b].pack('H*').unpack('C*')
      ).map { |x, y| x ^ y }.pack("C*")
    end

    # Convert +value+ to +length+ size binary string.
    # @param [Integer] value
    # @param [Integer] length
    # @return [String]
    def to_byte(value, length)
      bytes = []

      length.times do
        bytes.unshift(value & 0xFF)
        value >>= 8
      end

      bytes.pack("C*")
    end

    def keyed_hash(prefix, k, m)
      case name
      when 'wotsp-sha2_256'
        Digest::SHA256.hexdigest(to_byte(prefix, 32) + hex_to_bin(k) + hex_to_bin(m))
      when 'wotsp-sha512'
        Digest::SHA512.hexdigest(to_byte(prefix, 64) + hex_to_bin(k) + hex_to_bin(m))
      else
        raise 'Unknown param'
      end
    end
  end
end