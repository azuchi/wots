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
    attr_reader :len

    # @param [Hash] opts
    # @option opts [Integer] :n the message length as well as the length of a private key,
    # public key, or signature element in bytes.
    # @option opts [Integer] :w the Winternitz parameter; it is a member of the set {4, 16}.
    # @option opts [Integer] :len the number of n-byte string elements in a WOTS+ private key, public key, and signature.
    def initialize(opts)
      raise ArgumentError, 'name must be string.' unless opts[:name].is_a?(String)
      raise ArgumentError, 'n must be integer.' unless opts[:n].is_a?(Integer)
      raise ArgumentError, 'w must be integer.' unless opts[:w].is_a?(Integer)
      raise ArgumentError, 'len must be integer.' unless opts[:len].is_a?(Integer)

      @name = opts[:name]
      @n = opts[:n]
      @w = opts[:w]
      @len = opts[:len]
    end

    # PRF function.
    # @param [String] k
    # @param [String] m
    # @return [String] Hex string.
    def prf(k, m)
      case name
      when 'wotsp-sha2_256'
        Digest::SHA256.hexdigest(prf_prefix + hex_to_bin(k) + hex_to_bin(m))
      when 'wotsp-sha512'
        Digest::SHA512.hexdigest(prf_prefix + hex_to_bin(k) + hex_to_bin(m))
      else
        raise 'Unknown param'
      end
    end

    private

    def to_byte(value, length)
      (Array.new(length - 1, 0) + [value]).pack('C*')
    end

    def prf_prefix
      @_prf_prefxi ||= case name
                       when 'wotsp-sha2_256', 'wotsp-shake_256'
                         to_byte(3, 32)
                       when 'wotsp-sha512', 'wotsp-shake_512'
                         to_byte(3, 64)
                       else
                         raise 'Unknown param'
                       end
    end
  end
end