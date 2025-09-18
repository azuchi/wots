module WOTS
  # WOTS+ signature.
  class Signature
    include Util

    attr_reader :param, :sigs

    def initialize(param, sigs)
      raise ArgumentError, "param must be WOTS::Param." unless param.is_a?(WOTS::Param)
      raise ArgumentError, "sigs must be Array." unless sigs.is_a?(Array)
      raise ArgumentError, "The length of sigs must be the same as param#len." unless sigs.length == param.len
      sigs.each do |sig|
        raise ArgumentError, "sig must be hex string." unless hex_string?(sig)
        raise ArgumentError, "sig must be #{param.n} bytes." unless hex_to_bin(sig).bytesize == param.n
      end

      @param = param
      @sigs = sigs
    end
  end
end