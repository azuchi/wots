# frozen_string_literal: true
require 'digest'
require_relative "wots/version"
require_relative 'wots/util'
require_relative 'wots/param'
require_relative 'wots/private_key'

module WOTS
  class Error < StandardError; end

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
end
