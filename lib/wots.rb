# frozen_string_literal: true
require 'digest'
require_relative "wots/version"
require_relative 'wots/util'
require_relative 'wots/param'
require_relative 'wots/address'
require_relative 'wots/private_key'
require_relative 'wots/public_key'
require_relative 'wots/signature'

module WOTS
  class Error < StandardError; end
end
