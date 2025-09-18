# frozen_string_literal: true
require 'spec_helper'
require 'securerandom'
require 'digest'

RSpec.describe WOTS do

  describe 'Test Vector' do
    let(:vector) { load_fixture('key.json') }
    it do
      seed = vector['seed']
      pub_seed = vector['pub_seed']
      message = vector['message']

      params = [
        WOTS::Param::SHA256,
        WOTS::Param.new(name: 'WOTSP-SHA2_256', n: 32, w: 4),
        WOTS::Param.new(name: 'WOTSP-SHA2_256', n: 32, w: 256)
      ]

      params.each do |param|
        private_key = WOTS::PrivateKey.from_seed(param, seed)
        public_key = WOTS::PublicKey.from_private_key(private_key, pub_seed)

        if param.w == 16
          expect(public_key.keys).to eq(vector['public_key'])
        end

        signature = private_key.sign(pub_seed, message)
        expect_signature = case param.w
                    when 4
                      vector['signatureW4']
                    when 256
                      vector['signatureW256']
                    else
                      vector['signature']
                    end

        expect(signature.sigs).to eq(expect_signature)

        pubkey_from_sig = WOTS::PublicKey.from_signature(signature, pub_seed, message)
        expect(pubkey_from_sig).to eq(public_key)
      end
    end
  end

  describe 'All params' do
    let(:params) { [ WOTS::Param::SHA256, WOTS::Param::SHA512, WOTS::Param::SHAKE256 ] }
    it do
      params.each do |param|
        seed = SecureRandom.hex(param.n)
        pub_seed = SecureRandom.hex(param.n)
        message = SecureRandom.hex(param.n)

        private_key = WOTS::PrivateKey.from_seed(param, seed)
        public_key = WOTS::PublicKey.from_private_key(private_key, pub_seed)
        expect([public_key.keys.join].pack('H*').bytesize).to eq(param.n * param.len)

        signature = private_key.sign(pub_seed, message)
        expect([signature.sigs.join].pack('H*').bytesize).to eq(param.n * param.len)
        pubkey_from_sig = WOTS::PublicKey.from_signature(signature, pub_seed, message)
        expect(pubkey_from_sig).to eq(public_key)
      end
    end
  end
end
