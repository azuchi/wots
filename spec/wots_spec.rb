# frozen_string_literal: true
require 'spec_helper'

RSpec.describe WOTS do

  let(:param) { WOTS::Param::SHA256 }

  describe 'generate public key' do
    let(:vector) { load_fixture('key.json') }
    it do
      private_key = WOTS::PrivateKey.from_seed(param, vector['seed'])
      public_key = WOTS::PublicKey.from_private_key(private_key, vector['pub_seed'])

      expect(public_key.keys).to eq(vector['public_key'])
      message = vector['message']
      signature = private_key.sign(vector['pub_seed'], message)
      expect(signature.sigs).to eq(vector['signature'])

      pubkey_from_sig = WOTS::PublicKey.from_signature(signature, vector['pub_seed'], message)
      expect(pubkey_from_sig).to eq(public_key)
    end
  end
end
