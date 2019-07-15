# https://cryptopals.com/sets/2/challenges/16
require_relative "../test_helper"

module Set2
  module Challenge16
    KEY = OpenSSL::Random.random_bytes(16).freeze
    IV  = OpenSSL::Random.random_bytes(16).freeze

    # not sure if this is needed for this challenge or not...
    def undo_pkcs7(str)
      chars   = []
      padding = []

      str.bytes.each_with_index do |byte, idx|
        if byte > 15
          chars << byte.chr
        else
          if padding.empty? && (str.length - idx == byte)
            padding << byte
          elsif byte == padding.first
            padding << byte
          else
            raise "padding error X"
          end
        end
      end

      chars.join
    end

    def pkcs_7(block, blocksize)
      padding_amount =
        if block.length < blocksize
          blocksize - block.length
        elsif block.length % blocksize == 0
          0
        else
          n = block.length % blocksize

          blocksize - n
        end

      (block.bytes + ([padding_amount] * padding_amount)).pack("C*")
    end

    def cbc_encrypt(p, key, iv)
      p        = pkcs_7(p, 16)

      acc      = []
      previous = iv
      p.each_char.each_slice(16) do |pn|
        pn       = pn.join
        pn       = _xor(previous, pn)
        cn       = _ecb_encrypt(pn, key)
        previous = cn

        acc << cn
      end

      acc.join
    end

    def cbc_decrypt(c, key, iv)
      previous = iv
      acc      = []
      c.each_char.each_slice(16) do |cn|
        cn       = cn.join
        x        = _ecb_decrypt(cn, key)
        p        = _xor(previous, x)
        previous = cn

        acc << p
      end

      acc.join
    end

    def _ecb_encrypt(p1, key)
      aes         = OpenSSL::Cipher.new("AES-128-ECB")
      aes.encrypt
      aes.key     = key
      aes.padding = 0

      aes.update(p1) + aes.final
    end

    def _ecb_decrypt(c1, key)
      aes         = OpenSSL::Cipher.new("AES-128-ECB")
      aes.decrypt
      aes.key     = key
      aes.padding = 0

      aes.update(c1) + aes.final
    end

    def _xor(cn, pn)
      cn  = cn.bytes
      pn  = pn.bytes
      acc = []

      cn.length.times do |idx|
        acc << (cn.at(idx) ^ pn.at(idx))
      end

      acc.pack("C*")
    end
  end

  class Challenge16Test < Test::Unit::TestCase
    include Challenge16

    def test_challenge16
    end

    # TODO: why does CBC have this property?
    # TODO: write the functions as Rx'd in the challenge
    # TODO: how to add in admin=true ?
    def test_scratch
      p1 = "WE ALL LIVE IN A YELLOW SUBMARINE, MOTHERFUKERS!"
      c1 = cbc_encrypt(p1, KEY, IV)

      b1, b2, b3 = c1.bytes.each_slice(16).to_a

      eb1    = b1.clone
      eb1[0] = b1[0].succ

      c2 = [eb1, b2, b3].flatten.pack("C*")

      p2 = cbc_decrypt(c2, KEY, IV)

      p2b1, p2b2, p2b3 = p2.each_char.each_slice(16).to_a

      binding.pry
    end
  end
end
