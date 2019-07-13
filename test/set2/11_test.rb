# https://cryptopals.com/sets/2/challenges/11
require_relative "../test_helper"

module Set2
  module Challenge11
    def encryption_oracle(p)
      key  = OpenSSL::Random.random_bytes(16)
      iv   = OpenSSL::Random.random_bytes(16)
      pre  = OpenSSL::Random.random_bytes(rand(5) + 5)
      post = OpenSSL::Random.random_bytes(rand(5) + 5)

      p    = [pre, p, post].join

      if rand(2) == 0
        cbc_encrypt(p, key, iv)
      else
        p = pkcs_7(p, 16)

        _ecb_encrypt(p, key)
      end
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

    def ecb_or_cbc(c)
      acc = Hash.new { 0 }

      c.each_char.each_slice(16) do |slice|
        acc[slice] += 1
      end

      if acc.values.any? { |v| v > 1 }
        "ECB"
      else
        "CBC"
      end
    end
  end

  class Challenge11Test < Test::Unit::TestCase
    include Challenge11

    def test_challenge_11
      results =
        10.times.map { ecb_or_cbc(encryption_oracle("a" * 160)) }.uniq

      assert results.include?("ECB")
      assert results.include?("CBC")
    end
  end
end
