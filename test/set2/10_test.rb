# https://cryptopals.com/sets/2/challenges/10
require_relative "../test_helper"

module Set2
  module Challenge10
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
        cn       = _ebc_encrypt(pn, key)
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
        x        = _ebc_decrypt(cn, key)
        p        = _xor(previous, x)
        previous = cn

        acc << p
      end

      acc.join
    end

    def _ebc_encrypt(p1, key)
      aes         = OpenSSL::Cipher.new("AES-128-ECB")
      aes.encrypt
      aes.key     = key
      aes.padding = 0

      aes.update(p1) + aes.final
    end

    def _ebc_decrypt(c1, key)
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

  class Challenge10Test < Test::Unit::TestCase
    include Challenge10

    def test_prelims
      key = "YELLOW SUBMARINE"
      iv  = "\x00" * 16

      p1 = "hello"
      c1 = cbc_encrypt(p1, key, iv)
      pn = cbc_decrypt(c1, key, iv)

      assert_match p1, pn

      p1 =  "aaaabbbbccccdddd"
      c1 = _ebc_encrypt(p1, key)
      pn  = _ebc_decrypt(c1, key)

      p1 =  "aaaabbbbccccdddd" * 10
      c1 = _ebc_encrypt(p1, key)
      pn  = _ebc_decrypt(c1, key)

      assert_equal p1, pn
    end

    def test_more_prelims
      p1  = "aaaabbbbccccdddd" * 10
      key = "YELLOW SUBMARINE"
      iv  = "\x00" * 16

      c1  = cbc_encrypt(p1, key, iv)
      pn  = cbc_decrypt(c1, key, iv)

      assert_equal p1, pn
    end

    def test_challenge_10
      c1  = IO.read("test/fixtures/challenge-10-data.txt")
      c1  = c1.split("\n").join.unpack("m0").first.chomp
      key = "YELLOW SUBMARINE"
      iv  = "\x00" * 16

      pn  = cbc_decrypt(c1, key, iv)

      actual   = pn.lines[-2] # 2nd to last line
      expected = "Play that funky music \n"

      assert_equal actual, expected
    end
  end
end
