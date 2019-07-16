# https://cryptopals.com/sets/2/challenges/16
require_relative "../test_helper"

module Set2
  module Challenge16
    KEY = OpenSSL::Random.random_bytes(16).freeze
    IV  = OpenSSL::Random.random_bytes(16).freeze

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

    def f1(userdata)
      cleaned_userdata = userdata.gsub(/([;=])/, "'" + '\1' + "'")

      data = [
        "comment1=cooking%20MCs;userdata=",
        cleaned_userdata,
        ";comment2=%20like%20a%20pound%20of%20bacon"
      ].join

      data = pkcs_7(data, 16)

      cbc_encrypt(data, KEY, IV)
    end

    def admin?(ciphertext)
      data = cbc_decrypt(ciphertext, KEY, IV)

      !!(data =~ /;admin=true;/)
    end
  end

  class Challenge16Test < Test::Unit::TestCase
    include Challenge16

    # LESSON: it's not as simple as taking the byte integer value and
    # simply incrementing it - because going from byte value 3 to byte value
    # 4, for example, changes more than 1 bit.
    #
    # If you just want to flip a single bit, then byte-value ^ 1 seems to be
    # a better way to go.
    def test_challenge16
      c1     = f1(":admin<true")
      refute admin?(c1)

      blocks = c1.bytes.each_slice(16).to_a

      blocks[1][0]  = blocks[1][0] ^ 1
      blocks[1][6]  = blocks[1][6] ^ 1

      c2 = blocks.flatten.pack("C*")

      assert admin?(c2)
    end
  end
end
