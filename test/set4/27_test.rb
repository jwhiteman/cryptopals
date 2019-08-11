# https://cryptopals.com/sets/4/challenges/27
require_relative "../test_helper"

module Set4
  module Challenge27
    KEY = OpenSSL::Random.random_bytes(16).freeze
    IV  = KEY

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

      if data.bytes.any? { |byte| byte > 127 }
        # simulate an error from high ASCII value found
        data
      else
        data = pkcs_7(data, 16)

        cbc_encrypt(data, KEY, IV)
      end
    end

    def admin?(ciphertext)
      data = cbc_decrypt(ciphertext, KEY, IV)

      if data.bytes.any? { |byte| byte > 127 }
        # simulate an error from high ASCII value found
        data
      else
        !!(data =~ /;admin=true;/)
      end
    end
  end

  class Challenge27Test < Test::Unit::TestCase
    include Challenge27

    # this attack is easy enough to see if you draw out CBC decryption,
    # re-use the KEY as the IV and are able to make decryption requests
    def test_challenge_27
      ciphertext        = f1("")
      c0                = ciphertext[0...16]
      attack_ciphertext = [c0, "\x00" * 16, c0, "A" * 256].join
      error_text        = admin?(attack_ciphertext)

      p1, _, p3         = error_text.bytes.each_slice(16).take(3)
      found_key         = p1.zip(p3).map { |l, r| l ^ r }.pack("C*")

      refute admin?(ciphertext)
      assert_equal KEY, found_key
    end
  end
end
