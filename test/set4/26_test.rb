# https://cryptopals.com/sets/4/challenges/26
require_relative "../test_helper"

module Set4
  module Challenge26
    KEY   = OpenSSL::Random.random_bytes(16).freeze
    NONCE = rand(2 ** 64)

    # Q: 64-bit unsigned, native endian (uint64_t)
    def ctr(text, key, nonce)
      text.
        bytes.
        each_slice(16).
        map.
        with_index do |block, block_index|
          keystream = _ecb_encrypt([nonce, block_index].pack("QQ"), key)

          block.map.with_index do |byte, byte_index|
            byte ^ keystream[byte_index].ord
          end
        end.flatten.pack("C*")
    end

    def _ecb_encrypt(p1, key)
      aes         = OpenSSL::Cipher.new("AES-128-ECB")
      aes.encrypt
      aes.key     = key
      aes.padding = 0

      aes.update(p1) + aes.final
    end

    def f1(userdata)
      cleaned_userdata = userdata.gsub(/([;=])/, "'" + '\1' + "'")

      data = [
        "comment1=cooking%20MCs;userdata=",
        cleaned_userdata,
        ";comment2=%20like%20a%20pound%20of%20bacon"
      ].join

      ctr(data, KEY, NONCE)
    end

    def admin?(ciphertext)
      data = ctr(ciphertext, KEY, NONCE)

      !!(data =~ /;admin=true;/)
    end
  end

  class Challenge26Test < Test::Unit::TestCase
    include Challenge26

    # At idx N, you will know:
    # - the plaintext byte (you control it)
    # - the ciphertext byte (you can read it)
    # therefore, you will know the keystream byte at N
    #
    # If the keystream byte is known, new bytes can be inserted in wholesale
    # by keystream-byte ^ byte-of-char-you-want
    #
    # CTR "decrypts" by keystream-byte XOR ciphertext-byte, which with our
    # subbed in byte, will give back byte-of-char-wanted
    def test_challenge_26
      idx = f1("").
            bytes.
            zip(f1("A").bytes).
            each_with_index do |(l, r), idx|
              break idx if l != r
            end

      p1          = "XadminXtrue"
      c1          = f1(p1)
      refute admin?(c1)

      ksb0        = p1[0].ord ^ c1[idx].ord
      ncb0        = ksb0 ^ ";".ord
      c1[idx]     = ncb0.chr

      ksb6        = p1[6].ord ^ c1[idx + 6].ord
      ncb6        = ksb6 ^ "=".ord
      c1[idx + 6] = ncb6.chr

      assert admin?(c1)
    end
  end
end
