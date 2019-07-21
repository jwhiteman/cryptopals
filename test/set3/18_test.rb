# https://cryptopals.com/sets/3/challenges/18
# https://is.gd/0fbhnj
require_relative "../test_helper"

module Set3
  module Challenge18
    MSG = (
      "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/"\
      "2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    ).freeze

    KEY = "YELLOW SUBMARINE".freeze

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
  end

  class Challenge18Test < Test::Unit::TestCase
    include Challenge18

    def test_challenge_18
      msg = Base64.strict_decode64(MSG)

      p1 = ctr(msg, KEY, 0)

      assert_equal p1, "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

      c1 = ctr(p1, KEY, 0)

      assert_equal c1, msg
      assert_equal Base64.strict_encode64(c1), MSG
    end
  end
end
