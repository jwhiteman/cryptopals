# https://cryptopals.com/sets/4/challenges/30
require_relative "../test_helper"

module Set4
  class Challenge30Test < Test::Unit::TestCase
    STRING = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".freeze
    KEY    = "SECRET-PREFIX!".freeze

    def _mac(string)
      MD4.exec(KEY + string)
    end

    def _valid?(string, digest)
      _mac(string) == digest
    end

    def _md_padding(string)
      byte_length = string.length
      mask        = 0xffffffff

      bit_len     = string.size << 3 # == string.size * 8
      string += "\x80"

      while (string.size % 64) != 56
        string += "\0"
      end

      string =
        string.force_encoding('ascii-8bit') + [bit_len & mask, bit_len >> 32].pack("V2")

      if string.size % 64 != 0
        raise "failed to pad to correct length"
      else
        string[byte_length..-1].force_encoding("utf-8")
      end
    end

    def test_challenge_30
      good_digest   = _mac(STRING)
      state         = [good_digest].pack("H*").unpack("V4")

      msg1          = ("A" * KEY.length) + ("A" * STRING.length)
      msg2          = msg1 + _md_padding(msg1) + ";admin=true"
      forged_digest = MD4.exec(";admin=true" + _md_padding(msg2), state.dup, true)
      forged_string = STRING + _md_padding(msg1) + ";admin=true"

      assert _valid?(forged_string, forged_digest)
    end

    def test_md4
      d1 = MD4.exec("hello, world")
      d2 = OpenSSL::Digest::MD4.hexdigest("hello, world")

      assert_equal d1, d2
    end
  end
end
