# https://cryptopals.com/sets/4/challenges/29
require_relative "../test_helper"

module Set4
  class Challenge29Test < Test::Unit::TestCase
    STRING = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".freeze
    KEY    = "SECRET-PREFIX!".freeze

    def _mac(string)
      SHA1.exec(KEY + string)
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
        string.force_encoding('ascii-8bit') + [bit_len >> 32, bit_len & mask].pack("N2")

      if string.size % 64 != 0
        raise "failed to pad to correct length"
      else
        string[byte_length..-1].force_encoding("utf-8")
      end
    end

    # https://en.wikipedia.org/wiki/Length_extension_attack
    # http://netifera.com/research/flickr_api_signature_forgery.pdf
    # https://en.wikipedia.org/wiki/SHA-1
    def test_challenge_29
      good_digest   = _mac(STRING)
      state         = [good_digest].pack("H*").unpack("N5")

      forged_hash_created = (1..20).detect do |key_length_guess|
        msg1          = ("A" * key_length_guess) + ("A" * STRING.length)
        msg2          = msg1 + _md_padding(msg1) + ";admin=true"
        forged_digest = SHA1.exec(";admin=true" + _md_padding(msg2), state.dup, true)
        forged_string = STRING + _md_padding(msg1) + ";admin=true"

        _valid?(forged_string, forged_digest)
      end

      assert forged_hash_created
    end

    # solve a simpler problem:
    # https://math.berkeley.edu/~gmelvin/polya.pdf
    def test_simpler_problem
      # the 'key' + the original message:
      d1    = SHA1.exec("AB")
      state = [d1].pack("H*").unpack("N5")

      # at no point does the above `state` appear in this:
      # SHA1.exec("ABC")

      # but, it does is this:
      m2    =  "AB" + _md_padding("AB") + "C"
      d2    = SHA1.exec(m2)

      # the trick here, it seems, is that if you start w/ your own state var
      # (instead of the magic numbers), then you need to take it upon yourself
      # to make sure that the overall padding works out correctly; otherwise,
      # the padding algorithm that normally runs at the start will have no idea
      # how to take into account the padding that is in the given state. so i'm
      # providing it manually
      # note how "prepadded" is set to true, and the overall padding is set
      # manually
      d3    = SHA1.exec("C" + _md_padding(m2), state, true)

      assert_equal d2, d3
    end
  end
end
