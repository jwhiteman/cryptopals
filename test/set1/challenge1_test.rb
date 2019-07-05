# https://cryptopals.com/sets/1/challenges/1
require_relative "../test_helper"

module Set1
  class Challenge1Test < Test::Unit::TestCase
    def test_challenge_1
      hex = "49276d206b696c6c696e6720796f757220627261696e206c" \
            "696b65206120706f69736f6e6f7573206d757368726f6f6d"

      original_text =
        hex.
          scan(/../).
          reduce("") do |acc, hex_byte|
            acc << hex_byte.hex.chr
          end

      expected = "I'm killing your brain like a poisonous mushroom"
      assert_equal expected, original_text

      base64_text = [original_text].pack("m0")

      expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9p" \
                 "c29ub3VzIG11c2hyb29t"

      assert_equal expected, base64_text
    end
  end
end
