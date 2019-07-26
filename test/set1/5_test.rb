# https://cryptopals.com/sets/1/challenges/5
require_relative "../test_helper"

def repeat_key_xor(key, plaintext)
  plaintext_bytes = plaintext.chomp.bytes
  key_bytes       = key.bytes

  plaintext_bytes.
    map.
    with_index do |pb, idx|
      encrypted_byte =
        pb ^ key_bytes[idx % key_bytes.length]

      sprintf("%02X", encrypted_byte)
    end.join
end

module Set1
  class Challenge5Test < Test::Unit::TestCase
    def test_challenge_5
      plaintext = <<~PLAINTEXT
      Burning 'em, if you ain't quick and nimble
      I go crazy when I hear a cymbal
      PLAINTEXT

      key = "ICE"

      expected = "0B3637272A2B2E63622C2E69692A23693A2A3C6324202D623D6" \
                 "3343C2A26226324272765272A282B2F20430A652E2C652A3124" \
                 "333A653E2B2027630C692B20283165286326302E27282F"

      actual = repeat_key_xor(key, plaintext)

      assert_equal expected, actual
    end
  end
end
