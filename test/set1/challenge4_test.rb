# https://cryptopals.com/sets/1/challenges/4
require_relative "../test_helper"

def single_char_xor(data)
  results =
    data.
    lines.
    map.
    with_index do |possible_ciphertext, idx|
      possible_ciphertext.chomp!

      SINGLE_BYTE_KEYS.map do |possible_key|
        h1 = possible_ciphertext.scan(/../)
        h2 = Array.new(h1.length) { possible_key }

        possible_plaintext =
          h1.zip(h2).map { |l, r| l.hex ^ r }.pack("C*")

        [
          frequency_match_score(possible_plaintext),
          possible_plaintext,
          possible_key.chr,
          possible_ciphertext,
          idx
        ]
      end
    end

  results =
    results.flatten(1).sort

  results.last
end

module Set1
  class Challenge4Test < Test::Unit::TestCase
    def test_challenge_4
      data = IO.read("test/fixtures/challenge-4-data.txt")

      expected = [
        17,
        "Now that the party is jumping\n",
        "5",
        "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f",
        170
      ]

      actual = single_char_xor(data)

      assert_equal expected, actual
    end
  end
end
