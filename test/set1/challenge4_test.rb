# https://cryptopals.com/sets/1/challenges/4
# https://github.com/technion/matasano_challenge/blob/master/set1/chal4/chal4.rb
require_relative "../test_helper"

module Set1
  module Challenge4
    def single_char_xor(data)
      results =
        data.lines.map.with_index do |possible_ciphertext, idx|
          possible_ciphertext.chomp!

          (0..255).map do |possible_key|
            possible_plaintext =
              possible_ciphertext.
                scan(/../).
                map { |hex| hex.hex ^ possible_key }.
                pack("C*")

            score =
              possible_plaintext.
              scan(/[ETAOIN SHRLDU]/i).
              size

            [score, possible_plaintext]
          end
        end

      results.flatten(1).sort.last
    end
  end

  class Challenge4Test < Test::Unit::TestCase
    include Challenge4

    def test_challenge_4
      data = IO.read("test/fixtures/challenge-4-data.txt")

      expected = [22, "Now that the party is jumping\n"]

      actual = single_char_xor(data)
      assert_equal expected, actual
    end
  end
end
