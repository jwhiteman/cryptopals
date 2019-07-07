# https://cryptopals.com/sets/1/challenges/2
require_relative "../test_helper"

def fixed_xor_cheating(a, b)
  (a.to_i(16) ^ b.to_i(16)).to_s(16)
end

def fixed_xor(a, b)
  h1 = a.scan(/../)
  h2 = b.scan(/../)

  h1.zip(h2).map { |l, r| l.hex ^ r.hex }.pack("C*")
end

# lesson learned:
# String#hex isn't just for single bytes, it can be entire strings, thus
def fixed_xor_improved(a, b)
  (a.hex ^ b.hex).to_s(16)
end

module Set1
  class Challenge2Test < Test::Unit::TestCase
    def setup
      @a = "1c0111001f010100061a024b53535009181c"
      @b = "686974207468652062756c6c277320657965"
    end

    def test_challenge_2
      plaintext = fixed_xor(@a, @b)

      expected = "the kid don't play"
      assert_equal expected, plaintext

      expected = "746865206b696420646f6e277420706c6179"
      hex      = plaintext.unpack("H*").first

      assert_equal expected, hex
    end

    def test_challenge_2_cheating
      expected = "746865206b696420646f6e277420706c6179"
      hex      = fixed_xor_cheating(@a, @b)

      assert_equal expected, hex
    end

    def test_fixed_xor_improved
      expected = "746865206b696420646f6e277420706c6179"
      hex      = fixed_xor_improved(@a, @b)

      assert_equal expected, hex
    end
  end
end
