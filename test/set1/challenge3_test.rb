# https://cryptopals.com/sets/1/challenges/3
require_relative "../test_helper"

module Set1
  module Challenge3
    def single_byte_xor(ciphertext, key)
      ciphertext.scan(/../).map { |hexbyte| hexbyte.hex ^ key }.pack("C*")
    end
  end

  class Challenge3Test < Test::Unit::TestCase
    include Challenge3

    def setup
      @ciphertext = "1b37373331363f78151b7f2b783431333d78" \
                    "397828372d363c78373e783a393b3736"
    end

    def test_challenge_3
      key =
        (0..255).detect do |possible_key|
          evaluated = single_byte_xor(@ciphertext, possible_key)
          magiccount = evaluated.scan(/[ETAOIN SHRLDU]/i).size

          magiccount > 20 && (evaluated !~ /[[:cntrl:]]/)
        end

      assert_equal "X", key.chr
    end
  end
end
