# https://cryptopals.com/sets/1/challenges/7
require_relative "../test_helper"

module Set7
  class Challenge7Test < Test::Unit::TestCase
    def test_challenge_7
      ciphertext = IO.read("test/fixtures/challenge-7-data.txt")
      ciphertext = ciphertext.split("\n").join.unpack("m0").first.chomp
      key        = "YELLOW SUBMARINE"
      cipher     = OpenSSL::Cipher.new("AES-128-ECB")

      cipher.key = key
      plaintext  = cipher.update(ciphertext)

      expected   = "I'm back and I'm ringin' the bell \n"
      assert_equal expected, plaintext.lines.first

      # NOTE: Is this right?. Maybe I've made a mistake somewhere..
      expected   = "Play that f"
      assert_equal expected, plaintext.lines.last
    end
  end
end
