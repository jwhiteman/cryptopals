# https://cryptopals.com/sets/1/challenges/7
require_relative "../test_helper"

module Set1
  class Challenge7Test < Test::Unit::TestCase
    def test_challenge_7
      ciphertext = IO.read("test/fixtures/challenge-7-data.txt")
      ciphertext = ciphertext.split("\n").join.unpack("m0").first.chomp
      key        = "YELLOW SUBMARINE"
      cipher     = OpenSSL::Cipher.new("AES-128-ECB")

      cipher.key = key
      plaintext  = cipher.update(ciphertext) + cipher.final

      expected   = "I'm back and I'm ringin' the bell \n"
      assert_equal expected, plaintext.lines.first

      # Is this right? Check against the command line.
      expected   = "Play that funky music \n"
      assert_equal expected, plaintext.lines.last
    end
  end
end
