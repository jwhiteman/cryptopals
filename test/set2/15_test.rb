# https://cryptopals.com/sets/2/challenges/15
require_relative "../test_helper"

module Set2
  module Challenge15
    def undo_pkcs7(str)
      chars   = []
      padding = []

      str.
        bytes.
        each_with_index do |byte, idx|
          if byte > 15
            chars << byte.chr
          else
            if padding.empty? && (str.length - idx == byte)
              padding << byte
            elsif byte == padding.first
              padding << byte
            else
              raise "padding error X"
            end
          end
        end

      chars.join
    end
  end

  class Challenge15Test < Test::Unit::TestCase
    include Challenge15

    def test_challenge15
      assert_equal undo_pkcs7("ICE ICE BABY\x04\x04\x04\x04"), "ICE ICE BABY"

      assert_equal(
        undo_pkcs7("YELLOW SUBMARINE ICE ICE BABY\x03\x03\x03"),
        "YELLOW SUBMARINE ICE ICE BABY"
      )

      assert_raise do
        undo_pkcs7("ICE ICE BABY\x05\x05\x05\x05")
      end

      assert_raise do
        undo_pkcs7("ICE ICE BABY\x01\x02\x03\x04")
      end
    end
  end
end
