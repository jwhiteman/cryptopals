# https://cryptopals.com/sets/2/challenges/9
require_relative "../test_helper"

module Set2
  module Challange9
    def pkcs_7(block, blocksize)
      padding_amount =
        if block.length < blocksize
          blocksize - block.length
        elsif block.length % blocksize == 0
          0
        else
          n = block.length % blocksize

          blocksize - n
        end


      block << "\x04" * padding_amount
    end
  end

  class Challenge9Test < Test::Unit::TestCase
    include Challange9

    def test_challange_9
      result = pkcs_7("YELLOW SUBMARINE", 20)
      assert_equal "YELLOW SUBMARINE\x04\x04\x04\x04", result

      result = pkcs_7("YELLOW SUBMARINE", 8)
      assert_equal "YELLOW SUBMARINE", result

      result = pkcs_7("YELLOW SUBMARINES", 8)
      assert_equal "YELLOW SUBMARINES\x04\x04\x04\x04\x04\x04\x04", result
    end
  end
end
