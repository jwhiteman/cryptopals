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


      (block.bytes + ([padding_amount] * padding_amount)).pack("C*")
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
      assert_equal "YELLOW SUBMARINES\x07\x07\x07\x07\x07\x07\x07", result

      result = pkcs_7("Y", 16)
      assert_equal "Y\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F", result
    end
  end
end
