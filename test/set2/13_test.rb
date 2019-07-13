# https://cryptopals.com/sets/2/challenges/13
require_relative "../test_helper"
require "ostruct"

module Set2
  module Challenge13
    KEY = OpenSSL::Random.random_bytes(16)

    def string_to_object(string)
      kvs = string.split("&")

      obj = {}
      kvs.each do |kv|
        k, v = kv.split("=")

        obj[k] = v
      end

      OpenStruct.new(obj)
    end

    def profile_for(email)
      email = email.tr("&", "").tr("=", "")

      "email=#{email}&uid=10&role=user"
    end

    def encrypt(p)
      cipher = OpenSSL::Cipher.new("AES-128-ECB")
      cipher.encrypt
      cipher.key = KEY
      cipher.padding = 0

      p = pkcs_7(p, 16)
      cipher.update(p) + cipher.final
    end

    def decrypt(c)
      cipher = OpenSSL::Cipher.new("AES-128-ECB")
      cipher.decrypt
      cipher.key = KEY

      cipher.update(c) + cipher.final
    end

    def oracle(email)
      encrypt(profile_for(email))
    end

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

  class Challenge13Test < Test::Unit::TestCase
    include Challenge13

    def test_string_to_object
      object = string_to_object("foo=bar&baz=qux&zap=zazzle")

      assert_equal object.foo, "bar"
      assert_equal object.baz, "qux"
      assert_equal object.zap, "zazzle"
    end

    def test_profile_for
      profile = profile_for("foo@bar.com")
      user  = string_to_object(profile)

      assert_equal user.email, "foo@bar.com"
      assert_match(/\d+/, user.uid)
      assert_equal user.role, "user"


      profile = profile_for("foo@bar.com&role=admin")
      user  = string_to_object(profile)

      assert_equal user.email, "foo@bar.comroleadmin"
    end

    def test_encrypt_decrypt
      profile = profile_for("foo@bar.com")

      c1  = encrypt(profile)
      p1  = decrypt(c1)

      assert_equal profile, p1
    end

    # ok to use/assume pkcs_7 padding here?
    # ok that the attack exploits the encoding k=v order?
    # ok that the attacker somehow knows this order?
    # ok that the uid stays constant?
    def test_challenge13
      assert oracle("").length == 32
      assert oracle("A" * 9).length == 32
      assert oracle("A" * 10).length == 48

      # So ("A" * 9) represents when the plaintext is exactly 32 bytes
      # long, becuase at ("A" * 10) => 33 bytes, it jumps up a block.
      # *However* that does not mean that the next character after ("A" * 9)
      # represents the start of a new block. This is because we could be
      # (and in this case we are) inserting in the middle of a block, not
      # at the end - so even though we've got two full 16 byte blocks, the
      # first block still has trailing character(s) that we don't own.
      #
      # example: (imagine 8 byte blocks):
      # XXXXXXXX|XXXXXX00
      # XXXXIIXX|XXXXXXXX (FULL!)
      # XXXXIIIX|XXXXXXXX|X00000000 (the 3rd I is *not* the start of a new block)
      #
      # the better way is to keep incrementing ("A" * 32) + ("A" * N) until
      # two identical blocks appear. Then use N as the target point that we
      # need to get to where we can insert our complete block, cleanly.

      blocks1 =
        oracle("A" * 10 + pkcs_7("admin", 16)).each_char.each_slice(16).to_a

      blocks2 =
        oracle("jw@eatshit.io").each_char.each_slice(16).to_a

      blocks2.pop
      blocks2 << blocks1[1]

      cn = blocks2.flatten.join

      pn = decrypt(cn)
      bad_user = string_to_object(pn)

      assert_equal bad_user.email, "jw@eatshit.io"
      assert_equal bad_user.uid, "10"
      assert_equal bad_user.role, "admin"
    end
  end
end
