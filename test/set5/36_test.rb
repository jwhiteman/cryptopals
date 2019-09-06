# https://cryptopals.com/sets/5/challenges/36
require_relative "../test_helper"

module Set5
  class Challenge36Test < Test::Unit::TestCase
    # experimenting w/ a fiber here, to see if it makes it easier to write
    # a proof-of-concept. i'm not sure that it does.
    # regardless, treat the params of Fiber.yield as a return that then blocks
    # until `resume` is called, which then becomes the return value.
    def test_challenge_36
      server = Fiber.new do |msg|
        n, g, k, i, p = msg

        # Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
        # ...and get i and biga in return
        i, biga = Fiber.yield(msg)

        # Generate salt as random integer
        salt = rand(n)

        # Generate string xH=SHA256(salt|password)
        xh   = OpenSSL::Digest::SHA256.hexdigest(salt.to_s + p)

        # Convert xH to integer x somehow (put 0x on hexdigest)
        x    = xh.hex

        # Generate v=g**x % N
        v    = g.pow(x, n)

        # Send salt, B=kv + g**b % N
        b    = rand(n)
        bigb = k * v + g.pow(b, n)

        client_mac = Fiber.yield([salt, bigb])

        # Compute string uH = SHA256(A|B), u = integer of uH
        uh = OpenSSL::Digest::SHA256.hexdigest(biga.to_s + bigb.to_s)
        u  = uh.hex

        # Generate S = (A * v**u) ** b % N
        s  = (biga * v.pow(u, n)).pow(b, n)

        # Generate K = SHA256(S)
        k  = OpenSSL::Digest::SHA256.hexdigest(s.to_s)

        # Send "OK" if HMAC-SHA256(K, salt) validates
        our_mac = OpenSSL::HMAC.hexdigest("SHA1", k, salt.to_s)

        Fiber.yield (client_mac == our_mac) ? "OK" : [client_mac, our_mac]
      end

      n = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"\
        "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374f"\
        "e1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee38"\
        "6bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48"\
        "361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52907"\
        "7096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".hex

      g = 2
      k = 3
      i = "someone@example.com"
      p = "some-password"

      n, g, k, i, p = server.resume([n, g, k, i, p])

      a    = rand(n)
      biga = g.pow(a, n)

      # Send I, A=g**a % N (a la Diffie Hellman)
      salt, bigb = server.resume([i, biga])

      # Compute string uH = SHA256(A|B), u = integer of uH
      uh = OpenSSL::Digest::SHA256.hexdigest(biga.to_s + bigb.to_s)
      u  = uh.hex

      # Generate string xH=SHA256(salt|password)
      xh = OpenSSL::Digest::SHA256.hexdigest(salt.to_s + p)

      # Convert xH to integer x somehow (put 0x on hexdigest)
      x  = xh.hex

      # Generate S = (B - k * g**x)**(a + u * x) % N
      s = (bigb - k * g.pow(x, n)).pow(a + u * x, n)

      # Generate K = SHA256(S)
      k = OpenSSL::Digest::SHA256.hexdigest(s.to_s)

      # Send HMAC-SHA256(K, salt)
      mac = OpenSSL::HMAC.hexdigest("SHA1", k, salt.to_s)

      response = server.resume(mac)

      assert_equal response, "OK"
    end
  end
end
