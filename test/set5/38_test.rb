# https://cryptopals.com/sets/5/challenges/38
require_relative "../test_helper"

module Set5
  class SimplifiedWorker < SRP::Worker
    attr_reader :u

    def exchange_keys(i, public_a)
      @public_a  = public_a
      @i         = server.lookup(i)
      @s         = @i[:s]
      @v         = @i[:v]
      @public_b  = g.pow(b, n)
      @u         = rand(2 ** 128)

      [@s, @public_b, @u]
    end

    def verify_mac(client_mac)
      s       = (public_a * v.pow(u, n)).pow(b, n)
      k       = _hash(s)
      our_mac = _hmac(k, @s)

      if client_mac == our_mac
        "OK"
      else
        "ERROR"
      end
    end
  end

  class SimplifiedClient < SRP::Client
    def login(worker)
      a                 = rand(n)
      public_a          = g.pow(a, n)

      # step 1
      salt, public_b, u = worker.exchange_keys(@i, public_a)

      # I'm really not sure how this protocol works.
      # Do they recalculate x each time, via a new salt?
      x                 = _hash(salt, p).hex
      s                 = public_b.pow(a + (u * x), n)

      k                 = _hash(s)

      mac               = _hmac(k, salt)

      # step 2
      worker.verify_mac(mac)
    end
  end

  class MITM < SRP::Worker
    attr_accessor :cracked_password

    def exchange_keys(i, public_a)
      @public_a  = public_a
      @dict      = %w(password p4assw0rd passw0rd)

      @s         = rand(2 ** 128) # we'll make this up
      @public_b  = g.pow(b, n)
      @u         = rand(2 ** 128)

      [@s, @public_b, @u]
    end

    def verify_mac(client_mac)
      self.cracked_password =
        @dict.detect do |guess|
          x       = _hash(@s, guess).hex
          v       = g.pow(x, n)
          s       = (public_a * v.pow(@u, n)).pow(b, n)
          k       = _hash(s)

          client_mac == _hmac(k, @s)
        end

      if cracked_password
        "OK"
      else
        "ERROR"
      end
    end
  end

  class Challenge38Test < Test::Unit::TestCase
    N = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"\
      "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374f"\
      "e1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee38"\
      "6bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48"\
      "361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52907"\
      "7096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".hex
    G = 2
    I = "someone@example.com"
    P = "passw0rd"

    def test_challenge_38_simplified_basics
      server   = SRP::Server.new
      client   = SimplifiedClient.new(I, P, N, G)
      client.register(server)

      worker   = SimplifiedWorker.new(server, N, G)

      response = client.login(worker)

      assert_equal response, "OK"
    end

    def test_challenge_38_attack
      server   = SRP::Server.new
      client   = SimplifiedClient.new(I, P, N, G)
      client.register(server)

      worker   = MITM.new(server, N, G)

      client.login(worker)

      assert_equal worker.cracked_password, "passw0rd"
    end
  end
end
