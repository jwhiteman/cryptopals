# https://cryptopals.com/sets/5/challenges/37
require_relative "../test_helper"

module Set5
  class Challenge37Test < Test::Unit::TestCase
    N = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"\
      "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374f"\
      "e1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee38"\
      "6bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48"\
      "361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52907"\
      "7096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".hex
    G = 2
    I = "someone@example.com"
    P = "some-password"

    # In each case, S reduces to 0 on the server side, when we send over a bunk
    # A. All we have to do is anticipate this when we calculate our local S,
    # and we can login.
    class EvilClient1 < SRP::Client
      def login(worker)
        _a              = rand(n)

        # step 1
        salt, public_b  = worker.exchange_keys(@i, 0)

        _u              = _hash(0, public_b).hex
        s               = 0
        k               = _hash(s)
        mac             = _hmac(k, salt)

        # step 2
        worker.verify_mac(mac)
      end
    end

    class EvilClient2 < SRP::Client
      def login(worker)
        _a              = rand(n)

        # step 1
        salt, public_b  = worker.exchange_keys(@i, n)

        _u              = _hash(n, public_b).hex
        s               = 0
        k               = _hash(s)
        mac             = _hmac(k, salt)

        # step 2
        worker.verify_mac(mac)
      end
    end

    class EvilClient3 < SRP::Client
      def login(worker)
        _a              = rand(n)

        # step 1
        salt, public_b  = worker.exchange_keys(@i, n ** 2)

        _u              = _hash(n ** 2, public_b).hex
        s               = 0
        k               = _hash(s)
        mac             = _hmac(k, salt)

        # step 2
        worker.verify_mac(mac)
      end
    end

    def setup
      @server   = SRP::Server.new
      @client   = SRP::Client.new(I, P, N, G)
      @client.register(@server)

      @worker   = SRP::Worker.new(@server, N, G)

    end

    def test_challenge_37_login_with_zero
      attacker = EvilClient1.new(I, "bogus-password", N, G)
      response = attacker.login(@worker)

      assert_equal response, "OK"
    end

    def test_challenge_37_login_with_n
      attacker = EvilClient2.new(I, "bogus-password", N, G)
      response = attacker.login(@worker)

      assert_equal response, "OK"
    end

    def test_challenge_37_login_with_multiple_of_n
      # failed attack...
      failed_attacker =
        SRP::Client.new("attacker@fubar.net", "blah", N, G)
      failed_attacker.register(@server)
      failed_attacker.instance_variable_set(:@i, I)
      response = failed_attacker.login(@worker)
      assert_equal response, "ERROR"

      # successful attack
      successful_attacker = EvilClient3.new(I, "bogus-password", N, G)
      response = successful_attacker.login(@worker)
      assert_equal response, "OK"
    end
  end
end
