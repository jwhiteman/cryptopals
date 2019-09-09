# https://cryptopals.com/sets/5/challenges/36
require_relative "../test_helper"

module Set5
  class Challenge36Test < Test::Unit::TestCase
    N = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"\
      "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374f"\
      "e1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee38"\
      "6bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48"\
      "361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52907"\
      "7096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".hex
    G = 2
    I = "someone@example.com"
    P = "some-password"

    def test_challenge_36
      server   = SRP::Server.new
      client   = SRP::Client.new(I, P, N, G)
      client.register(server)

      worker   = SRP::Worker.new(server, N, G)

      response = client.login(worker)

      assert_equal response, "OK"
    end
  end
end
