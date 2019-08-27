# https://cryptopals.com/sets/5/challenges/34
require_relative "../test_helper"

module Set5
  class Challenge34Test < Test::Unit::TestCase
    PORT    = 5001
    HOST    = "0.0.0.0"
    VERBOSE = true
    LQUEUE  = 5
    CHUNK   = 1024

    def _start_server
      socket  = Socket.new(:INET, :STREAM)
      address = Socket.pack_sockaddr_in(PORT, HOST)

      socket.setsockopt(:IPPROTO_TCP, :TCP_NODELAY, 1)
      socket.setsockopt(:SOCKET, :REUSEADDR, 1)

      socket.bind(address)

      if VERBOSE
        print "Echo Server listening on #{PORT} (pid #{$$})\n"
      end

      socket.listen(LQUEUE)

      connection, _ = socket.accept

      diffie_start = connection.readpartial(CHUNK)

      p, g, puba =
        diffie_start.
          lines.map do |l|
            l.chomp.split("=").last.to_i
          end

      b       = rand(p)
      pubb    = g.pow(b, p)
      connection.write("B=#{pubb}")
      iv      = OpenSSL::Random.random_bytes(8).unpack("H*")[0]
      s       = puba.pow(b, p)
      s       = OpenSSL::Digest::SHA1.hexdigest(s.to_s)[0...16]

      loop do
        begin
          request  = connection.readpartial(CHUNK)
          c, civ   = request.split(":")
          aes      = OpenSSL::Cipher.new("AES-128-CBC")
          aes.decrypt
          aes.key  = s
          aes.iv   = civ
          request  = aes.update(c) + aes.final

          puts "SERVER RECEIVED: #{request}" if VERBOSE

          aes      = OpenSSL::Cipher.new("AES-128-CBC")
          aes.encrypt
          aes.key  = s
          aes.iv   = iv
          response = aes.update(request) + aes.final

          connection.write("#{response}:#{iv}")
        rescue EOFError
          connection.close
          break
        end
      end
    end

    def _start_client
      socket = Socket.new(:INET, :STREAM)
      addr   = Socket.pack_sockaddr_in(PORT, HOST)
      socket.connect(addr)
      socket
    end

    def _make_request(client, request)
      client.write(request)
      client.readpartial(CHUNK)
    end

    def test_challenge_34
      p = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"\
          "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374f"\
          "e1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee38"\
          "6bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48"\
          "361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52907"\
          "7096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".hex

      server   = Thread.new { _start_server }
      client   = _start_client

      g       = 3
      a       = rand(p)
      puba    = g.pow(a, p)

      pubb    = _make_request(client, "p=#{p}\ng=#{g}\nA=#{puba}")
      pubb    = pubb.chomp.split("=").last.to_i

      iv      = OpenSSL::Random.random_bytes(8).unpack("H*")[0]
      s       = pubb.pow(a, p)
      s       = OpenSSL::Digest::SHA1.hexdigest(s.to_s)[0...16]

      msg     = "this is request 1!"
      aes     = OpenSSL::Cipher.new("AES-128-CBC")
      aes.encrypt
      aes.key = s
      aes.iv  = iv
      req     = aes.update(msg) + aes.final

      res     = _make_request(client, "#{req}:#{iv}")

      aes     = OpenSSL::Cipher.new("AES-128-CBC")
      c, siv  = res.split(":")
      aes.decrypt
      aes.key = s
      aes.iv  = siv
      res     = aes.update(c) + aes.final

      assert_equal res, msg

      # 1. parameterize the start function to take all those constant vars
      # 2. create start client that syncs up w/ main via a queue
      #    start client should be parameterized
      # 3. use a shared data structure (hash?) to record convos
      # 4. use this shared data structure for tests (up to this point)
      # 5. inside of the main test start a middle man that does nothing
      #    but proxy; no extra thread needed; add tests for this
      # 6. complete the middle man logic.

      server.kill
    end
  end
end
