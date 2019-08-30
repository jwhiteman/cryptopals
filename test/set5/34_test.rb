# https://cryptopals.com/sets/5/challenges/34
#
# I probably should have used ØMQ here. This is stupid byzantine...
#
require_relative "../test_helper"

module Set5
  class Challenge34Test < Test::Unit::TestCase
    VERBOSE   = false   # toggle this for easier debugging
    LQUEUE    = 5
    CHUNK     = 1024
    DELIMITER = "-" * 8

    def _start_mitm(port, host, cntrl, server_port, server_host, msgs)
      socket  = Socket.new(:INET, :STREAM)
      address = Socket.pack_sockaddr_in(port, host)

      socket.setsockopt(:IPPROTO_TCP, :TCP_NODELAY, 1)
      socket.setsockopt(:SOCKET, :REUSEADDR, 1)

      socket.bind(address)

      if VERBOSE
        print "MITM listening on #{port} (pid #{$$})\n"
      end

      socket.listen(LQUEUE)

      real_server = Socket.new(:INET, :STREAM)
      addr   = Socket.pack_sockaddr_in(server_port, server_host)
      real_server.connect(addr)

      cntrl.enq("MITM READY")

      connection, _ = socket.accept

      diffie_start = connection.readpartial(CHUNK)

      p, g, _puba =
        diffie_start.
          lines.map do |l|
            l.chomp.split("=").last.to_i
          end

      # Eve sends p as A
      real_server.write("p=#{p}\ng=#{g}\nA=#{p}")

      # Get B back from the real server
      pubb = real_server.readpartial(CHUNK)
      pubb = pubb.chomp.split("=").last.to_i

      # But give back Alice 'p' instead of 'B'
      connection.write("B=#{p}")

      # In this attack S becomes zero because (p ** n) % p will always be zero.
      s = OpenSSL::Digest::SHA1.hexdigest("0")[0...16]

      loop do
        begin
          request  = connection.readpartial(CHUNK)

          c, iv   = request.split(DELIMITER)
          aes     = OpenSSL::Cipher.new("AES-128-CBC")
          aes.decrypt
          aes.key = s
          aes.iv  = iv
          rreq    = aes.update(c) + aes.final

          puts "MITM RECEIVED FROM UNSUSPECTING CLIENT: #{rreq}" if VERBOSE
          msgs[:mitm_client] = rreq

          real_server.write(request)
          response = real_server.readpartial(CHUNK)

          c, iv   = response.split(DELIMITER)
          aes     = OpenSSL::Cipher.new("AES-128-CBC")
          aes.decrypt
          aes.key = s
          aes.iv  = iv
          rres    = aes.update(c) + aes.final

          puts "MITM RECEIVED FROM UNSUSPECTING SERVER: #{rres}" if VERBOSE
          msgs[:mitm_server] = rres

          connection.write(response)
        rescue EOFError
          connection.close
          break
        end
      end
    end

    def _start_server(port, host, cntrl, msgs)
      socket  = Socket.new(:INET, :STREAM)
      address = Socket.pack_sockaddr_in(port, host)

      socket.setsockopt(:IPPROTO_TCP, :TCP_NODELAY, 1)
      socket.setsockopt(:SOCKET, :REUSEADDR, 1)

      socket.bind(address)

      if VERBOSE
        print "Reversed Echo Server listening on #{port} (pid #{$$})\n"
      end

      socket.listen(LQUEUE)
      cntrl.enq("SERVER READY")

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
          c, civ   = request.split(DELIMITER)
          aes      = OpenSSL::Cipher.new("AES-128-CBC")
          aes.decrypt
          aes.key  = s
          aes.iv   = civ
          request  = aes.update(c) + aes.final

          puts "SERVER RECEIVED: #{request}" if VERBOSE
          msgs[:server_req] = request

          aes      = OpenSSL::Cipher.new("AES-128-CBC")
          aes.encrypt
          aes.key  = s
          aes.iv   = iv
          response = aes.update(request.reverse) + aes.final

          connection.write("#{response}#{DELIMITER}#{iv}")
        rescue EOFError
          connection.close
          break
        end
      end
    end

    def _start_client(port, host, cntrl, msgs)
      client = Socket.new(:INET, :STREAM)
      addr   = Socket.pack_sockaddr_in(port, host)
      client.connect(addr)

      p = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"\
          "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374f"\
          "e1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee38"\
          "6bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48"\
          "361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52907"\
          "7096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".hex

      g       = 3
      a       = rand(p)
      puba    = g.pow(a, p)

      print "CLIENT WAITING..." if VERBOSE
      cntrl.deq
      print "DONE.\n" if VERBOSE

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

      res     = _make_request(client, "#{req}#{DELIMITER}#{iv}")

      aes     = OpenSSL::Cipher.new("AES-128-CBC")
      c, siv  = res.split(DELIMITER)

      aes.decrypt
      aes.key = s
      aes.iv  = siv
      res     = aes.update(c) + aes.final

      msgs[:client_response] = res
    end

    def _make_request(client, request)
      client.write(request)
      client.readpartial(CHUNK)
    end

    def test_challenge_34
      cntrl = Queue.new
      msgs  = {}

      # start server
      server =
        Thread.new do
          _start_server(5001, "0.0.0.0", cntrl, msgs)
        end

      # wait until we receive notice that it's ready
      cntrl.deq

      # start the mitm 'server'
      mitm =
        Thread.new do
          _start_mitm(5000, "0.0.0.0", cntrl, 5001, "127.0.0.1", msgs)
        end

      # and also wait until it's ready...
      cntrl.deq

      # start the client
      client =
        Thread.new do
          _start_client(5000, "127.0.0.1", cntrl, msgs)
        end

      # signal to client to start making requests
      cntrl.enq("CLIENT START")

      client.join

      # assert that each thread received/sent what it should
      assert_equal msgs, {
        mitm_client:     "this is request 1!",
        mitm_server:     "!1 tseuqer si siht",
        server_req:      "this is request 1!",
        client_response: "!1 tseuqer si siht"
      }

      mitm.kill
      server.kill
    end
  end
end
