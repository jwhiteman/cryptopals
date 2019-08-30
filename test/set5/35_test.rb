# https://cryptopals.com/sets/5/challenges/35
require_relative "../test_helper"

require "ffi-rzmq"

module Set5
  class Challenge35Test < Test::Unit::TestCase
    VERBOSE   = false
    DELIMITER = "-" * 8

    def start_mitm(msgs)
      context = ZMQ::Context.new

      client = context.socket(ZMQ::ROUTER)
      server = context.socket(ZMQ::DEALER)

      client.bind("tcp://*:5559")
      server.bind("tcp://*:5560")

      poller = ZMQ::Poller.new
      poller.register(client, ZMQ::POLLIN)
      poller.register(server, ZMQ::POLLIN)

      # puts client sends over p & g
      client.recv_strings(messages = [])
      p, _ = messages.last.split(DELIMITER).map(&:to_i)
      badg = yield p
      messages[2] = [p, badg].join(DELIMITER)

      # send the bad g to the server
      server.send_strings(messages)

      # get it ack'd back
      server.recv_strings(messages = [])
      p, _ = messages.last.split(DELIMITER).map(&:to_i)
      messages[2] = [p, badg].join(DELIMITER)

      # send the bad g to the client
      client.send_strings(messages)

      # get A from the client
      client.recv_strings(messages = [])

      # send A to the server...
      server.send_strings(messages)

      # get B from the server
      server.recv_strings(messages = [])

      # send it to the client...
      client.send_strings(messages)

      # if g = 1:
      #   A = (1 ** a) % p = 1 % p = 1
      #   B = (1 ** b) % p = 1 % p = 1
      #   s = (B ** a) % p = (1 ** a) % p = 1 % p = 1
      #
      # if g = p:
      #   A = (p ** a) % p = 0
      #   B = (p ** a) % p = 0
      #   s = (0 ** a) % p = 0 % p = 0
      #
      # if g = p - 1:
      #   A = ((p - 1) ** a) % p
      #     if p is a large prime number, it's odd
      #     ...and then p-1 is even
      #     and it appears that ((p - a) ** a) % p is 1 in that case.
      #
      #   if A/B are equal to 1, then s will end up as 1, I think.
      s =
        if badg == 1
          OpenSSL::Digest::SHA1.hexdigest("1")[0...16]
        elsif badg == p.to_i
          OpenSSL::Digest::SHA1.hexdigest("0")[0...16]
        elsif badg == p.to_i - 1
          OpenSSL::Digest::SHA1.hexdigest("1")[0...16]
        else
          raise "shouldn't reach here"
        end

      loop do
        poller.poll(:blocking)
        poller.readables.each do |socket|
          if socket == client
            client.recv_strings(messages = [])
            request = messages.last

            c, iv   = request.split(DELIMITER)
            aes     = OpenSSL::Cipher.new("AES-128-CBC")
            aes.decrypt
            aes.key = s
            aes.iv  = iv
            rreq    = aes.update(c) + aes.final

            puts "MITM RECEIVED FROM UNSUSPECTING CLIENT: #{rreq}" if VERBOSE
            msgs[:mitm_client] = rreq

            server.send_strings(messages)
          elsif socket == server
            server.recv_strings(messages = [])
            response = messages.last

            c, iv   = response.split(DELIMITER)
            aes     = OpenSSL::Cipher.new("AES-128-CBC")
            aes.decrypt
            aes.key = s
            aes.iv  = iv
            rres    = aes.update(c) + aes.final

            puts "MITM RECEIVED FROM UNSUSPECTING SERVER: #{rres}" if VERBOSE
            msgs[:mitm_server] = rres

            client.send_strings(messages)

            break # make it easier for the program to terminate
          else
            raise "error"
          end
        end
      end

      client.close
      server.close
      context.terminate
    end

    def start_server(msgs)
      context = ZMQ::Context.new

      server = context.socket(ZMQ::REP)
      server.connect("tcp://localhost:5560")

      server.recv_string(p_and_g = "")
      p, g = p_and_g.split(DELIMITER).map(&:to_i)  # read the requested p & g

      server.send_string([p, g].join(DELIMITER))   # lazily ack them

      server.recv_string(puba = "")                # get A
      puba = puba.to_i

      b       = rand(p)
      pubb    = g.pow(b, p)                        # calculate B
      server.send_string(pubb.to_s)                # send it over...

      iv      = OpenSSL::Random.random_bytes(8).unpack("H*")[0]
      s       = puba.pow(b, p)
      s       = OpenSSL::Digest::SHA1.hexdigest(s.to_s)[0...16]

      loop do
        server.recv_string(request = "")
        c, civ  = request.split(DELIMITER).map(&:chomp)
        aes      = OpenSSL::Cipher.new("AES-128-CBC")
        aes.decrypt
        aes.key  = s
        aes.iv   = civ
        request  = aes.update(c) + aes.final

        msgs[:server_req] = request

        aes      = OpenSSL::Cipher.new("AES-128-CBC")
        aes.encrypt
        aes.key  = s
        aes.iv   = iv
        response = aes.update(request.reverse) + aes.final

        server.send_string([response, iv].join(DELIMITER))
      end

      server.close
      context.terminate
    end

    def start_client(msgs)
      context = ZMQ::Context.new

      client = context.socket(ZMQ::REQ)
      client.connect("tcp://localhost:5559")

      p = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"\
          "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374f"\
          "e1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee38"\
          "6bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48"\
          "361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52907"\
          "7096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".hex

      g       = 3
      a       = rand(p)

      client.send_string([p, g].join(DELIMITER)) # request p and g

      client.recv_string(p_and_g = "")           # get negotiated p and g
      p, g = p_and_g.split(DELIMITER).map(&:to_i)

      puba    = g.pow(a, p)                      # calculate A

      client.send_string(puba.to_s)              # send it over

      client.recv_string(pubb = "")              # get B
      pubb    = pubb.to_i

      iv      = OpenSSL::Random.random_bytes(8).unpack("H*")[0]
      s       = pubb.pow(a, p)
      s       = OpenSSL::Digest::SHA1.hexdigest(s.to_s)[0...16]

      msg     = "this is request 1!"
      aes     = OpenSSL::Cipher.new("AES-128-CBC")
      aes.encrypt
      aes.key = s
      aes.iv  = iv
      req     = aes.update(msg) + aes.final

      client.send_string([req, iv].join(DELIMITER))
      client.recv_string(res = "")

      aes     = OpenSSL::Cipher.new("AES-128-CBC")
      c, siv  = res.split(DELIMITER).map(&:chomp)
      aes.decrypt
      aes.key = s
      aes.iv  = siv
      res     = aes.update(c) + aes.final

      msgs[:client_response] = res

      client.close
      context.terminate
    end

    def uno
      msgs    = {}

      _mitm   = Thread.new do
        start_mitm(msgs) { |_p| 1 }
      end

      _server = Thread.new { start_server(msgs) }
      client  = Thread.new { start_client(msgs) }

      client.join

      assert_equal msgs, {
        mitm_client:     "this is request 1!",
        server_req:      "this is request 1!",
        mitm_server:     "!1 tseuqer si siht",
        client_response: "!1 tseuqer si siht"
      }
    end

    def dos
      msgs    = {}

      _mitm   = Thread.new do
        start_mitm(msgs) { |p| p }
      end

      _server = Thread.new { start_server(msgs) }
      client  = Thread.new { start_client(msgs) }

      client.join

      assert_equal msgs, {
        mitm_client:     "this is request 1!",
        server_req:      "this is request 1!",
        mitm_server:     "!1 tseuqer si siht",
        client_response: "!1 tseuqer si siht"
      }
    end

    def tres
      msgs    = {}

      _mitm   = Thread.new do
        start_mitm(msgs) { |p| p - 1 }
      end

      _server = Thread.new { start_server(msgs) }
      client  = Thread.new { start_client(msgs) }

      client.join

      assert_equal msgs, {
        mitm_client:     "this is request 1!",
        server_req:      "this is request 1!",
        mitm_server:     "!1 tseuqer si siht",
        client_response: "!1 tseuqer si siht"
      }
    end

    # run either uno, dos or tres to test
    # only running one at a time because zeromq seems to be fussy on how
    # sockets are destroyed and re-created
    def test_challenge_35
      # uno
      # dos
      tres
    end
  end
end
