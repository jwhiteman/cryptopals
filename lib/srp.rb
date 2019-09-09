module SRP
  K = 3

  module CommonHelpers
    def _hash(*args)
      OpenSSL::Digest::SHA256.hexdigest(
        args.map(&:to_s).reduce(:+)
      )
    end

    def _hmac(k, salt)
      OpenSSL::HMAC.hexdigest("SHA256", k.to_s, salt.to_s)
    end
  end

  class Server
    attr_reader :db

    def initialize
      @db = {}
    end

    def register(i, s, v)
      db[i] = { s: s, v: v }
    end

    def lookup(i)
      db[i]
    end
  end

  class Worker
    include CommonHelpers

    attr_reader :server
    attr_reader :n
    attr_reader :g
    attr_reader :b
    attr_reader :public_b
    attr_reader :public_a
    attr_reader :i
    attr_reader :s
    attr_reader :v

    def initialize(server, n, g)
      @server = server
      @n      = n
      @g      = g
      @b      = rand(n)
    end

    def exchange_keys(i, public_a)
      @public_a  = public_a
      @i         = server.lookup(i)
      @s         = @i[:s]
      @v         = @i[:v]
      @public_b  = (K * v) + g.pow(b, n)

      [@s, @public_b]
    end

    def verify_mac(client_mac)
      u       = _hash(public_a, public_b).hex
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

  class Client
    include CommonHelpers

    attr_reader :i
    attr_reader :p
    attr_reader :n
    attr_reader :g
    attr_reader :x
    attr_reader :s
    attr_reader :v

    def initialize(i, p, n, g)
      @i      = i                  # identifier (email)
      @p      = p                  # password
      @n      = n                  # large prime number
      @g      = g                  # generator
    end

    def register(server)
      @s      = rand(n)            # salt
      @x      = _hash(@s, @p).hex  # ...some intermediate value
      @v      = g.pow(x, n)        # verifier

      server.register(@i, @s, @v)
    end

    def login(worker)
      a              = rand(n)
      public_a       = g.pow(a, n)

      # step 1
      salt, public_b = worker.exchange_keys(@i, public_a)

      u              = _hash(public_a, public_b).hex
      s              = (public_b - K * g.pow(x, n)).pow(a + u * x, n)
      k              = _hash(s)
      mac            = _hmac(k, salt)

      # step 2
      worker.verify_mac(mac)
    end
  end
end
