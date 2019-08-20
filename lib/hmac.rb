# https://tools.ietf.org/html/rfc2104
# https://en.wikipedia.org/wiki/HMAC
module HMAC
  module SHA1
    extend self

    BLOCK_SIZE  = 64 # bytes
    OUTPUT_SIZE = 20 # bytes

    def exec(key, msg)
      if key.length > BLOCK_SIZE
        key = _hash(key)
      end

      if key.length < BLOCK_SIZE
        key = _pad(key, BLOCK_SIZE)
      end

      o_key_pad = _fixed_xor(key, 0x5c)
      i_key_pad = _fixed_xor(key, 0x36)

      # _hash(o_key_pad + _hash(i_key_pad + msg))

      # for easier debugging...
      a = i_key_pad + msg
      b = [_hash(a)].pack("H*")
      c = o_key_pad + b
      d = _hash(c)

      d
    end

    def _hash(msg)
      ::SHA1.exec(msg)
    end

    def _pad(key, length)
      missing = length - key.length

      key << ("\x00" * missing)
    end

    def _fixed_xor(string, byte)
      string.bytes.map { |b| b ^ byte }.pack("U*")
    end
  end
end
