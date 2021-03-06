# Adapted from https://rosettacode.org/wiki/SHA-1
# and from https://gist.github.com/tstevens/925415/6dd06487a8fcd5c4c3c9c18ee32eb60e2917b815
require 'stringio'
module SHA1
  extend self

  def exec(string, starting_state = nil, prepadded = false)
    mask = 0xffffffff
    s    = proc { |n, x| ((x << n) & mask) | (x >> (32 - n)) }
    k    = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6].freeze
    f    = [
      proc { |b, c, d| (b & c) | (b.^(mask) & d) },
      proc { |b, c, d| b ^ c ^ d },
      proc { |b, c, d| (b & c) | (b & d) | (c & d) },
      proc { |b, c, d| b ^ c ^ d },
    ].freeze

    # initial hash
    h =
      starting_state || [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

    if !prepadded
      bit_string = string.unpack('B*')
      message_length = string.unpack('B*')[0].length
      bit_string[0] += "1"
      until ((448 % 512) == (bit_string[0].length % 512)) do
        bit_string[0] += "0"
      end
      bit_string[0] += (("0" * (64 - message_length.to_s(2).length)) + message_length.to_s(2))

      string = bit_string.pack('B*')
    end

    io = StringIO.new(string)
    block = ""

    while io.read(64, block)
=begin
      if h == [114902420, 715287137, 3189294050, 737254332, 2833066845]
        puts "earlier state found..."
      else
        puts "looping..."
      end
=end

      w = block.unpack("N16")

      # Process block.
      (16..79).each {|t| w[t] = s[1, w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]]}

      a, b, c, d, e = h
      t = 0
      4.times do |i|
        20.times do
          temp = (s[5, a] + f[i][b, c, d] + e + w[t] + k[i]) & mask
          a, b, c, d, e = temp, a, s[30, b], c, d
          t += 1
        end
      end

      [a,b,c,d,e].each_with_index {|x,i| h[i] = (h[i] + x) & mask}
    end

    # I fucked this up...should be raw bytes be default. live and learn.
    h.pack("N5").unpack("H*").first
  end
end
