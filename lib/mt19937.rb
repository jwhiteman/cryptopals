class MT19937
  W          = 32
  N          = 624
  M          = 397
  R          = 31
  F          = 1812433253 # 69069

  LOWER_MASK = 0x7FFF_FFFF # (1 << R) - 1
  UPPER_MASK = 0x8000_0000 # ~LOWER_MASK

  U          = 11
  S          = 7
  T          = 15
  L          = 18
  D          = 0xFFFF_FFFF
  B          = 0x9D2C_5680
  C          = 0xEFC6_0000

  A          = 0x9908_B0DF

  attr_accessor :mt
  attr_accessor :index

  def initialize(seed)
    @mt    = []
    @mt[0] = seed

    (1..(N-1)).each do |i|
      @mt[i] =
        (F * (@mt[i-1] ^ (@mt[i-1] >> (W-2))) + i) & 0xFFFF_FFFF
    end

    @index = N
  end

  def rand
    twist if index == N

    y = mt[index]
    y = y ^ (y >> U)
    y = y ^ ((y << S) & B)
    y = y ^ ((y << T) & C)
    y = y ^ (y >> L)
    self.index = index + 1

    y & 0xFFFF_FFFF
  end

  def inspect
    "<PRNG: #{mt[index]}>"
  end

  private

  def twist
    (0..(N-1)).each do |i|
      x  = (mt[i] & UPPER_MASK) + (mt[(i+1) % N] & LOWER_MASK)
      xA = x >> 1
      if x % 2 != 0
        xA = xA ^ A
      end

      self.mt[i] = mt[(i + M) % N] ^ xA
    end

    self.index = 0
  end
end
