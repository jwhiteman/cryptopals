def t(rs = 11)
  a = (2 ** 32) - rand(2 ** 30)

  b = a >> rs
  c = a ^ b

  puts a
  puts

  puts (as = sprintf("%032b", a)) + ": A"
  puts sprintf("%032b", b) + ": x (A >> #{rs})"
  puts "-" * 32
  puts sprintf("%032b", c) + ": C (x ^ A)"
  puts

  d = c >> rs
  e = c ^ d

  puts sprintf("%032b", c) + ": C"
  puts sprintf("%032b", d) + ": y (C >> #{rs})"
  puts "-" * 32
  puts (es = sprintf("%032b", e)) + ": A? (y ^ C)"

  puts

  divergence =
    (0...as.length).
    detect do |idx|
      as[idx] != es[idx]
    end

  puts
  puts "They diverge at index: #{divergence || 'never'}"

  if divergence
    puts as.insert(divergence, '_')
    puts es.insert(divergence, '_')
  else
    puts as
    puts es
  end

  divergence
end

# TODO: start here...
def t(rs = 15, m = 0x9D2C_5680)
  m = 0x9D2C_5680
  a = rand(2 ** 32)
  b = (a << rs)
  c = b & m
  d = c ^ a

  d = d
  e = (d << rs)
  f = e & m
  g = f ^ d

  puts a
  puts

  justify = 32 + rs

  puts (as = sprintf("%0#{justify}b", a)) + ": a"
  puts sprintf("%0#{justify}b", c) + ": (a << #{rs}) & 0x#{m.to_s(16).upcase}"
  puts "-" * justify
  puts sprintf("%0#{justify}b", d) + ": d (c ^ a)"

  puts

  puts sprintf("%0#{justify}b", d) + ": d"
  puts sprintf("%0#{justify}b", f) + ": (d << #{rs}) & 0x#{m.to_s(16).upcase}"
  puts "-" * justify
  puts (gs = sprintf("%0#{justify}b", g)) + ": g (f ^ d)"

  divergence =
    (0...as.length).
    detect do |idx|
      as[idx] != gs[idx]
    end

  puts
  if divergence
    puts as.insert(divergence, '_') + ": a"
    puts gs.insert(divergence, '_') + ": g"
  else
    puts as + ": a"
    puts gs + ": g"
  end

  divergence
end

# y = y ^ ((y << S) & B)
def t(rs = 7)
  m = 0x9D2C_5680

  a = (2 ** 32) - rand(2 ** 30)
  b = a << rs
  c = b & m
  d = a ^ c

  puts a
  puts

  puts (as = sprintf("%039b", a)) + ": a"
  puts sprintf("%039b", b) + ": b (a << #{rs})"
  puts sprintf("%039b", c) + ": c (b & 0x9D2C_5680)"
  puts "-" * 39
  puts sprintf("%039b", d) + ": d (c ^ a)"
  puts

  d = d # putting here for symmetry
  e = d << rs
  f = e & m
  g = f ^ d

  puts sprintf("%039b", d) + ": d"
  puts sprintf("%039b", e) + ": e (d << #{rs})"
  puts sprintf("%039b", f) + ": f (e & 0x9D2C_5680)"
  puts "-" * 39
  puts (gs = sprintf("%039b", g)) + ": g (f ^ d)"
  puts

  puts sprintf("%039b", m) + ": m"
  puts sprintf("%039b", c) + ": c (b & 0x9D2C_5680)"
  puts sprintf("%039b", m - c) + ": m - c: #{m-c}"
  puts sprintf("%039b", m ^ c) + ": m ^ c: #{m^c}"
  puts sprintf("%039b", m & c) + ": m & c == c? (#{m & c == c})"
  puts

  puts sprintf("%039b", e) + ": e"
  puts sprintf("%039b", c) + ": c"
  puts sprintf("%039b", e - c) + ": e - c: #{e-c}"
  puts sprintf("%039b", e ^ c) + ": e ^ c: #{e^c}"
  puts sprintf("%039b", e & c) + ": e & c: #{e & c})"
  puts

  divergence =
    (0...as.length).
    detect do |idx|
      as[idx] != gs[idx]
    end

  puts "They diverge at index: #{divergence || 'never'}"

  if divergence
    puts as.insert(divergence, '_')
    puts gs.insert(divergence, '_')
  else
    puts as
    puts gs
  end

  divergence
end
