require "pry"
require_relative "frequency"

c1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

results =
  (0..255).map do |c|
    h1 = c1.scan(/../)
    h2 = Array.new(h1.length) { c }

    m = h1.zip(h2).map { |l, r| l.hex ^ r }.pack("U*")

    [FrequencyMatch.score(m), m]
  end

puts results.sort.last[1]
