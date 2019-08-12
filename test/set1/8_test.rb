# https://cryptopals.com/sets/1/challenges/8
require_relative "../test_helper"

module Set1
  module Challenge8
    def calculate_distance(s1, s2)
      b1 = s1.unpack("b*").first.scan(/./)
      b2 = s2.unpack("b*").first.scan(/./)

      b1.zip(b2).reduce(0) do |acc, (l, r)|
        acc += 1 if l.to_i != r.to_i
        acc
      end
    end

    # Seems like the avg distance for random strings converges
    # on 4.000.. for some reason.
    # Out of a set of a million, only a few (< 10 ?) blocks
    # will be under 2.5.
    # The smallest I've seen (so far) is 2.18.
    def x(times, size, threshold = 2.5)
      t = Time.now

      results =
        times.times.map do
          block1 = OpenSSL::Random.random_bytes(size)
          block2 = OpenSSL::Random.random_bytes(size)

          calculate_distance(block1, block2) / size.to_f
        end

      puts "Done. Took #{Time.now - t} seconds"

      puts "min: #{results.min}"
      puts "max: #{results.max}"

      avg = results.reduce(&:+) / times.to_f
      puts "avg: #{avg}"

      results.select { |r| r < threshold }
    end
  end

  class Challenge8Test < Test::Unit::TestCase
    include Challenge8

    def test_challenge_8
      blocksize = 16
      raw_data  = IO.read("test/fixtures/challenge-8-data.txt").chomp

      data = raw_data.lines.map do |line|
        line.chomp!
        original = line

        line = line.scan(/../).map { |hex| hex.hex }.pack("C*")

        distances =
          line.
          each_char.
          each_slice(blocksize).
          with_index.
          reduce({ distances: [], previous: [] }) do |acc, (block, idx)|
            block = block.join

            if idx == 0
              acc[:previous] << block
            else
              acc[:previous].each do |previous|
                distance =
                  calculate_distance(previous, block) / blocksize.to_f

                acc[:distances] << distance
              end

              acc[:previous] << block
            end

            acc
          end

        avg_distance = (
          distances[:distances].reduce(&:+) /
            distances[:distances].length.to_f
        )

        [avg_distance, original]
      end

      expected = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2" \
                 "d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af7" \
                 "0dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82" \
                 "bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd5" \
                 "66489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403" \
                 "180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b0" \
                 "6fba186a"

      assert_equal expected, data.min[1]
    end
  end
end
