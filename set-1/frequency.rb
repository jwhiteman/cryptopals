require "pry"

VALID_BYTES = ((48..57).to_a + (65..90).to_a + (97..122).to_a).freeze
FREQUENT    = ["e", "t", "a", "o", "i", "n", "s"].freeze
INFREQUENT  = %w(p b v k j x q z).freeze

def frequency_match_score(plaintext)
  plaintext = plaintext.downcase

  accumulator = Hash.new { |h, k| h[k] = [] }

  sorted =
    plaintext.
    scan(/./).
    reduce(accumulator) do |acc, char|
      acc[char] << 1
      acc
    end.
    sort_by { |k, v| v.length }.
    map(&:first)

  infrequency_score =
    sorted[0..5].
    reduce(0) do |acc, char|
      acc = acc + 1 if INFREQUENT.include?(char)

      acc
    end

  frequency_score =
    sorted[-6..-1].
    reduce(0) do |acc, char|
      acc = acc + 1 if FREQUENT.include?(char)

      acc
    end

  liability_score = 0
  liability_score -= 1 unless sorted.include?(" ")

  liability_score =
    sorted.
      reduce(liability_score) do |acc, char|
        acc -= 1 unless VALID_BYTES.include?(char.bytes.first)

        acc
      end

  infrequency_score + frequency_score + liability_score
end
