require "pry"

# this is stupid
module FrequencyMatch
  extend self

  FREQUENT   = ["e", "t", "a", "o", "i", "n", "s", "h", " "].freeze
  INFREQUENT = %w(p b v k j x q z).freeze

  def score(plaintext)
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

    infrequency_score + frequency_score
  end
end
