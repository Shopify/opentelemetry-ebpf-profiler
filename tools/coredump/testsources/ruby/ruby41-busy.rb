# Synthetic CPU-bound fixture; intended to be captured in generated machine code.
class Ruby41Busy
  def self.outer(limit)
    middle(limit)
  end

  def self.middle(limit)
    inner(limit)
  end

  def self.inner(limit)
    index = 0
    value = 0
    while index < limit
      value = (value + index) & 0x7fff
      index += 1
    end
    value
  end
end

200.times { Ruby41Busy.outer(1000) }
stats = RubyVM::ZJIT.enabled? ? RubyVM::ZJIT.stats : RubyVM::YJIT.runtime_stats
File.write(ARGV.fetch(0), "#{RUBY_DESCRIPTION}\n#{stats.inspect}\n")
loop { Ruby41Busy.outer(1_000_000) }
