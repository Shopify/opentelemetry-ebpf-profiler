# Synthetic workload only: no application data or credentials.
class Ruby41Fixture
  def self.outer
    middle
  end

  def self.middle
    inner
  end

  def self.inner
    value = (1..100).inject(0) { |sum, item| sum + item }
    raise 'wrong result' unless value == 5050
    sleep(0.002)
    value
  end
end

200.times { Ruby41Fixture.outer }
jit = if defined?(RubyVM::ZJIT) && RubyVM::ZJIT.enabled?
  {zjit: true, stats: RubyVM::ZJIT.stats}
elsif defined?(RubyVM::YJIT) && RubyVM::YJIT.enabled?
  {yjit: true, stats: RubyVM::YJIT.runtime_stats}
else
  {interpreter: true}
end
File.write(ARGV.fetch(0), "#{RUBY_DESCRIPTION}\n#{RUBY_REVISION}\n#{jit.inspect}\n")
loop { Ruby41Fixture.outer }
