def ruby_hot_loop(ms)
  t_end = Process.clock_gettime(Process::CLOCK_MONOTONIC) + ms / 1000.0
  x = 0
  x = (x * 31 + 7) % 1_000_003 while Process.clock_gettime(Process::CLOCK_MONOTONIC) < t_end
  x
end

def ruby_mid
  ruby_hot_loop(10)
end

def ruby_outer
  ruby_mid + 1
end

def ruby_deep(depth)
  depth.zero? ? ruby_hot_loop(10) : ruby_deep(depth - 1) + 1
end

module RubyMod
  def self.ruby_module_method
    ruby_hot_loop(2)
  end
end

sink = 0
i = 0
loop do
  i += 1
  sink += ruby_outer
  sink += RubyMod.ruby_module_method
  [2].each { |ms| sink += ruby_hot_loop(ms) }
  sink += ruby_deep(200) if (i % 20).zero?
  sleep 0.15
end
