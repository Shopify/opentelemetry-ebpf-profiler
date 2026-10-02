def ruby_hot_loop(ms)
  t_end = Process.clock_gettime(Process::CLOCK_MONOTONIC) + ms / 1000.0
  x = 0
  x = (x * 31 + 7) % 1_000_003 while Process.clock_gettime(Process::CLOCK_MONOTONIC) < t_end
  x
end
def ruby_mid; ruby_hot_loop(10); end
def ruby_outer; ruby_mid + 1; end
sink = 0
loop { sink += ruby_outer; sleep 0.15 }
