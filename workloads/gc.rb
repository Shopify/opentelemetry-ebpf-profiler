# Reproducible GC workload for profiler VM-layout regression cores.
# No network, credentials, external gems, or application data.
def gc_inner
  objects = Array.new(20_000) { Object.new }
  GC.start(full_mark: true, immediate_sweep: true)
  objects.size
end

def gc_middle
  gc_inner
end

def gc_outer
  gc_middle
end

loop do
  gc_outer
  sleep 0.05
end
