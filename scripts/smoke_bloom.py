import sys
import time
sys.path.append(r"c:\Users\Wahib\Desktop\proXXy\src")
from bloom import TimeWindowBloom

bf = TimeWindowBloom(window_seconds=10, slices=2, capacity_per_slice=10, error_rate=0.01)
assert not bf.contains("hello"), "unexpected membership before add"
bf.add("hello")
assert bf.contains("hello"), "expected membership after add"
print("TimeWindowBloom smoke test passed")
