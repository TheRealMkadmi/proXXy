from __future__ import annotations

import time
from typing import Optional

from rbloom import Bloom


class TimeWindowBloom:
    """
    Generational time-window Bloom filter.

    Maintains G slices of equal duration covering a full window (e.g., 1 hour).
    Insertions go to the current slice. Membership checks search all slices.
    As time advances, the oldest slice is discarded and a fresh one is created.
    """

    def __init__(
        self,
        window_seconds: float = 3600.0,
        slices: int = 4,
        capacity_per_slice: int = 100_000,
        error_rate: float = 0.01,
    ) -> None:
            self.window_seconds = max(1.0, float(window_seconds))
            self.slices = max(1, int(slices))
            self.slice_seconds = self.window_seconds / self.slices
            self.capacity_per_slice = max(1, int(capacity_per_slice))
            self.error_rate = float(error_rate)
            self._filters = [Bloom(self.capacity_per_slice, self.error_rate) for _ in range(self.slices)]
            self._epoch = time.monotonic()
            self._current_index = 0

    def _advance(self, now: Optional[float] = None) -> None:
        t = time.monotonic() if now is None else float(now)
        elapsed = t - self._epoch
        if elapsed < self.slice_seconds:
            return
        steps = int(elapsed // self.slice_seconds)
        if steps <= 0:
            return
        for _ in range(min(steps, self.slices)):
            self._current_index = (self._current_index + 1) % self.slices
            # Drop the oldest by replacing it with a new empty filter
            self._filters[self._current_index] = Bloom(self.capacity_per_slice, self.error_rate)
        # Move epoch forward by whole steps to avoid drift
        self._epoch += steps * self.slice_seconds

    def _normalize_key(self, key: str):
        return key

    def add(self, key: str) -> None:
            self._advance()
            k = self._normalize_key(key)
            self._filters[self._current_index].add(k)

    def contains(self, key: str) -> bool:
        self._advance()
        k = self._normalize_key(key)
        for bf in self._filters:
            if k in bf:
                return True
        return False
