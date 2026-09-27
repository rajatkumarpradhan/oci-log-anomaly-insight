"""Drain-style log template mining (He et al., ICWS 2017), simplified.

Parses raw messages into templates by grouping on token count and first
token, then generalizing divergent positions to <*>. Deterministic and
stdlib-only; good enough for audit-style structured messages.
"""
from __future__ import annotations

from dataclasses import dataclass, field

WILDCARD = "<*>"


@dataclass
class TemplateCluster:
    template: tuple[str, ...]
    count: int = 0
    examples: list[str] = field(default_factory=list)

    @property
    def template_str(self) -> str:
        return " ".join(self.template)


def _tokens(message: str) -> tuple[str, ...]:
    return tuple(message.strip().split())


def _match(template: tuple[str, ...], tokens: tuple[str, ...]) -> bool:
    return len(template) == len(tokens) and all(
        t == WILDCARD or t == x for t, x in zip(template, tokens))


def _merge(a: tuple[str, ...], b: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(x if x == y else WILDCARD for x, y in zip(a, b))


class DrainMiner:
    def __init__(self, max_examples: int = 3):
        self.clusters: list[TemplateCluster] = []
        self.max_examples = max_examples

    def add(self, message: str) -> int:
        """Add a message, return its cluster id.

        Drain heuristic: candidates are clusters with the same token count;
        merge into the most similar one (max equal fixed positions), which
        generalizes divergent positions to wildcards.
        """
        tokens = _tokens(message)
        best_cid, best_score = -1, -1
        for cid, c in enumerate(self.clusters):
            if len(c.template) != len(tokens):
                continue
            # Drain's fixed-depth grouping: same length AND same first token
            if c.template[0] != WILDCARD and c.template[0] != tokens[0]:
                continue
            score = sum(1 for t, x in zip(c.template, tokens)
                        if t != WILDCARD and t == x)
            if score > best_score:
                best_cid, best_score = cid, score
        if best_cid >= 0:
            c = self.clusters[best_cid]
            c.template = _merge(c.template, tokens)
            c.count += 1
            if len(c.examples) < self.max_examples:
                c.examples.append(message)
            return best_cid
        self.clusters.append(TemplateCluster(template=tokens, count=1,
                                             examples=[message]))
        return len(self.clusters) - 1

    def parse_all(self, messages: list[str]) -> list[int]:
        return [self.add(m) for m in messages]
