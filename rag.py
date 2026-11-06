"""
rag.py — tiny local retrieval-augmented generation helper.

Builds a TF-IDF index over a small corpus of text files (writeups, KB notes)
and retrieves the most relevant chunks for a query. Used by step4_rag.py to
ground assistant reports in project-specific context.

Usage:
    from rag import RagIndex
    idx = RagIndex.from_paths(["writeups", "README.md"])
    for chunk, score in idx.retrieve("how to handle DDoS", k=3):
        print(score, chunk[:80])
"""
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class RagIndex:
    def __init__(self, chunks: list[str], vectorizer: TfidfVectorizer, matrix):
        self.chunks = chunks
        self.vectorizer = vectorizer
        self.matrix = matrix

    @classmethod
    def from_paths(cls, paths, chunk_size: int = 400):
        texts = []
        for p in paths:
            p = Path(p)
            if p.is_dir():
                for f in sorted(p.rglob("*")):
                    if f.is_file() and f.suffix in {".md", ".txt", ".rst"}:
                        texts.append(f.read_text(errors="ignore"))
            elif p.is_file():
                texts.append(p.read_text(errors="ignore"))
        chunks = []
        for t in texts:
            words = t.split()
            for i in range(0, len(words), chunk_size // 5):
                chunk = " ".join(words[i:i + chunk_size // 5])
                if len(chunk) > 60:
                    chunks.append(chunk)
        if not chunks:
            chunks = [""]
        vec = TfidfVectorizer(stop_words="english", max_features=4000)
        mat = vec.fit_transform(chunks)
        return cls(chunks, vec, mat)

    def retrieve(self, query: str, k: int = 4) -> list[tuple[str, float]]:
        if not query.strip():
            return []
        q = self.vectorizer.transform([query])
        sims = cosine_similarity(q, self.matrix).ravel()
        order = np.argsort(sims)[::-1][:k]
        return [(self.chunks[i], float(sims[i])) for i in order if sims[i] > 0]
