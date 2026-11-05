"""Retrieval over the curated threat notes in app/knowledge (LangChain retriever + BM25)."""

import re
from functools import lru_cache
from pathlib import Path

from langchain_core.callbacks import CallbackManagerForRetrieverRun
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever
from pydantic import ConfigDict
from rank_bm25 import BM25Okapi

KNOWLEDGE_DIR = Path(__file__).resolve().parents[1] / "knowledge"
_TOKEN = re.compile(r"[a-z0-9]+(?:\.[0-9]+)?")


def _tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


def load_documents(folder: Path = KNOWLEDGE_DIR) -> list[Document]:
    """One document per '## ' heading, so a search returns a section and not a whole file."""
    documents = []
    for path in sorted(folder.glob("*.md")):
        sections = re.split(r"(?m)^## ", path.read_text(encoding="utf-8"))
        for section in sections[1:]:
            title, _, body = section.partition("\n")
            slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
            documents.append(Document(
                page_content=f"{title}\n{body.strip()}",
                metadata={"id": f"{path.stem}/{slug}", "title": title.strip(), "source": path.name},
            ))
    return documents


class ThreatNotesRetriever(BaseRetriever):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    documents: list[Document]
    index: BM25Okapi
    k: int = 3

    @classmethod
    def from_documents(cls, documents: list[Document], k: int = 3) -> "ThreatNotesRetriever":
        return cls(documents=documents, index=BM25Okapi([_tokenize(d.page_content) for d in documents]), k=k)

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun
    ) -> list[Document]:
        terms = _tokenize(query)
        scores = self.index.get_scores(terms)
        # BM25 idf can go to zero on a small corpus, so a shared term also counts as a match.
        ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        hits = [
            self.documents[i] for i in ranked
            if scores[i] > 0 or set(terms) & set(_tokenize(self.documents[i].page_content))
        ]
        return hits[: self.k]


@lru_cache(maxsize=1)
def get_retriever() -> ThreatNotesRetriever:
    return ThreatNotesRetriever.from_documents(load_documents())
