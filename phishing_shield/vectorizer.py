# Compatibility shim for legacy pickles that reference top-level module 'vectorizer'
# This re-exports symbols from backend.nlp_engine.vectorizer so joblib can locate them
from backend.nlp_engine.vectorizer import _tokenize_no_clean, _identity, EnhancedVectorizer

__all__ = ["_tokenize_no_clean", "_identity", "EnhancedVectorizer"]
