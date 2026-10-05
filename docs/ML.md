# Learning and ML status

The application currently trains a scikit-learn Random Forest on a deterministic set of synthetic behavior scenarios and classifies each request using features engineered from persistent event history. K-Means produces descriptive groups when multiple profiles exist. Synthetic model labels and inferred group descriptions are triage hints, not ground truth; no independent accuracy claim is made. SQLite stores events, profiles and policy state, while JSONL remains available for compatibility.

The `anomaly` hook in the original application remains optional and unset. The Random Forest currently uses synthetic seed cases, not labeled real attacks. A future retrainer needs curated, provenance-documented labeled examples, train/validation separation, class coverage, evaluation and safe fallback behavior before performance claims are made. Do not train on rule-generated labels and then present agreement with those rules as independent model validation.
