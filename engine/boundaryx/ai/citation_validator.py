from typing import List, Set

from boundaryx.ai.schemas import AnalysisOutput


class CitationValidationError(ValueError):
    pass


class CitationValidator:
    """
    Verifies that all evidence IDs referenced in AI outputs actually exist
    in the provided context / local database.
    Strips hallucinated IDs and appends an audit warning to limitations.
    """

    @staticmethod
    def validate_and_filter(output: AnalysisOutput, valid_evidence_ids: Set[str]) -> AnalysisOutput:
        valid_set = set(valid_evidence_ids)
        hallucinated_ids = set()

        # Validate facts
        for fact in output.facts:
            filtered_eids = []
            for eid in fact.evidence_ids:
                if eid in valid_set:
                    filtered_eids.append(eid)
                else:
                    hallucinated_ids.add(eid)
            fact.evidence_ids = filtered_eids

        # Validate hypotheses
        for hyp in output.hypotheses:
            filtered_supp = []
            for eid in hyp.supporting_evidence_ids:
                if eid in valid_set:
                    filtered_supp.append(eid)
                else:
                    hallucinated_ids.add(eid)
            hyp.supporting_evidence_ids = filtered_supp

            filtered_counter = []
            for eid in hyp.counter_evidence_ids:
                if eid in valid_set:
                    filtered_counter.append(eid)
                else:
                    hallucinated_ids.add(eid)
            hyp.counter_evidence_ids = filtered_counter

        if hallucinated_ids:
            warning = f"Notice: Filtered out unverified/hallucinated evidence citations: {sorted(hallucinated_ids)}"
            output.limitations.append(warning)

        return output
