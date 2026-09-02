from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiment import CASES, MECHANISMS, NonCooperativeSink, ROOT_SEED, run_one, validate_record  # noqa: E402


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="oasi-s6-test-"))

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def run_case(self, mechanism: str, case: str):
        return run_one(mechanism, case, 1, ROOT_SEED + 1, self.base)

    def test_exact_surface(self):
        self.assertEqual(len(MECHANISMS), 5)
        self.assertEqual(len(CASES), 10)

    def test_sink_api_has_no_idempotency_key_or_query(self):
        self.assertEqual(NonCooperativeSink.apply.__code__.co_argcount, 2)
        self.assertFalse(hasattr(NonCooperativeSink, "query"))
        self.assertFalse(hasattr(NonCooperativeSink, "deduplicate"))

    def test_b3_cannot_deduplicate_post_effect_ambiguity(self):
        b3 = self.run_case("B3_IDEMPOTENT_UNAVAILABLE", "ack_lost_after_effect")
        oasi = self.run_case("OASI", "ack_lost_after_effect")
        self.assertEqual(b3["effect_count"], 2)
        self.assertTrue(b3["double_effect"])
        self.assertEqual(oasi["effect_count"], 1)
        self.assertFalse(oasi["double_effect"])

    def test_oasi_pre_effect_tradeoff_is_visible(self):
        b3 = self.run_case("B3_IDEMPOTENT_UNAVAILABLE", "disconnect_before_effect")
        oasi = self.run_case("OASI", "disconnect_before_effect")
        self.assertEqual(b3["effect_count"], 1)
        self.assertEqual(oasi["effect_count"], 0)
        self.assertTrue(oasi["delivery_lost"])

    def test_replay_discriminates_state(self):
        self.assertTrue(self.run_case("B0_DIRECT", "replay")["double_effect"])
        self.assertTrue(self.run_case("B1_AUTH_STATELESS", "replay")["double_effect"])
        self.assertFalse(self.run_case("B2_AT_LEAST_ONCE", "replay")["double_effect"])
        self.assertFalse(self.run_case("B3_IDEMPOTENT_UNAVAILABLE", "replay")["double_effect"])
        self.assertFalse(self.run_case("OASI", "replay")["double_effect"])

    def test_red_green_mutant_is_rejected(self):
        green = self.run_case("OASI", "nominal")
        self.assertEqual(validate_record(green), [])
        mutant = dict(green, effect_count=2, double_effect=True)
        self.assertIn("OASI_DOUBLE_EFFECT", validate_record(mutant))

    def test_independent_verifier_does_not_import_experiment(self):
        source = (ROOT / "verify_results.py").read_text(encoding="utf-8")
        self.assertNotIn("import experiment", source)
        self.assertNotIn("from experiment", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
