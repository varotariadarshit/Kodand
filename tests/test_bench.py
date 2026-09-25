from importlib.resources import files

from kodand.bench import run_bench


def _corpus():
    return str(files("kodand").joinpath("builtin_corpus"))


def test_run_bench_default_threshold_is_perfect_on_packaged_corpus():
    res = run_bench(_corpus())
    assert res["score_threshold"] == 45
    o = res["overall"]
    assert o["precision"] == 1.0 and o["recall"] == 1.0


def test_run_bench_threshold_is_configurable_and_affects_recall():
    lenient = run_bench(_corpus(), score_threshold=1)
    strict = run_bench(_corpus(), score_threshold=100)
    assert lenient["score_threshold"] == 1
    assert strict["score_threshold"] == 100
    # an impossibly strict threshold can only match as well as or worse than a lenient one
    assert strict["overall"]["recall"] <= lenient["overall"]["recall"]
