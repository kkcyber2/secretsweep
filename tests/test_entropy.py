from secretsweep.entropy import looks_random, shannon_entropy


def test_entropy_of_a_single_character_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_of_uniform_distribution_is_log2_of_alphabet():
    assert abs(shannon_entropy("abcd") - 2.0) < 1e-9


def test_random_looking_string_is_detected():
    assert looks_random("aB3xK9mQ2pL7vN4zR8tW1yC6") is True


def test_english_sentence_is_not_random():
    assert looks_random("the quick brown fox jumps over") is False


def test_short_string_is_not_random():
    assert looks_random("aB3xK9") is False


def test_single_character_class_is_not_random():
    assert looks_random("abcdefghijklmnopqrstuvwx") is False


def test_repeated_character_is_not_random():
    assert looks_random("a" * 40) is False
