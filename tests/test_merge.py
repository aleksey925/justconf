from justconf import merge


class TestMerge:
    def test_merge__empty_dicts__returns_empty(self):
        # act
        result = merge({}, {})

        # assert
        assert result == {}

    def test_merge__no_arguments__returns_empty(self):
        # act
        result = merge()

        # assert
        assert result == {}

    def test_merge__single_dict__returns_copy(self):
        # arrange
        original = {'a': 1, 'b': 2}

        # act
        result = merge(original)

        # assert
        assert result == {'a': 1, 'b': 2}
        assert result is not original

    def test_merge__flat_dicts__later_wins(self):
        # act
        result = merge({'a': 1, 'b': 2}, {'b': 3, 'c': 4})

        # assert
        assert result == {'a': 1, 'b': 3, 'c': 4}

    def test_merge__nested_dicts__deep_merge(self):
        # act
        result = merge(
            {'db': {'host': 'localhost', 'port': 5432}},
            {'db': {'port': 3306}},
        )

        # assert
        assert result == {'db': {'host': 'localhost', 'port': 3306}}

    def test_merge__lists__overwrite(self):
        # act
        result = merge({'tags': ['a', 'b']}, {'tags': ['c']})

        # assert
        assert result == {'tags': ['c']}

    def test_merge__scalar_to_dict__dict_wins(self):
        # act
        result = merge({'db': 'sqlite:///db.sqlite'}, {'db': {'host': 'localhost'}})

        # assert
        assert result == {'db': {'host': 'localhost'}}

    def test_merge__dict_to_scalar__scalar_wins(self):
        # act
        result = merge({'db': {'host': 'localhost'}}, {'db': 'sqlite:///db.sqlite'})

        # assert
        assert result == {'db': 'sqlite:///db.sqlite'}

    def test_merge__multiple_dicts__priority_order(self):
        # act
        result = merge(
            {'a': 1, 'b': 1, 'c': 1},
            {'b': 2, 'c': 2},
            {'c': 3},
        )

        # assert
        assert result == {'a': 1, 'b': 2, 'c': 3}

    def test_merge__deeply_nested__recursive_merge(self):
        # act
        result = merge(
            {'level1': {'level2': {'level3': {'a': 1, 'b': 1}}}},
            {'level1': {'level2': {'level3': {'b': 2, 'c': 2}}}},
        )

        # assert
        assert result == {'level1': {'level2': {'level3': {'a': 1, 'b': 2, 'c': 2}}}}

    def test_merge__mixed_types_in_nested__correct_behavior(self):
        # act
        result = merge(
            {'config': {'debug': True, 'db': {'host': 'localhost'}}},
            {'config': {'debug': False, 'db': {'port': 5432}}},
        )

        # assert
        assert result == {'config': {'debug': False, 'db': {'host': 'localhost', 'port': 5432}}}

    def test_merge__none_values__preserved(self):
        # act
        result = merge({'a': 1}, {'a': None})

        # assert
        assert result == {'a': None}

    def test_merge__empty_dict_value__preserved(self):
        # act
        result = merge({'a': {'b': 1}}, {'a': {}})

        # assert
        assert result == {'a': {'b': 1}}
