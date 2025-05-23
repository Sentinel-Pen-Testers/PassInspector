import os
import sys
import types

# Ensure the project root is on the import path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Stub external dependencies required during import
sys.modules['tqdm'] = types.ModuleType('tqdm')
sys.modules['tqdm'].tqdm = lambda *args, **kwargs: args[0]

sys.modules['neo4j'] = types.ModuleType('neo4j')
sys.modules['neo4j'].GraphDatabase = object

sys.modules['xlsxwriter'] = types.ModuleType('xlsxwriter')

from passinspector.passinspector import convert_to_leetspeak


def test_convert_to_leetspeak_password_variants():
    variants = convert_to_leetspeak("password")
    assert "p@ssword" in variants
    assert "passw0rd" in variants
    assert "pa55word" in variants
