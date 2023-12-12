from json import load


class JSONConfigLoader:
    @staticmethod
    def load(filename: str) -> dict:
        with open(filename, 'r', encoding='utf-8') as f:
            return load(f)
