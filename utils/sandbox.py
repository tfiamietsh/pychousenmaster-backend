from time import perf_counter_ns
import tracemalloc


class Sandbox:
    @staticmethod
    def parse_testcases(testcases: str) -> dict[str or dict[str, str], str]:
        testcases = eval(testcases)
        for i in range(len(testcases)):
            for key in testcases[i]['input']:
                if type(testcases[i]['input'][key]) is str:
                    testcases[i]['input'][key] = eval(testcases[i]['input'][key])
            if type(testcases[i]['output']) is str:
                testcases[i]['output'] = eval(testcases[i]['output'])
        return testcases

    @staticmethod
    def postedit_code(code: str, method_name: str) -> str:
        return '{}\n_2615074_result = []\nfor testcase in _2615074_testcases:\n\t' \
               '_2615074_result.append({}(**testcase[\'input\']))'.format(code, method_name)

    @staticmethod
    def run(code: str, _locals: dict[str, any]) -> list[any]:
        exec(code, globals(), _locals)
        return _locals['_2615074_result']

    @staticmethod
    def test(code: str, method_name: str, testcases: str, solution: str) -> dict[str, any]:
        code = Sandbox.postedit_code(code, method_name)
        testcases = Sandbox.parse_testcases(testcases)
        outputs, runtime, memory, status = None, -1, -1, 'Accepted'
        _locals = {'_2615074_testcases': testcases}
        expected = Sandbox.run(Sandbox.postedit_code(solution, method_name), _locals)

        tracemalloc.start()
        runtime = perf_counter_ns()
        try:
            outputs = Sandbox.run(Sandbox.postedit_code(code, method_name), _locals)
        except Exception:
            status = 'Runtime Error'
        runtime = (perf_counter_ns() - runtime) // 1_000_000
        _, memory = tracemalloc.get_traced_memory()
        memory = round(memory / 1_048_576, 1)

        check = list(map(lambda i: outputs[i] == expected[i], range(len(outputs)))) if outputs else []
        if runtime > 10_000:
            status, runtime, memory = 'Time Limit Exceeded', -1, -1
        elif memory > 1024:
            status, runtime, memory = 'Memory Limit Exceeded', -1, -1
        elif not all(check):
            status = 'Wrong Answer'
        return {
            'outputs': [str(t) for t in outputs] if outputs else [],
            'expected': [str(t) for t in expected] if expected else [],
            'runtime': runtime,
            'memory': memory,
            'status': status
        }
