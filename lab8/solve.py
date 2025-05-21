#!/usr/bin/env python3


import angr
import claripy
import sys

def main():
    proj = angr.Project("./chal", auto_load_libs=False)
    key_bytes = [claripy.BVS(f'key_{i}', 8) for i in range(8)]
    secret_key = claripy.Concat(*key_bytes)
    state = proj.factory.full_init_state(stdin=secret_key)
    for b in key_bytes:
        state.solver.add(b >= 0x20)
        state.solver.add(b <= 0x7e)
    simgr = proj.factory.simgr(state)

    def is_successful(state):
        return b"Correct!" in state.posix.dumps(1)

    def should_abort(state):
        return b"Wrong key!" in state.posix.dumps(1)

    simgr.explore(find=is_successful, avoid=should_abort)

    if simgr.found:
        found = simgr.found[0]
        key = found.solver.eval(secret_key, cast_to=bytes)
        sys.stdout.buffer.write(key)
    else:
        print("No solution found.")


if __name__ == '__main__':
    main()
