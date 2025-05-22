#!/usr/bin/env python3

import angr
import claripy
import sys

def main():
    # 載入 chal 執行檔
    proj = angr.Project("./chal", auto_load_libs=False)

    # 建立 8 個符號位元組（每個是 8-bit），組成 secret_key
    key_bytes = [claripy.BVS(f'key_{i}', 8) for i in range(8)]
    secret_key = claripy.Concat(*key_bytes)

    # 初始化 state，將 symbolic input 傳入 stdin
    state = proj.factory.full_init_state(stdin=secret_key)

    # 加入輸入長度限制（因為 chal.c 會用 strlen 判斷長度必須是 8）
    for b in key_bytes:
        state.solver.add(b >= 0x20)  # 可列印字元
        state.solver.add(b <= 0x7e)

    # 建立 simulation manager
    simgr = proj.factory.simgr(state)

    # 設定搜尋目標：當輸出包含 "Correct!"，代表成功通過 gate()
    def is_successful(state):
        return b"Correct!" in state.posix.dumps(1)

    # 設定排除條件：當輸出包含 "Wrong key!"，表示是失敗路徑
    def should_abort(state):
        return b"Wrong key!" in state.posix.dumps(1)

    # 探索符合條件的路徑
    simgr.explore(find=is_successful, avoid=should_abort)

    if simgr.found:
        found = simgr.found[0]
        # 將求得的符號解碼為實際的字串
        key = found.solver.eval(secret_key, cast_to=bytes)
        sys.stdout.buffer.write(key)
    else:
        print("No solution found.")

if __name__ == '__main__':
    main()
