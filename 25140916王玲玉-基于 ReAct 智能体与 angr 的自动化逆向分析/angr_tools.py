import angr

class AngrTools:
    def __init__(self, binary_path):
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.state = self.project.factory.entry_state()
        self.simgr = self.project.factory.simulation_manager(self.state)

    def explore_step(self, find_addr=None, avoid_addr=None):
        """
        受控探索：到达 find_addr 或避开 avoid_addr
        """
        if find_addr is None and avoid_addr is None:
            self.simgr.step()
        else:
            self.simgr.explore(find=find_addr, avoid=avoid_addr)
        return {
            "active": len(self.simgr.active),
            "found": len(self.simgr.found),
            "avoided": len(self.simgr.avoided)
        }

    def solve_input(self, state):
        """
        从符号状态求解具体输入
        """
        input_str = state.posix.dumps(0)  # 标准输入
        return input_str