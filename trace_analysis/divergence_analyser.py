from trace_db import TraceDatabase, TraceRecord
from kernel_db import KernelDatabase
from instruction_flow_analyser import FlowAnalyser, FlowInstruction


class DivergenceAnalyser:
    def __init__(
        self,
        kernel_db: KernelDatabase,
        trace_db: TraceDatabase,
        trace_db_tmp: TraceDatabase,
    ):
        self.kernel_db = kernel_db
        self.trace_db = trace_db
        self.trace_db_tmp = trace_db_tmp
        self.flow_analyser = FlowAnalyser(kernel_db, trace_db)
        self.cmp_flow_analyser = FlowAnalyser(kernel_db, trace_db_tmp)

    def analyse_data_flow(self):
        # TODO: assert (clusters, sockets, cores, wids) are the same in both trace DBs
        clusters = self.trace_db.get_clusters()
        for cluster in clusters:
            sockets = self.trace_db.get_sockets(cluster)
            print(f"Analysing {cluster}: sockets={sockets}")
            for socket in sockets:
                cores = self.trace_db.get_cores(cluster, socket)
                print(f"  {socket}: cores={cores}")
                for core in cores:
                    wids = self.trace_db.get_wids(cluster, socket, core)
                    print(f"    {core}: wids={wids}")
                    for wid in wids:
                        self.analyse_flow_by_id(cluster, socket, core, wid)
                        id = f"{cluster}/{socket}/{core}/wid{wid}"
                        control_flow_divergence_points, data_flow_divergence_points = (
                            self.analyse_flow_by_id(cluster, socket, core, wid)
                        )
                        first_data_divergence = (
                            data_flow_divergence_points[0]
                            if data_flow_divergence_points
                            else None
                        )
                        if first_data_divergence:
                            instr, instr_cmp = first_data_divergence
                            self.analyse_data_divergent_flow(instr, instr_cmp, id)
                            return

    def analyse_flow_by_id(self, cluster, socket, core, wid):
        trace = self.flow_analyser.get_flow(cluster, socket, core, wid)
        trace_cmp = self.cmp_flow_analyser.get_flow(cluster, socket, core, wid)
        return self.analyse_flow_by_trace(trace, trace_cmp)

    def analyse_flow_by_trace(self, trace, trace_cmp):
        control_flow_divergence_points = []
        data_flow_divergence_points = []
        for instr, instr_cmp in zip(trace, trace_cmp):
            if instr.pc != instr_cmp.pc:
                control_flow_divergence_points.append((instr, instr_cmp))
                break
            # same PC — check for data divergence in LSU events
            lsu_trace = [r for r in instr.trace if "lsu" in r.event]
            lsu_trace_cmp = [r for r in instr_cmp.trace if "lsu" in r.event]
            for t, tc in zip(lsu_trace, lsu_trace_cmp):
                t.lsu_payload
                if t.raw_line != tc.raw_line:
                    data_flow_divergence_points.append((instr, instr_cmp))
                    break
        return control_flow_divergence_points, data_flow_divergence_points

    def analyse_data_divergent_flow(
        self, instr: FlowInstruction, instr_cmp: FlowInstruction, id=None
    ):
        print(
            f"{id}: First data flow divergence at instruction {instr.uuid} (PC={instr.pc}):"
        )
        print(
            f"  Trace 1: pc={hex(instr.pc) if instr.pc else '???'} {instr.instruction_text} uuid=#{instr.uuid}"
        )
        print(
            f"  Trace 2: pc={hex(instr_cmp.pc) if instr_cmp.pc else '???'} {instr_cmp.instruction_text} uuid=#{instr_cmp.uuid}"
        )
        for r, rc in zip(instr.trace, instr_cmp.trace):
            divergent = r.raw_line[r.raw_line.find(":"):] != rc.raw_line[rc.raw_line.find(":"):]
            # padding = len(r.raw_line) - len(rc.raw_line)
            # max_len = max(len(r.raw_line), len(rc.raw_line))
            # # print(f"{"+-" + "-"*max_len + "-+" if divergent else ""}")
            # print(f"{"|" if divergent else " "} {r.raw_line} {' ' * max(-padding, 0)} {"|" if divergent else ""}")
            # print(f"{"|" if divergent else " "} {rc.raw_line} {' ' * max(padding, 0)} {"|" if divergent else ""}")
            # print(f"{"+-" + "-"*max_len + "-+" if divergent else ""}")
            print(f"{"+--" if divergent else ""}")
            print(f"{"|" if divergent else ""} {r.raw_line}")
            print(f"{"|" if divergent else ""} {rc.raw_line}")
            print(f"{"+--" if divergent else ""}")


if __name__ == "__main__":
    # s = "1279: cluster0-socket0-core3-execute-lsu0-memsched core-req-wr: valid=1111, addr={0x3ffe27fe, 0x3ffe2ffe, 0x3ffe37fe, 0x3ffe3ffe}, byteen={0xf, 0xf, 0xf, 0xf}, data={0x0, 0x0, 0x0, 0x0}, tag=0xc000000212000007a185000 (#51539607585)"
    # from parsing import parse_trace_line
    # print(f"Parsing line: {s}")
    # record = parse_trace_line(s, line_no=1)
    # print(record)

    from instruction_flow_analyser import FlowAnalyser

    trace_db = TraceDatabase.from_file("example/full_trace.log")
    trace_db_cmp = TraceDatabase.from_file("example/full_trace_cmp.log")
    kernel_db = KernelDatabase.from_file("example/kernel.dump")

    # flow_analyser = FlowAnalyser(kernel_db, trace_db)
    # trace = trace_db.get_trace_by_uuid("cluster0", "socket0", "core3", 51539607585)
    # trace_cmp = trace_db_cmp.get_trace_by_uuid("cluster0", "socket0", "core3", 51539607585)

    # flow = flow_analyser.get_flow_by_trace(trace)
    # flow_cmp = flow_analyser.get_flow_by_trace(trace_cmp)

    # lsu_trace = [trace for trace in flow.trace if "lsu" in trace.event]
    # lsu_trace_cmp = [trace for trace in flow_cmp.trace if "lsu" in trace.event]

    # for t, tc in zip(lsu_trace, lsu_trace_cmp):
    #     if (t.raw_line != tc.raw_line):
    #         print(f"{t.raw_line} \n {tc.raw_line}")
    #         print("\n")

    data_trace_analyser = DivergenceAnalyser(kernel_db, trace_db, trace_db_cmp)
    # control_flow_divergence_points, data_flow_divergence_points = data_trace_analyser.analyse_flow_by_id("cluster0", "socket0", "core3", 1)
    # first_data_divergence = data_flow_divergence_points[0] if data_flow_divergence_points else None
    # if first_data_divergence:
    #     instr, instr_cmp = first_data_divergence
    #     print(f"First data flow divergence at instruction {instr.uuid} (PC={instr.pc}):")
    #     print(f"  Trace 1: {instr.log_text}")
    #     print(f"  Trace 2: {instr_cmp.log_text}")
    data_trace_analyser.analyse_data_flow()
