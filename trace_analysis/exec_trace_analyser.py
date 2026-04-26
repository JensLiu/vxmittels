import re

from typing import Dict, List, Optional, Tuple
from trace_db import TraceDatabase, TraceRecord
from kernel_db import KernelDatabase
from instruction_flow_analyser import FlowAnalyser, FlowInstruction


class ExecTraceAnalyser:
    def __init__(self, kernel_db: KernelDatabase, trace_db: TraceDatabase):
        self.kernel_db = kernel_db
        self.trace_db = trace_db
        self.execution_analysis_context = None
        self.flow_analyser = FlowAnalyser(kernel_db, trace_db)

    @staticmethod
    def __fmt_func_name(name: Optional[str], width: int) -> str:
        s = name if isinstance(name, str) and name else "<?>"
        return f"{s:<{width}s}"

    def __analyse_control_flow(self, flow):
        func_trace = []
        for i, inst_flow in enumerate(flow):
            inst_text = inst_flow.instruction_text
            pc = inst_flow.pc
            # isolate call and ret instructions
            kind = "normal"
            if inst_text in ["ret"]:
                kind = "ret"
            elif re.match(r"jalr?\b", inst_text):
                kind = "call"
            else:
                continue
            # resolve call/ret targets
            func_trace.append((kind, inst_flow))
        return func_trace

    @staticmethod
    def __fmt_pc(pc):
        return f"0x{pc:08x}" if pc is not None else "???"

    @staticmethod
    def __fmt_cycles(first, last):
        if first is None and last is None:
            return "???-???"
        if first == last:
            return str(first)
        return f"{first}-{last}"

    def __analysis_summary(self, func_call_trace: List[Tuple]):
        if not func_call_trace:
            return "  (no calls/returns detected)\n"
        lines = []
        for kind, inst in func_call_trace:
            arrow = "->" if kind == "call" else "<-"
            label = "CALL" if kind == "call" else "RET "
            lines.append(
                f"  {arrow} {label} {self.__fmt_func_name(inst.function_name, 30)}  "
                f"pc={self.__fmt_pc(inst.pc)}  "
                f"cycle={self.__fmt_cycles(inst.first_cycle, inst.last_cycle):<12s}  "
                f"uuid=#{inst.uuid}"
            )
        return "\n".join(lines) + "\n"

    def __analysis_detail(self, function_trace: List[FlowInstruction]):
        if not function_trace:
            return "  (no instructions)\n"
        lines = []
        for inst in function_trace:
            cycle_str = self.__fmt_cycles(inst.first_cycle, inst.last_cycle)
            latency = ""
            if inst.first_cycle is not None and inst.last_cycle is not None:
                latency = f" ({inst.last_cycle - inst.first_cycle} cyc)"
            lines.append(
                f"  [{cycle_str:>12s}]{latency:<10s}  "
                f"{self.__fmt_pc(inst.pc)}  "
                f"{inst.instruction_text:<36s}  "
                f"{self.__fmt_func_name(inst.function_name, 28)}  "
                f"tmask={inst.tmask or '????'}  uuid=#{inst.uuid}"
            )
            stage_str = " -> ".join(
                [f"{event}(x{count})" for event, count in inst.events]
            )
            lines.append(f"    stages: {stage_str}")
        return "\n".join(lines) + "\n"

    def __analyse_execution_flow(self):
        clusters = self.trace_db.get_clusters()
        summary = {}
        detail = {}
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
                        exec_trace = self.flow_analyser.get_flow(
                            cluster, socket, core, wid
                        )
                        func_trace = self.__analyse_control_flow(exec_trace)
                        detail[(cluster, socket, core, wid)] = (exec_trace, func_trace)
                        summary[(cluster, socket, core, wid)] = func_trace
        return summary, detail

    def analysis_report(self):
        lines = []
        summary, detail = self.__analyse_execution_flow()
        sep = "=" * 100

        # -- Section 1: Call/Return Summary --
        lines.append(sep)
        lines.append("  FUNCTION CALL / RETURN SUMMARY")
        lines.append(sep)
        for key, func_trace in summary.items():
            component = f"{key[0]}/{key[1]}/{key[2]}/wid{key[3]}"
            lines.append("")
            lines.append(f"--- {component} ---")
            lines.append(self.__analysis_summary(func_trace))

        # -- Section 2: Full Execution Detail --
        lines.append("")
        lines.append(sep)
        lines.append("  FULL EXECUTION TRACE")
        lines.append(sep)
        for key, (exec_trace, _func_trace) in detail.items():
            component = f"{key[0]}/{key[1]}/{key[2]}/wid{key[3]}"
            lines.append("")
            lines.append(f"--- {component}  ({len(exec_trace)} instructions) ---")
            lines.append(self.__analysis_detail(exec_trace))

        return "\n".join(lines) + "\n"


if __name__ == "__main__":
    trace_path = "bug/run.log"
    kernel_path = "bug/kernel.dump"
    report_path = "bug/log.analysis"
    analyser = ExecTraceAnalyser(
        kernel_db=KernelDatabase.from_file(kernel_path),
        trace_db=TraceDatabase.from_file(trace_path),
    )
    report = analyser.analysis_report()
    with open(report_path, "w") as f:
        f.write(report)

    # trace_db = TraceDatabase.from_file(trace_path)
    # trace = trace_db.get_trace_by_uuid("cluster0", "socket0", "core0", 33)
    # for record in trace:
    #     print(record.raw_line)
