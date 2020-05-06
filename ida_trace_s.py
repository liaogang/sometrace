# -*- coding: utf-8 -*-

import idaapi
import idc
import re
import ida_dbg
import ida_idd
from idaapi import *
from collections import OrderedDict
import logging
import time
import datetime
import os
import codecs

debughook = None

base = 0x00
size = 0x00

def xx_hex(ea):
    return hex(ea).rstrip("L").lstrip("0x")


def set_breakpoint(ea):
    # idc.SetReg(ea, "T", 1)
    idc.MakeCode(ea)
    idc.add_bpt(ea)


def my_get_reg_value(register):
    rv = ida_idd.regval_t()
    ida_dbg.get_reg_val(register, rv)
    current_addr = rv.ival
    return current_addr


def suspend_other_thread():
    current_thread = idc.get_current_thread()
    thread_count = idc.get_thread_qty()
    for i in range(0, thread_count):
        other_thread = idc.getn_thread(i)
        if other_thread != current_thread:
            idc.suspend_thread(other_thread)


def resume_process():
    current_thread = idc.get_current_thread()
    thread_count = idc.get_thread_qty()
    for i in range(0, thread_count):
        other_thread = idc.getn_thread(i)
        if other_thread != current_thread:
            idc.resume_thread(other_thread)
    idc.resume_thread(current_thread)
    idc.resume_process()


class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def __init__(self, skip_functions, end_ea):
        super(MyDbgHook, self).__init__()
        self.skip_functions = skip_functions
        self.trace_step_into_count = 0
        self.trace_step_into_size = 1
        self.trace_total_size = 300000
        self.trace_size = 0
        self.trace_lr = 0
        self.end_ea = end_ea
        self.bpt_trace = 0
        self.Logger = None
        self.line_trace = 0
        print("__init__")

    def start_line_trace(self):
        self.bpt_trace = 0
        self.line_trace = 1
        self.start_hook()

    def start_hook(self):
        self.hook()
        print("start_hook")

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))

    def dbg_process_exit(self, pid, tid, ea, code):
        self.unhook()
        if self.Logger:
            self.Logger.log_close()
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))

    def dbg_process_detach(self, pid, tid, ea):
        self.unhook()
        self.Logger.log_close()
        return 0

    def dbg_bpt(self, tid, ea):
        print("Break point at 0x%x tid=%d" % (ea, tid))
        if ea in self.end_ea:
            ida_dbg.enable_insn_trace(False)
            ida_dbg.enable_step_trace(False)
            ida_dbg.suspend_process()
            return 0
        return 0

    def dbg_trace(self, tid, ea):
        # print("Trace tid=%d ea=0x%x" % (tid, ea))
        # return values:
        #   1  - do not log this trace event;
        #   0  - log it
        if self.line_trace:
            # if ((base <= ea) and (ea <= (base + size)) ):
            if base <= ea <= (base+size):
                in_mine_so = True
            else:
                in_mine_so = False

            self.trace_size += 1
            if (not in_mine_so) or (ea in self.skip_functions):
                if (self.trace_lr != 0) and (self.trace_step_into_count < self.trace_step_into_size):
                    self.trace_step_into_count += 1
                    return 0

                if (self.trace_lr != 0) and (self.trace_step_into_count == self.trace_step_into_size):
                    ida_dbg.enable_insn_trace(False)
                    ida_dbg.enable_step_trace(False)
                    ida_dbg.suspend_process()
                    if self.trace_size > self.trace_total_size:
                        self.trace_size = 0
                        ida_dbg.request_clear_trace()
                        ida_dbg.run_requests()

                    ida_dbg.request_run_to(self.trace_lr)
                    ida_dbg.run_requests()
                    self.trace_lr = 0
                    self.trace_step_into_count = 0
                    return 0

                if self.trace_lr == 0:
                    self.trace_lr = my_get_reg_value("X30")  # arm thumb LR arm64 X30
            return 0

    def dbg_run_to(self, pid, tid=0, ea=0):
        # print("dbg_run_to 0x%x pid=%d" % (ea, pid))
        if self.line_trace:
            ida_dbg.enable_insn_trace(True)
            ida_dbg.enable_step_trace(True)
            ida_dbg.request_continue_process()
            ida_dbg.run_requests()


def unhook():
    global debughook
    # Remove an existing debug hook
    try:
        if debughook:
            print("Removing previous hook ...")
            debughook.unhook()
            debughook.Logger.log_close()
    except:
        pass


def starthook():
    global debughook
    if debughook:
        debughook.start_line_trace()

source = """
rpc.exports = {
    getmodulebase: function (name) {
        return parseInt(Module.findBaseAddress(name));
    },
    getmodulesize: function (name) {
        var module = Module.load(name);
        if (module) {
            return module.size;
        }
        return 0;
    }
};
"""


def main():
    global debughook
    unhook()
    skip_functions = []

    for module in idc._get_modules():
        if module.name == '/var/containers/Bundle/Application/D6FADF96-5135-4014-93C4-CF4393986EBC/WeChat.app/WeChat':
            base = module.base
            size = module.size
            print( 'base: ' )
            print( base )
            print( 'size: ' )
            print(size )
            print( ' .' )

            if (base > 0 and size > 0):
                break


    start_ea = base + 0x445D294
    end_ea = [ base + 0x445DAC4]

    if start_ea:
        set_breakpoint(start_ea)
    if end_ea:
        for ea in end_ea:
            set_breakpoint(ea)

    if skip_functions:
        print("skip_functions")
        for skip_function in skip_functions:
            print ("%08X" % skip_function)

    debughook = MyDbgHook(skip_functions, end_ea)


if __name__ == "__main__":
    main()
