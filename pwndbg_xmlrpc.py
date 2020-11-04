#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import datetime
import threading
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer
from xml.sax.saxutils import escape

import idaapi
import idautils
import idc

server = None
thread = None

DEBUG_MARSHALLING = False


def create_marshaller(use_format=None, just_to_str=False):
    assert use_format or just_to_str, 'Either pass format to use or make it converting the value to str.'

    def wrapper(_marshaller, value, appender):
        if use_format:
            marshalled = use_format % value
        elif just_to_str:
            marshalled = '<value><string>%s</string></value>' % escape(
                str(value))

        if DEBUG_MARSHALLING:
            print("Marshalled: '%s'" % marshalled)

        appender(marshalled)

    return wrapper


xmlrpclib.Marshaller.dispatch[type(0L)] = create_marshaller("<value><i8>%d</i8></value>")
xmlrpclib.Marshaller.dispatch[type(0)] = create_marshaller(
    "<value><i8>%d</i8></value>")
xmlrpclib.Marshaller.dispatch[idaapi.cfuncptr_t] = create_marshaller(
    just_to_str=True)

orig_LineA = None


def mod_LineA(*a, **kw):
    global orig_LineA
    v = orig_LineA(*a, **kw)
    if v and v.startswith('\x01\x04; '):
        v = v[4:]
    return v


mutex = threading.Condition()


def wrap(f):
    def wrapper(*a, **kw):
        rv = []
        error = []

        def work():
            try:
                result = f(*a, **kw)
                rv.append(result)
            except Exception as e:
                error.append(e)

        with mutex:
            flags = idaapi.MFF_WRITE
            if f == idc.SetColor:
                flags |= idaapi.MFF_NOWAIT
                rv.append(None)
            idaapi.execute_sync(work, flags)

        if error:
            msg = 'Failed on calling {}.{} with args: {}, kwargs: {}\nException: {}' \
                .format(f.__module__, f.__name__, a, kw, str(error[0]))
            print('[!!!] ERROR:', msg)
            raise error[0]

        return rv[0]

    return wrapper


def decompile(addr):
    """
    Function that overwrites `idaapi.decompile` for xmlrpc so that instead
    of throwing an exception on `idaapi.DecompilationFailure` it just returns `None`.
    (so that we don't have to parse xmlrpc Fault's exception string on pwndbg side
    as it differs between IDA versions).
    """
    try:
        return idaapi.decompile(addr)
    except idaapi.DecompilationFailure:
        return None


def get_decompile_coord_by_ea(cfunc, addr):
    if idaapi.IDA_SDK_VERSION >= 720:
        item = cfunc.body.find_closest_addr(addr)
        y_holder = idaapi.int_pointer()
        if not cfunc.find_item_coords(item, None, y_holder):
            return None
        y = y_holder.value()
    else:
        lnmap = {}
        for i, line in enumerate(cfunc.pseudocode):
            phead = idaapi.ctree_item_t()
            pitem = idaapi.ctree_item_t()
            ptail = idaapi.ctree_item_t()
            ret = cfunc.get_line_item(line.line, 0, True, phead, pitem, ptail)
            if ret and pitem.it:
                lnmap[pitem.it.ea] = i
        y = None
        closest_ea = BADADDR
        for ea, line in lnmap.items():
            if closest_ea == BADADDR or abs(closest_ea - addr) > abs(ea - addr):
                closest_ea = ea
                y = lnmap[ea]

    return y


def register_module(module):
    for name, function in module.__dict__.items():
        if hasattr(function, '__call__'):
            server.register_function(wrap(function), name)


def decompile_context(addr, context_lines):
    cfunc = decompile(addr)
    if cfunc is None:
        return None
    y = get_decompile_coord_by_ea(cfunc, addr)
    if y is None:
        return cfunc
    lines = cfunc.get_pseudocode()
    retlines = []
    for lnnum in range(max(0, y - context_lines), min(len(lines), y + context_lines)):
        retlines.append(idaapi.tag_remove(lines[lnnum].line))
        if lnnum == y:
            retlines[-1] = '>' + retlines[-1][1:]
    return '\n'.join(retlines)


def versions():
    """Returns IDA & Python versions"""
    import sys
    return {
        'python': sys.version,
        'ida': idaapi.get_kernel_version(),
        'hexrays': idaapi.get_hexrays_version() if idaapi.init_hexrays_plugin() else None
    }


class PwndbgRPC:
    def __init__(self):
        global mod_LineA, orig_LineA
        self.host = '0.0.0.0'
        self.port = 31337
        if idc.LineA != mod_LineA:
            orig_LineA = idc.LineA
            idc.LineA = mod_LineA

    def set_host(self, hostname):
        self.host = hostname

    def set_port(self, port):
        self.port = port

    def start_server(self):
        global server
        global thread
        server = SimpleXMLRPCServer(
            (self.host, self.port), logRequests=True, allow_none=True)
        register_module(idc)
        register_module(idautils)
        register_module(idaapi)
        server.register_function(lambda a: eval(
            a, globals(), locals()), 'eval')
        # overwrites idaapi/ida_hexrays.decompile
        server.register_function(wrap(decompile))
        # support context decompile
        server.register_function(wrap(decompile_context), 'decompile_context')
        server.register_function(versions)
        server.register_introspection_functions()

        print('IDA Pro xmlrpc hosted on http://%s:%s' % (self.host, self.port))

        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

    def stop_server(self):
        global server, thread
        server.shutdown()
        server.server_close()


class PwndbgRPC_Form(idaapi.Form):
    def __init__(self):
        idaapi.Form.__init__(self,
                             r"""STARTITEM 0
BUTTON YES* Start
BUTTON NO* Stop
Pwndbg XML RPC
        {FormChangeCb}
        <Host:{host}>
        <Port:{port}>
        """, {
                                 'host': self.StringInput(value='0.0.0.0', swidth=20),
                                 'port': self.NumericInput(value=31337, swidth=20, tp=self.FT_DEC),
                                 'FormChangeCb': self.FormChangeCb(self.OnFormChange)
                             })

        self.Compile()

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        return 1


class PwndbgRPC_Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = 'Pwndbg XML RPC plugin'
    help = ''
    wanted_name = 'Pwndbg XML RPC'
    wanted_hotkey = ''

    def init(self):
        idaapi.msg('[*] Pwndbg XML RPC plugin loaded.\n')

        if idaapi.init_hexrays_plugin():
            addon = idaapi.addon_info_t()
            addon.id = "com.pwndbg.pwndbg"
            addon.name = "Pwndbg XML RPC"
            addon.producer = "pwndbg"
            addon.url = "https://github.com/pwndbg/pwndbg"
            addon.version = "1.0.0.0"
            idaapi.register_addon(addon)

        self.pwndbgRPC = PwndbgRPC()

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        f = PwndbgRPC_Form()
        btn_status = f.Execute()
        if btn_status == 1:  # start
            print("[*] pwndbg XML RPC started")
            self.pwndbgRPC.set_host(f.host.value)
            self.pwndbgRPC.set_port(f.port.value)
            self.pwndbgRPC.start_server()
        elif btn_status == 0:  # stop
            self.pwndbgRPC.stop_server()
            print("[*] pwndbg XML RPC stoped")
        else:  # -1, cancel
            pass
        f.Free()


def PLUGIN_ENTRY():
    return PwndbgRPC_Plugin()
