# -*- coding: utf-8 -*-
"""Mock of the bfrt_grpc.client surface that batched_reader.py uses.

A MockSwitch holds the register cells per pipe twice: `hw` (what the data
plane updates) and `shadow` (the driver's copy that a register Sync refreshes
and that from_hw=False reads return), so the snapshot semantics of the real
switch are kept. packet() applies one packet to a bucket the way ingress.p4
does (direction reference, first/last timestamp, min/max length, TCP flags,
reg_newconn_dst) and returns True when the data plane would send a CPU report
(first packet of an empty bucket in that pipe).

The module exposes what the reader imports from bfrt_grpc.client:
ClientInterface, Target, KeyTuple, DataTuple and bfruntime_pb2 (the real
generated module when it is importable, so the reader's fast response parser
is exercised against real protobuf messages). ClientInterface connects to the
MockSwitch registered for its address (serve()).

legacy_view(switch) returns the `bfrt` object that the legacy reader's
bfrt_python script expects (bfrt.basic.pipe.Ingress.reg_x.get/mod/
operation_register_sync, bfrt.complete_operations), backed by the same cells,
so both readers can be run on identical state.

All RPCs and legacy calls are counted in MockSwitch.stats.
"""
from __future__ import division, print_function

import copy
import json
import os
import time

REG_NAMES = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab",
             "reg_ref_src_port", "reg_ref_dst_port", "reg_dir_valid",
             "reg_min_len", "reg_max_len", "reg_first_ts", "reg_last_ts",
             "reg_syn", "reg_ack", "reg_rst"]
DST_REG_NAME = "reg_newconn_dst"
WIDTH_BITS = {"reg_ref_src_port": 16, "reg_ref_dst_port": 16, "reg_dir_valid": 8,
              "reg_min_len": 16, "reg_max_len": 16}
TABLE_PREFIX = "pipe.Ingress."
DATA_PREFIX = "Ingress."
KEY_FIELD = "$REGISTER_INDEX"
KEY_FIELD_ID = 1
DATA_FIELD_ID = 1
FLOW_BUCKETS = 65536

try:
    import sys as _sys
    from batched_reader import sde_site_packages as _sde
    for _p in reversed(_sde()):
        if _p not in _sys.path:
            _sys.path.insert(0, _p)
    import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
except Exception:
    bfruntime_pb2 = None

SWITCHES = {}


def width_bits(name):
    return WIDTH_BITS.get(name, 32)


def _bytes_to_int(b):
    b = bytes(b)
    n = 0
    for c in bytearray(b):
        n = (n << 8) | c
    return n


def _int_to_bytes(n, length):
    out = bytearray(length)
    for i in range(length - 1, -1, -1):
        out[i] = n & 0xFF
        n >>= 8
    return bytes(out)


class MockSwitch(object):
    def __init__(self, pipes=2, registers=None, sync_ops=("Sync",), p4_name="basic"):
        self.pipes = pipes
        self.registers = list(registers) if registers is not None else REG_NAMES + [DST_REG_NAME]
        self.sync_ops = list(sync_ops)
        self.p4_name = p4_name
        self.hw = dict((n, {}) for n in self.registers)
        self.shadow = dict((n, {}) for n in self.registers)
        self.table_ids = dict((n, 1000 + i) for i, n in enumerate(self.registers))
        self.stats = {"sync_rpcs": 0, "sync_ops": 0, "read_rpcs": 0, "read_entities": 0,
                      "read_from_hw": 0, "write_rpcs": 0, "write_updates": 0,
                      "legacy_gets": 0, "legacy_syncs": 0, "legacy_mods": 0}
        self.hang_on = 0          # tests: hang on this Read RPC ...
        self.hang_marker = None   # ... only once, recorded in this file
        self.bound_client = None  # the one client that may hold the program binding

    # ------------------------------------------------------------ cells
    def cell(self, store, name, idx):
        d = store[name]
        if idx not in d:
            d[idx] = [0] * self.pipes
        return d[idx]

    def read(self, name, idx, from_hw):
        store = self.hw if from_hw else self.shadow
        return list(store[name].get(idx, [0] * self.pipes))

    def write(self, name, idx, value):
        """Register write (entry_mod / reg.mod): all pipes, hardware and shadow."""
        mask = (1 << width_bits(name)) - 1
        self.hw[name][idx] = [value & mask] * self.pipes
        self.shadow[name][idx] = [value & mask] * self.pipes

    def seed(self, name, idx, pipe, value):
        """Set one cell in hardware and shadow (test setup)."""
        self.cell(self.hw, name, idx)[pipe] = value
        self.cell(self.shadow, name, idx)[pipe] = value

    def sync(self, name):
        self.shadow[name] = copy.deepcopy(self.hw[name])
        self.stats["sync_ops"] += 1

    def maybe_hang(self):
        if not self.hang_on or self.stats["read_rpcs"] != self.hang_on:
            return
        if self.hang_marker:
            if os.path.exists(self.hang_marker):
                return
            open(self.hang_marker, "w").close()
        time.sleep(3600)

    def table_name(self, table_id):
        for n, i in self.table_ids.items():
            if i == table_id:
                return n
        raise KeyError("unknown table id %d" % table_id)

    # ------------------------------------------------------------ data plane
    def packet(self, idx, pipe, length, sport, dport, proto=6, flags=0, ts=1, dst_idx=None):
        """Apply one packet like ingress.p4; return True if it sends a CPU report."""
        hw = self.hw

        def c(name):
            return self.cell(hw, name, idx)

        m32 = 0xFFFFFFFF
        report = False
        if c("reg_dir_valid")[pipe] == 0:
            c("reg_dir_valid")[pipe] = 1
            c("reg_ref_src_port")[pipe] = sport
            c("reg_ref_dst_port")[pipe] = dport
            dir_ab = 1
            report = True
        else:
            rs, rd = c("reg_ref_src_port")[pipe], c("reg_ref_dst_port")[pipe]
            if sport == rs and dport == rd:
                dir_ab = 1
            elif sport == rd and dport == rs:
                dir_ab = 0
            else:
                dir_ab = 1
        if dir_ab:
            c("reg_pkts_ab")[pipe] = (c("reg_pkts_ab")[pipe] + 1) & m32
            c("reg_bytes_ab")[pipe] = (c("reg_bytes_ab")[pipe] + length) & m32
        c("reg_pkts")[pipe] = (c("reg_pkts")[pipe] + 1) & m32
        c("reg_bytes")[pipe] = (c("reg_bytes")[pipe] + length) & m32
        if c("reg_min_len")[pipe] == 0 or length < c("reg_min_len")[pipe]:
            c("reg_min_len")[pipe] = length & 0xFFFF
        if length > c("reg_max_len")[pipe]:
            c("reg_max_len")[pipe] = length & 0xFFFF
        if c("reg_first_ts")[pipe] == 0:
            c("reg_first_ts")[pipe] = ts & m32
        c("reg_last_ts")[pipe] = ts & m32
        if proto == 6:
            if flags & 0x02:
                c("reg_syn")[pipe] = (c("reg_syn")[pipe] + 1) & m32
            if flags & 0x04:
                c("reg_rst")[pipe] = (c("reg_rst")[pipe] + 1) & m32
            if flags & 0x10:
                c("reg_ack")[pipe] = (c("reg_ack")[pipe] + 1) & m32
            if (flags & 0x12) == 0x02 and dst_idx is not None and DST_REG_NAME in hw:
                d = self.cell(hw, DST_REG_NAME, dst_idx)
                d[pipe] = (d[pipe] + 1) & m32
        return report

    # ------------------------------------------------------------ server side
    def rpc_read(self, req):
        """Serve a bfruntime_pb2.ReadRequest; yield ReadResponse messages."""
        self.stats["read_rpcs"] += 1
        self.maybe_hang()
        out = []
        for ent in req.entities:
            te = ent.table_entry
            name = self.table_name(te.table_id)
            from_hw = bool(te.table_flags.from_hw)
            if from_hw:
                self.stats["read_from_hw"] += 1
            idxs = [_bytes_to_int(kf.exact.value) for kf in te.key.fields] or sorted(self.hw[name])
            for idx in idxs:
                vals = self.read(name, idx, from_hw)
                out.append((te.table_id, idx, vals))
        self.stats["read_entities"] += len(out)
        # Stream in pieces, as the server does.
        for start in range(0, max(len(out), 1), 1000):
            rsp = bfruntime_pb2.ReadResponse()
            for table_id, idx, vals in out[start:start + 1000]:
                te = rsp.entities.add().table_entry
                te.table_id = table_id
                kf = te.key.fields.add()
                kf.field_id = KEY_FIELD_ID
                kf.exact.value = _int_to_bytes(idx, 4)
                # as the BF Runtime server: one data field per pipe, bytes in `stream`
                size = (width_bits(self.table_name(table_id)) + 7) // 8
                for v in vals:
                    df = te.data.fields.add()
                    df.field_id = DATA_FIELD_ID
                    df.stream = _int_to_bytes(v, size)
            yield rsp

    def rpc_write(self, req):
        self.stats["write_rpcs"] += 1
        for upd in req.updates:
            ent = upd.entity
            if ent.HasField("table_operation"):
                name = self.table_name(ent.table_operation.table_id)
                op = ent.table_operation.table_operations_type
                if op not in self.sync_ops:
                    raise RuntimeError("operation %s not supported on %s" % (op, name))
                self.sync(name)
                self.stats["sync_rpcs"] += 1
            elif ent.HasField("table_entry"):
                te = ent.table_entry
                name = self.table_name(te.table_id)
                idx = _bytes_to_int(te.key.fields[0].exact.value)
                value = 0
                for df in te.data.fields:
                    if df.HasField("stream"):
                        value = _bytes_to_int(df.stream)
                    elif df.HasField("int_arr_val"):
                        value = list(df.int_arr_val.val)[0] if len(df.int_arr_val.val) else 0
                self.write(name, idx, value)
                self.stats["write_updates"] += 1
        return bfruntime_pb2.WriteResponse() if bfruntime_pb2 is not None else None


# ---------------------------------------------------------------- client API

class Target(object):
    def __init__(self, device_id=0, pipe_id=0xffff, direction=0xff, prsr_id=0xff):
        self.device_id_ = device_id
        self.pipe_id_ = pipe_id
        self.direction_ = direction
        self.prsr_id_ = prsr_id


class KeyTuple(object):
    def __init__(self, name, value=None, mask=None, prefix_len=None, low=None, high=None, is_valid=None):
        self.name = name
        self.value = value
        self.mask = mask
        self.prefix_len = prefix_len
        self.low = low
        self.high = high
        self.is_valid = is_valid


class DataTuple(object):
    def __init__(self, name, val=None, float_val=None, str_val=None, int_arr_val=None, bool_arr_val=None,
                 bool_val=None, str_arr_val=None, container_arr_val=None):
        self.name = name
        self.val = val
        self.float_val = float_val
        self.str_val = str_val
        self.int_arr_val = int_arr_val
        self.bool_arr_val = bool_arr_val
        self.bool_val = bool_val
        self.str_arr_val = str_arr_val
        self.container_arr_val = container_arr_val


class _TableInfo(object):
    def __init__(self, switch, name):
        self.switch = switch
        self.name = name
        self.data_name = DATA_PREFIX + name + ".f1"

    def name_get(self):
        return TABLE_PREFIX + self.name

    def id_get(self):
        return self.switch.table_ids[self.name]

    def type_get(self):
        return "Register"

    def size_get(self):
        return FLOW_BUCKETS

    def operations_supported_get(self):
        return list(self.switch.sync_ops)

    def attributes_supported_get(self):
        return []

    def key_field_name_list_get(self):
        return [KEY_FIELD]

    def key_field_id_get(self, field_name):
        if field_name != KEY_FIELD:
            raise KeyError(field_name)
        return KEY_FIELD_ID

    def key_field_size_get(self, field_name):
        self.key_field_id_get(field_name)
        return (4, 32)

    def key_field_type_get(self, field_name):
        return "uint32"

    def key_field_match_type_get(self, field_name):
        return "Exact"

    def data_field_name_list_get(self, action_name=None):
        return [self.data_name]

    def data_field_id_get(self, field_name, action_name=None):
        if field_name != self.data_name:
            raise KeyError(field_name)
        return DATA_FIELD_ID

    def data_field_size_get(self, field_name, action_name=None):
        self.data_field_id_get(field_name)
        bits = width_bits(self.name)
        return ((bits + 7) // 8, bits)

    def data_field_type_get(self, field_name, action_name=None):
        return "bytes"

    def data_field_annotations_get(self, field_name, action_name=None):
        return ["$bfrt_field_class.register_data"]


class _Key(object):
    def __init__(self, table, fields):
        if not isinstance(fields, list):
            raise TypeError("A list of KeyTuple is expected")
        self.table = table
        self.field_dict = {}
        for f in fields:
            table.info.key_field_id_get(f.name)
            self.field_dict[f.name] = f

    def to_dict(self):
        return dict((name, {"value": int(f.value)}) for name, f in self.field_dict.items())


class _Data(object):
    def __init__(self, table, fields, values=None):
        self.table = table
        self.field_dict = dict((f.name, f) for f in fields)
        self.values = values
        self.action_name = None
        self.is_default_entry = False

    def to_dict(self):
        d = {}
        for name in self.field_dict:
            d[name] = list(self.values) if self.values is not None else self.field_dict[name].val
        d["action_name"] = None
        d["is_default_entry"] = False
        return d


class _ReaderWriter(object):
    def __init__(self, switch, client_id):
        self.switch = switch
        self.client_id = client_id

    def _read(self, req, metadata=None):
        req.client_id = self.client_id
        return self.switch.rpc_read(req)

    def _write(self, req, metadata=None):
        req.client_id = self.client_id
        return self.switch.rpc_write(req)


class _Table(object):
    def __init__(self, switch, name):
        self.switch = switch
        self.name = name
        self.info = _TableInfo(switch, name)

    def make_key(self, key_field_list_in):
        return _Key(self, key_field_list_in)

    def make_data(self, data_field_list_in=[], action_name=None, get=False):
        for f in data_field_list_in:
            self.info.data_field_id_get(f.name)
        return _Data(self, list(data_field_list_in))

    def entry_get(self, target, key_list=None, flags={"from_hw": True}, required_data=None, handle=None,
                  p4_name=None, metadata=None, entry_tgt_list=None):
        sw = self.switch
        sw.stats["read_rpcs"] += 1
        sw.maybe_hang()
        from_hw = bool(flags.get("from_hw", True))
        if from_hw:
            sw.stats["read_from_hw"] += 1
        idxs = [int(k.field_dict[KEY_FIELD].value) for k in (key_list or [])] or sorted(sw.hw[self.name])
        sw.stats["read_entities"] += len(idxs)
        for idx in idxs:
            yield (_Data(self, [DataTuple(self.info.data_name)], sw.read(self.name, idx, from_hw)),
                   _Key(self, [KeyTuple(KEY_FIELD, idx)]))

    def entry_mod(self, target, key_list=None, data_list=None, flags=None, atomicity=None, p4_name=None,
                  metadata=None, entry_tgt_list=None):
        sw = self.switch
        sw.stats["write_rpcs"] += 1
        for key, data in zip(key_list, data_list):
            idx = int(key.field_dict[KEY_FIELD].value)
            val = data.field_dict[self.info.data_name].val
            if isinstance(val, (bytes, bytearray)):
                val = _bytes_to_int(val)
            sw.write(self.name, idx, int(val or 0))
            sw.stats["write_updates"] += 1

    def operations_execute(self, target, table_op, p4_name=None, metadata=None):
        sw = self.switch
        sw.stats["write_rpcs"] += 1
        if table_op not in sw.sync_ops:
            raise RuntimeError("operation %s not supported on %s" % (table_op, self.name))
        sw.sync(self.name)
        sw.stats["sync_rpcs"] += 1


class _BfRtInfo(object):
    def __init__(self, switch, rw):
        self.switch = switch
        self.p4_name = switch.p4_name
        self.reader_writer_interface = rw
        self.table_dict = dict((TABLE_PREFIX + n, _Table(switch, n)) for n in switch.registers)

    def table_get(self, name):
        return self.table_dict[name]

    def table_name_list_get(self):
        return sorted(self.table_dict)

    def p4_name_get(self):
        return self.p4_name


class ClientInterface(object):
    def __init__(self, grpc_addr, client_id, device_id, notifications=None, timeout=1, num_tries=5,
                 perform_subscribe=True):
        switch = SWITCHES.get(grpc_addr, SWITCHES.get(None))
        if switch is None:
            raise RuntimeError("no mock switch is served at %s (bfrt_mock.serve)" % grpc_addr)
        self.switch = switch
        self.client_id = client_id
        self.device_id = device_id
        self.is_independent = not perform_subscribe
        self.reader_writer_interface = _ReaderWriter(switch, client_id)
        self.bound = None
        self.torn_down = False

    def bfrt_info_get(self, p4_name=None):
        if p4_name and p4_name != self.switch.p4_name:
            raise RuntimeError("BF_RT_INFO not received")
        return _BfRtInfo(self.switch, self.reader_writer_interface)

    def bind_pipeline_config(self, p4_name):
        other = self.switch.bound_client
        if other is not None and other != self.client_id:
            raise RuntimeError("Error: StatusCode.ALREADY_EXISTS : Client ID %d trying to bind but Client ID %d "
                               "already owns this P4 Already exists" % (self.client_id, other))
        self.switch.bound_client = self.client_id
        self.bound = p4_name

    def tear_down_stream(self):
        self.torn_down = True
        if self.switch.bound_client == self.client_id:
            self.switch.bound_client = None


def serve(switch, grpc_addr=None):
    """Make ClientInterface(grpc_addr, ...) connect to this switch (None = any address)."""
    SWITCHES[grpc_addr] = switch
    SWITCHES[None] = switch
    return switch


def switch_from_dict(spec):
    sw = MockSwitch(pipes=int(spec.get("pipes", 2)), registers=spec.get("registers"),
                    sync_ops=spec.get("sync_ops", ["Sync"]), p4_name=spec.get("p4_name", "basic"))
    for name, cells in (spec.get("cells") or {}).items():
        for idx, values in cells.items():
            values = list(values) + [0] * (sw.pipes - len(values))
            sw.hw[name][int(idx)] = list(values[:sw.pipes])
            sw.shadow[name][int(idx)] = list(values[:sw.pipes])
    return sw


def serve_from_file(path, grpc_addr=None, hang_on=0, hang_marker=None):
    with open(path) as f:
        sw = switch_from_dict(json.load(f))
    sw.hang_on = int(hang_on or 0)
    sw.hang_marker = hang_marker
    return serve(sw, grpc_addr)


# ---------------------------------------------------------------- legacy view

class _LegacyEntry(object):
    def __init__(self, name, values):
        self.data = {("Ingress.%s.f1" % name).encode(): values}


class _LegacyRegister(object):
    def __init__(self, switch, name):
        self.switch = switch
        self.name = name

    def get(self, REGISTER_INDEX, from_hw=False, print_ents=True, **kwargs):
        self.switch.stats["legacy_gets"] += 1
        if from_hw:
            self.switch.stats["read_from_hw"] += 1
        return _LegacyEntry(self.name, self.switch.read(self.name, REGISTER_INDEX, from_hw))

    def operation_register_sync(self, cb):
        self.switch.stats["legacy_syncs"] += 1
        self.switch.sync(self.name)
        cb(0, 0xFFFF, 0, 0)

    def mod(self, REGISTER_INDEX, f1):
        self.switch.stats["legacy_mods"] += 1
        self.switch.write(self.name, REGISTER_INDEX, f1)


def legacy_view(switch):
    """The `bfrt` object of the legacy reader's bfrt_python script, on this switch.
    A switch without a register sync has no operation_register_sync (as the
    existing FakeRegister(sync=False) of test_read_registers_inner.py)."""
    regs = dict((n, _LegacyRegister(switch, n)) for n in switch.registers)
    if not switch.sync_ops:
        for reg in regs.values():
            reg.operation_register_sync = None
    ingress = type("Ingress", (), regs)
    pipe = type("Pipe", (), {"Ingress": ingress})
    prog = type("Prog", (), {"pipe": pipe})
    return type("Bfrt", (), {"basic": prog, "complete_operations": staticmethod(lambda: None)})
