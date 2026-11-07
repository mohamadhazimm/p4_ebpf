#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Batched reader of the detector's flow registers over BF Runtime gRPC.

Per window the legacy reader (read_registers_with_index.py) starts a bfshell
session (1.4-1.5 s), syncs the 14 registers and then calls bfrt_python's
`reg.get()` once per register per bucket (~80 us each): 14 calls per bucket,
about 1.14 ms per bucket. This module does the same work with a long-lived
gRPC client and a fixed number of RPCs per window:

  1. one register `Sync` per table (14, plus reg_newconn_dst when its buckets
     are read), all issued before any read so the window's values still come
     from one snapshot. The BF Runtime server answers a Sync write only when
     the DMA has finished (bf_rt_server_impl.cpp, tableOperationWaitForCompletion,
     up to 5 s per table). With --sync-batched the 14 operations travel in one
     Write RPC (to be measured on the switch; on the Tofino model, where one
     sync takes ~2.5 s, the server's wait expires and the shadow can be stale,
     so one Write per table is the default). The request metadata `deadline_sec`
     is not used: the server rejects such writes with DEADLINE_EXCEEDED;
  2. one Read RPC per table with the whole active key list (chunked at
     --chunk keys per request), read from the driver's shadow copy
     (from_hw=False); the per-pipe values of each entry are merged with
     combine() below;
  3. one Write RPC that zeroes the 14 registers of every bucket to clear
     (one update per register per bucket, all in one batch): the idle buckets
     whose packet count still equals the caller's previous read
     (clear_if_unchanged) and the buckets the caller clears unconditionally
     (clear_indexes: buckets that left its active set unread, which would
     otherwise stay occupied and send no CPU report for the next flow).
     With nothing to read (no indexes and no dst_indexes) the syncs are
     skipped: a clear needs no snapshot.

combine() and make_row() are copies of the legacy reader's closures (the test
suite checks them textually against read_registers_with_index.INNER_TEMPLATE),
so the payload has the same keys, the same values and the same row order:

    {"source", "flow_count", "snapshot", "sync_s", "read_s", "clear_s",
     "t_switch", "errors", "dst_rows", "cleared", "timing", "rows"}

"timing" is new (per-window instrumentation: milliseconds per phase and RPC
counts); hybrid_collector.py prints it with --reader-timing.

Three routes between the key lists and the per-pipe values:

  safe  (--safe-parse)  the documented client route: entry_get() -> _Key/_Data
                        objects -> to_dict(); entry_mod() for the clears;
  fast  (default)       ReadRequest/WriteRequest built with the generated
                        protobuf classes, the ReadResponse walked directly,
                        without the client's objects;
  raw   (--raw-wire)    requests joined from per-table byte templates (one
                        entity serialized once by the protobuf classes, the key
                        bytes substituted) and responses decoded by the
                        wire-format parser of this module: the protobuf classes
                        are not used per entity. The SDE 9.6 client on the
                        switch runs protobuf without its C implementation,
                        where the generic classes cost 40-120 us per entity
                        (RUNBOOK.md Sections 9-10); the raw route costs a few
                        us whatever the implementation.

The fast and raw routes compare themselves with the safe route on the first
read of a run (--probe reports the comparison) and fall back to it if they
disagree.

Runs under Python 2.7 and 3: on the switch with the SDE 9.6 client
(/root/bf-sde-9.6.0/install/lib/python2.7/site-packages, python2.7) or on the
control host with open-p4studio's client. The SDE site-packages directories
are added to sys.path when bfrt_grpc is not importable (--sde-install,
$SDE_INSTALL, or the known installs).

Modes:
    --serve            JSON lines on stdin -> one JSON payload line per request
                       (used by hybrid_collector.py --reader batched)
    --indexes 1,2,3    one read, payload printed as the last line (same flags
                       as the legacy reader: --dst-indexes, --clear-if-unchanged,
                       --clear-indexes, --snapshot, --format json)
    --probe            connect, list the register tables, read one cell both
                       ways, time one Sync: the client/server compatibility check
    --bench 100,500    timing table: sync / read / clear per window for the
                       given active-set sizes
    --mock-cells FILE  use bfrt_mock instead of a switch (tests)
"""
from __future__ import division, print_function

import argparse
import binascii
import glob
import inspect
import json
import os
import random
import struct
import sys
import time
from collections import OrderedDict

REG_NAMES = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab",
             "reg_ref_src_port", "reg_ref_dst_port", "reg_dir_valid",
             "reg_min_len", "reg_max_len", "reg_first_ts", "reg_last_ts",
             "reg_syn", "reg_ack", "reg_rst"]
REQUIRED = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab"]
SUMMED = ["reg_pkts", "reg_bytes", "reg_pkts_ab", "reg_bytes_ab", "reg_syn", "reg_ack", "reg_rst"]
DST_REG_NAME = "reg_newconn_dst"
TABLE_PREFIX = "pipe.Ingress."
DATA_PREFIX = "Ingress."
KEY_FIELD = "$REGISTER_INDEX"
FLOW_BUCKETS = 65536
DEFAULT_GRPC_ADDR = "127.0.0.1:50052"
DEFAULT_CLIENT_ID = 7
DEFAULT_CHUNK = 4096
SDE_INSTALL_CANDIDATES = ["/root/bf-sde-9.6.0/install", "/home/ubuntu/open-p4studio/install"]
RPC_SERVICE = "bfrt_proto.BfRuntime"   # the gRPC service of bfruntime.proto (--raw-wire calls it directly)


def log(msg):
    sys.stderr.write("[batched] %s\n" % msg)
    sys.stderr.flush()


# --------------------------------------------------------------------------
# Row construction: copies of the legacy reader's closures (keep identical).

def combine(per_pipe):
    pipes = [p for p in range(len(per_pipe["reg_pkts"]))
             if per_pipe["reg_pkts"][p] or per_pipe["reg_dir_valid"][p]]
    row = {}
    for name in SUMMED:
        row[name] = sum(per_pipe[name][p] for p in pipes)
    nz = lambda name: [per_pipe[name][p] for p in pipes if per_pipe[name][p]]
    row["reg_min_len"] = min(nz("reg_min_len")) if nz("reg_min_len") else 0
    row["reg_max_len"] = max(nz("reg_max_len")) if nz("reg_max_len") else 0
    row["reg_first_ts"] = min(nz("reg_first_ts")) if nz("reg_first_ts") else 0
    row["reg_last_ts"] = max(nz("reg_last_ts")) if nz("reg_last_ts") else 0
    ref = [p for p in pipes if per_pipe["reg_dir_valid"][p]]
    row["reg_dir_valid"] = 1 if ref else 0
    row["reg_ref_src_port"] = per_pipe["reg_ref_src_port"][ref[0]] if ref else 0
    row["reg_ref_dst_port"] = per_pipe["reg_ref_dst_port"][ref[0]] if ref else 0
    return row, pipes


def make_row(idx, r, pipes):
    pkts, byt = r["reg_pkts"], r["reg_bytes"]
    first_ts, last_ts = r["reg_first_ts"], r["reg_last_ts"]
    return {
        "idx": idx,
        "pkts": pkts,
        "bytes": byt,
        "bpp": (float(byt) / pkts) if pkts else 0.0,
        "pkts_ab": r["reg_pkts_ab"],
        "pkts_ba": max(0, pkts - r["reg_pkts_ab"]),
        "bytes_ab": r["reg_bytes_ab"],
        "bytes_ba": max(0, byt - r["reg_bytes_ab"]),
        "ref_src_port": r["reg_ref_src_port"],
        "ref_dst_port": r["reg_ref_dst_port"],
        "dir_valid": r["reg_dir_valid"],
        "min_len": r["reg_min_len"],
        "max_len": r["reg_max_len"],
        "first_ts": first_ts,
        "last_ts": last_ts,
        "duration_ns": ((last_ts - first_ts) % (1 << 32)) if (first_ts and last_ts) else 0,
        "syn": r["reg_syn"],
        "ack": r["reg_ack"],
        "rst": r["reg_rst"],
        "pipes": pipes,
        "multi_pipe": len(pipes) > 1,
    }


def make_dst_row(idx, per_pipe):
    return {"idx": idx, "new_conn": sum(per_pipe),
            "pipes": [p for p in range(len(per_pipe)) if per_pipe[p]]}


def rows_from_per_pipe(indexes, per_idx):
    """per_idx[idx][reg_name] = list of per-pipe values -> rows in index order,
    with the legacy padding of shorter lists."""
    rows = []
    for idx in indexes:
        per_pipe = per_idx[idx]
        n = max(len(v) for v in per_pipe.values())
        for name in per_pipe:
            per_pipe[name] = (per_pipe[name] + [0] * n)[:n]
        r, pipes = combine(per_pipe)
        rows.append(make_row(idx, r, pipes))
    return rows


# --------------------------------------------------------------------------
# Byte helpers (Python 2 and 3).

def bytes_to_int(b):
    b = bytes(b)
    return int(binascii.hexlify(b), 16) if b else 0


def int_to_bytes(n, length):
    h = "%x" % n
    h = ("0" * (len(h) % 2) + h).zfill(length * 2)
    return binascii.unhexlify(h)


def accepts_kwarg(func, name):
    try:
        spec = inspect.getfullargspec(func)
        return name in spec.args or spec.varkw is not None
    except AttributeError:  # Python 2
        spec = inspect.getargspec(func)
        return name in spec.args or spec.keywords is not None
    except TypeError:
        return False


def protobuf_info():
    """'<version>/<implementation>' of the protobuf package in use; the pure
    'python' implementation is what makes the fast route slow on the switch."""
    try:
        import google.protobuf
        from google.protobuf.internal import api_implementation
        return "%s/%s" % (getattr(google.protobuf, "__version__", "?"), api_implementation.Type())
    except Exception:
        return None


# --------------------------------------------------------------------------
# Wire format (--raw-wire): byte templates for the requests, a parser for the
# ReadResponse. Field numbers from bfruntime.proto: ReadResponse.entities 1,
# Entity.table_entry 1, TableEntry.key 2 / data 3, TableKey.fields 1,
# KeyField.exact 2, Exact.value 1, TableData.fields 2, DataField.field_id 1 /
# stream 2 / int_arr_val 5, IntArray.val 1. Unknown fields are skipped.

def encode_varint(n):
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def key_packer(size):
    """bucket index -> big-endian key bytes of the table's key size."""
    fmt = {1: ">B", 2: ">H", 4: ">I", 8: ">Q"}.get(size)
    if fmt:
        return lambda idx: struct.pack(fmt, idx)
    return lambda idx: int_to_bytes(idx, size)


def field_tag(msg_class, field_name):
    """Tag bytes of a length-delimited field of a generated message class."""
    return encode_varint((msg_class.DESCRIPTOR.fields_by_name[field_name].number << 3) | 2)


def locate_key(build, key_size):
    """build(key_bytes) -> serialized message. Returns (head, tail) around the
    key bytes, found by serializing with two different placeholder keys."""
    a = build(bytes(bytearray([0xA5] * key_size)))
    b = build(bytes(bytearray([0x5A] * key_size)))
    diff = [i for i in range(min(len(a), len(b))) if a[i:i + 1] != b[i:i + 1]]
    if len(a) != len(b) or len(diff) != key_size or diff[-1] - diff[0] + 1 != key_size:
        raise RuntimeError("could not locate the key bytes in the serialized entity")
    return a[:diff[0]], a[diff[0] + key_size:]


def _varint(buf, pos):
    b = buf[pos]
    if b < 0x80:
        return b, pos + 1
    result = b & 0x7F
    shift = 7
    pos += 1
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, pos
        shift += 7


def _skip(buf, pos, wire_type):
    if wire_type == 0:
        while buf[pos] >= 0x80:
            pos += 1
        return pos + 1
    if wire_type == 2:
        ln, pos = _varint(buf, pos)
        return pos + ln
    if wire_type == 1:
        return pos + 8
    if wire_type == 5:
        return pos + 4
    raise ValueError("unsupported wire type %d" % wire_type)


def _to_int(buf, pos, end):
    n = 0
    for i in range(pos, end):
        n = (n << 8) | buf[i]
    return n


def parse_read_response(wire, data_id, out):
    """Decode one serialized ReadResponse into out[idx] = per-pipe values of
    the data field data_id (one DataField per pipe with `stream` bytes, as the
    BF Runtime server sends, or one int_arr_val). Returns the entries added."""
    buf = bytearray(wire)
    n = len(buf)
    pos = 0
    added = 0
    while pos < n:
        tag, pos = _varint(buf, pos)
        if tag != 0x0A:                                  # ReadResponse.entities
            pos = _skip(buf, pos, tag & 7)
            continue
        ln, pos = _varint(buf, pos)
        ent_end = pos + ln
        idx = None
        vals = []
        while pos < ent_end:                             # Entity
            tag, pos = _varint(buf, pos)
            if tag != 0x0A:                              # Entity.table_entry
                pos = _skip(buf, pos, tag & 7)
                continue
            ln, pos = _varint(buf, pos)
            te_end = pos + ln
            while pos < te_end:                          # TableEntry
                tag, pos = _varint(buf, pos)
                if tag == 0x12:                          # key
                    ln, pos = _varint(buf, pos)
                    k_end = pos + ln
                    while pos < k_end:                   # TableKey.fields
                        tag, pos = _varint(buf, pos)
                        if tag != 0x0A:
                            pos = _skip(buf, pos, tag & 7)
                            continue
                        ln, pos = _varint(buf, pos)
                        kf_end = pos + ln
                        while pos < kf_end:              # KeyField
                            tag, pos = _varint(buf, pos)
                            if tag == 0x12:              # exact
                                ln, pos = _varint(buf, pos)
                                ex_end = pos + ln
                                while pos < ex_end:      # Exact.value
                                    tag, pos = _varint(buf, pos)
                                    if tag == 0x0A:
                                        ln, pos = _varint(buf, pos)
                                        idx = _to_int(buf, pos, pos + ln)
                                        pos += ln
                                    else:
                                        pos = _skip(buf, pos, tag & 7)
                            else:
                                pos = _skip(buf, pos, tag & 7)
                elif tag == 0x1A:                        # data
                    ln, pos = _varint(buf, pos)
                    d_end = pos + ln
                    while pos < d_end:                   # TableData
                        tag, pos = _varint(buf, pos)
                        if tag != 0x12:                  # TableData.fields
                            pos = _skip(buf, pos, tag & 7)
                            continue
                        ln, pos = _varint(buf, pos)
                        df_end = pos + ln
                        fid = None
                        val = None
                        arr = None
                        while pos < df_end:              # DataField
                            tag, pos = _varint(buf, pos)
                            if tag == 0x08:              # field_id
                                fid, pos = _varint(buf, pos)
                            elif tag == 0x12:            # stream
                                ln, pos = _varint(buf, pos)
                                val = _to_int(buf, pos, pos + ln)
                                pos += ln
                            elif tag == 0x2A:            # int_arr_val
                                ln, pos = _varint(buf, pos)
                                ia_end = pos + ln
                                arr = []
                                while pos < ia_end:      # IntArray.val, packed or not
                                    tag, pos = _varint(buf, pos)
                                    if tag == 0x08:
                                        x, pos = _varint(buf, pos)
                                        arr.append(x)
                                    elif tag == 0x0A:
                                        ln, pos = _varint(buf, pos)
                                        p_end = pos + ln
                                        while pos < p_end:
                                            x, pos = _varint(buf, pos)
                                            arr.append(x)
                                    else:
                                        pos = _skip(buf, pos, tag & 7)
                            else:
                                pos = _skip(buf, pos, tag & 7)
                        if fid == data_id:
                            if val is not None:
                                vals.append(val)
                            elif arr:
                                vals.extend(arr)
                else:
                    pos = _skip(buf, pos, tag & 7)
        if idx is not None and vals:
            out[idx] = vals
            added += 1
    return added


# --------------------------------------------------------------------------
# Client import (real SDE client or the mock).

def sde_site_packages(sde_install=None):
    roots = []
    for root in [sde_install, os.environ.get("SDE_INSTALL")] + SDE_INSTALL_CANDIDATES:
        if root and root not in roots:
            roots.append(root)
    paths = []
    for root in roots:
        for sp in sorted(glob.glob(os.path.join(root, "lib", "python*", "site-packages"))):
            for p in (os.path.join(sp, "tofino"), sp):
                if os.path.isdir(p) and p not in paths:
                    paths.append(p)
    return paths


def import_client(sde_install=None):
    """Import bfrt_grpc.client with the SDE's own grpc/protobuf ahead of the
    system's (a system protobuf older than the one the SDE generated its
    modules with cannot load them)."""
    for p in reversed(sde_site_packages(sde_install)):
        if p not in sys.path:
            sys.path.insert(0, p)
    import bfrt_grpc.client as gc
    return gc


def connect(gc, grpc_addr, client_id, device_id, p4_name, bind=True):
    """ClientInterface + bfrt info. With bind, the client subscribes and binds to
    the program (a client association only, the device is not reconfigured);
    only one client can hold that binding, so when another one does
    (ALREADY_EXISTS) the connection is remade as an independent client that
    names the program in every request. Returns (iface, info, bound)."""
    iface = gc.ClientInterface(grpc_addr, client_id=client_id, device_id=device_id,
                               perform_subscribe=bool(bind))
    info = iface.bfrt_info_get(p4_name)
    if not bind:
        return iface, info, False
    try:
        iface.bind_pipeline_config(p4_name)
        return iface, info, True
    except Exception as error:
        if "ALREADY_EXISTS" not in str(error) and "already owns" not in str(error):
            raise
        log("another client is bound to %s (%s): continuing as an independent client"
            % (p4_name, str(error).strip().splitlines()[0][:120]))
        try:
            iface.tear_down_stream()
        except Exception:
            pass
        iface = gc.ClientInterface(grpc_addr, client_id=client_id, device_id=device_id, perform_subscribe=False)
        info = iface.bfrt_info_get(p4_name)
        return iface, info, False


# --------------------------------------------------------------------------

class RegisterTable(object):
    """One register table of the program and the ids the requests need."""

    def __init__(self, name, tbl):
        self.name = name                       # reg_pkts
        self.tbl = tbl
        self.full_name = tbl.info.name_get()   # pipe.Ingress.reg_pkts
        self.table_id = tbl.info.id_get()
        self.data_name = DATA_PREFIX + name + ".f1"
        # Field ids and sizes feed the fast request builder; a client without
        # these accessors still works through entry_get()/entry_mod() (ids_ok False).
        self.ids_ok = True
        try:
            self.key_id = tbl.info.key_field_id_get(KEY_FIELD)
            self.data_id = tbl.info.data_field_id_get(self.data_name)
        except Exception:
            self.key_id = self.data_id = None
            self.ids_ok = False
        try:
            self.key_size = tbl.info.key_field_size_get(KEY_FIELD)[0]
        except Exception:
            self.key_size = 4
        try:
            self.data_size = tbl.info.data_field_size_get(self.data_name)[0]
        except Exception:
            self.data_size = 4
        self.pack_key = key_packer(self.key_size)
        self.templates = {}   # --raw-wire: (head, tail) bytes around the key of one serialized entity
        self.sync_op = None
        try:
            ops = list(tbl.info.operations_supported_get() or [])
        except Exception:
            ops = ["Sync"]
        for op in ("Sync", "SyncRegisters"):
            if op in ops:
                self.sync_op = op
                break

    def raw_read_entity(self, pb2, from_hw):
        """(head, tail) of one serialized ReadRequest.entities element of this table."""
        key = ("read", bool(from_hw))
        if key not in self.templates:
            tag = field_tag(pb2.ReadRequest, "entities")

            def build(k):
                ent = pb2.Entity()
                te = ent.table_entry
                te.table_id = self.table_id
                te.table_flags.from_hw = bool(from_hw)
                kf = te.key.fields.add()
                kf.field_id = self.key_id
                kf.exact.value = k
                body = ent.SerializeToString()
                return tag + encode_varint(len(body)) + body
            self.templates[key] = locate_key(build, self.key_size)
        return self.templates[key]

    def raw_clear_update(self, pb2):
        """(head, tail) of one serialized WriteRequest.updates element zeroing this register."""
        if "clear" not in self.templates:
            tag = field_tag(pb2.WriteRequest, "updates")
            zero = int_to_bytes(0, self.data_size)

            def build(k):
                upd = pb2.Update()
                upd.type = pb2.Update.MODIFY
                te = upd.entity.table_entry
                te.table_id = self.table_id
                kf = te.key.fields.add()
                kf.field_id = self.key_id
                kf.exact.value = k
                df = te.data.fields.add()
                df.field_id = self.data_id
                df.stream = zero
                body = upd.SerializeToString()
                return tag + encode_varint(len(body)) + body
            self.templates["clear"] = locate_key(build, self.key_size)
        return self.templates["clear"]


class BatchedRegisterReader(object):
    """read_window(): one snapshot of the active buckets, legacy payload."""

    def __init__(self, gc, iface, info, p4_name="basic", strict=False, chunk=DEFAULT_CHUNK,
                 fast=True, device_id=0, sync_batched=False, p4_name_in_requests=False, raw=False):
        self.gc = gc
        self.iface = iface
        self.info = info
        self.p4_name = p4_name
        self.strict = strict
        self.chunk = max(1, int(chunk))
        self.device_id = device_id
        self.sync_batched = bool(sync_batched)
        self.p4_name_in_requests = p4_name_in_requests
        self.target = gc.Target(device_id=device_id, pipe_id=0xFFFF)
        self.pb2 = getattr(gc, "bfruntime_pb2", None)
        self.fast = bool(fast) and self.pb2 is not None
        self.checked = set()   # routes compared with the safe one on the first read of the run
        self.rw = getattr(iface, "reader_writer_interface", None)
        if self.rw is None:
            self.fast = False
        # The raw route sends bytes through the client's grpc channel itself.
        self.channel = getattr(iface, "channel", None)
        self.raw = bool(raw) and self.pb2 is not None and self.channel is not None
        self._raw_read_call = self._raw_write_call = None
        self._raw_heads = {}
        if self.raw:
            try:
                self._raw_read_call = self.channel.unary_stream("/%s/Read" % RPC_SERVICE)
                self._raw_write_call = self.channel.unary_unary("/%s/Write" % RPC_SERVICE)
            except Exception as error:
                log("no raw calls on the client's channel (%s)" % error)
                self.raw = False
        if bool(raw) and not self.raw:
            log("the wire-format route needs the protobuf module and the client's grpc channel: using the %s route"
                % ("fast" if self.fast else "safe"))
        self.tables = OrderedDict()
        for name in REG_NAMES:
            try:
                self.tables[name] = RegisterTable(name, info.table_get(TABLE_PREFIX + name))
            except KeyError:
                if strict and name in REQUIRED:
                    raise RuntimeError("Required register is missing from pipeline: " + name)
                self.tables[name] = None
        try:
            self.dst_table = RegisterTable(DST_REG_NAME, info.table_get(TABLE_PREFIX + DST_REG_NAME))
        except KeyError:
            self.dst_table = None
        self.flow_tables = [t for t in self.tables.values() if t is not None]
        if (self.fast or self.raw) and not all(t.ids_ok for t in self.flow_tables + [self.dst_table]
                                               if t is not None):
            log("the client does not expose the field ids: using entry_get()/entry_mod() only")
            self.fast = self.raw = False
        self.windows = 0

    def route(self):
        """The route in use: 'raw', 'fast' or 'safe'."""
        return "raw" if self.raw else ("fast" if self.fast else "safe")

    # ---------------------------------------------------------------- sync

    def _sync_all(self, tables, timing):
        if any(t.sync_op is None for t in tables):
            raise RuntimeError("register sync is not supported by this build: " +
                               ", ".join(t.name for t in tables if t.sync_op is None))
        t0 = time.time()
        if self.fast and self.sync_batched:
            req = self.pb2.WriteRequest()
            self._fill_target(req)
            for t in tables:
                upd = req.updates.add()
                upd.type = self.pb2.Update.INSERT
                upd.entity.table_operation.table_id = t.table_id
                upd.entity.table_operation.table_operations_type = t.sync_op
            self.rw._write(req)
            timing["sync_rpcs"] = 1
        else:
            kw = {}
            if self.p4_name_in_requests and accepts_kwarg(tables[0].tbl.operations_execute, "p4_name"):
                kw["p4_name"] = self.p4_name
            for t in tables:
                t.tbl.operations_execute(self.target, t.sync_op, **kw)
            timing["sync_rpcs"] = len(tables)
        timing["sync_ms"] = round((time.time() - t0) * 1000.0, 3)

    # ---------------------------------------------------------------- read

    def _fill_target(self, req):
        req.target.device_id = self.device_id
        req.target.pipe_id = 0xFFFF
        req.target.direction = 0xFF
        req.target.prsr_id = 0xFF
        if self.p4_name_in_requests:
            req.p4_name = self.p4_name

    def _read_fast(self, t, indexes, from_hw, timing):
        """dict idx -> per-pipe list, for the indexes the server returned."""
        values = {}
        for start in range(0, len(indexes), self.chunk):
            chunk = indexes[start:start + self.chunk]
            req = self.pb2.ReadRequest()
            self._fill_target(req)
            for idx in chunk:
                te = req.entities.add().table_entry
                te.table_id = t.table_id
                te.table_flags.from_hw = bool(from_hw)
                kf = te.key.fields.add()
                kf.field_id = t.key_id
                kf.exact.value = int_to_bytes(idx, t.key_size)
            timing["read_rpcs"] += 1
            for rsp in self.rw._read(req):
                for ent in rsp.entities:
                    te = ent.table_entry
                    if not te.key.fields:
                        continue
                    idx = bytes_to_int(te.key.fields[0].exact.value)
                    # The server sends one data field per pipe (same field id, bytes
                    # in `stream`); a client that squashes them uses int_arr_val.
                    vals = []
                    for f in te.data.fields:
                        if f.field_id != t.data_id:
                            continue
                        if f.HasField("stream"):
                            vals.append(bytes_to_int(f.stream))
                        elif f.HasField("int_arr_val"):
                            vals.extend(int(x) for x in f.int_arr_val.val)
                    if vals:
                        values[idx] = vals
                        timing["read_entities"] += 1
        return values

    def _read_safe(self, t, indexes, from_hw, timing):
        gc = self.gc
        values = {}
        kw = {}
        if self.p4_name_in_requests and accepts_kwarg(t.tbl.entry_get, "p4_name"):
            kw["p4_name"] = self.p4_name
        for start in range(0, len(indexes), self.chunk):
            chunk = indexes[start:start + self.chunk]
            keys = [t.tbl.make_key([gc.KeyTuple(KEY_FIELD, i)]) for i in chunk]
            timing["read_rpcs"] += 1
            for data, key in t.tbl.entry_get(self.target, keys, {"from_hw": bool(from_hw)}, **kw):
                idx = key.to_dict()[KEY_FIELD]["value"]
                v = data.to_dict()[t.data_name]
                if not isinstance(v, (list, tuple)):
                    v = [v]
                values[int(idx)] = [int(x) for x in v]
                timing["read_entities"] += 1
        return values

    def _raw_head(self, cls):
        """Serialized target, client id (and p4_name) of a request: the bytes before the entities."""
        if cls not in self._raw_heads:
            req = cls()
            self._fill_target(req)
            req.client_id = getattr(self.rw, "client_id", getattr(self.iface, "client_id", 0))
            self._raw_heads[cls] = req.SerializeToString()
        return self._raw_heads[cls]

    def _read_raw(self, t, indexes, from_hw, timing):
        """Like _read_fast, from byte templates and the wire-format parser."""
        head, tail = t.raw_read_entity(self.pb2, from_hw)
        prefix = self._raw_head(self.pb2.ReadRequest)
        pack = t.pack_key
        values = {}
        for start in range(0, len(indexes), self.chunk):
            chunk = indexes[start:start + self.chunk]
            req = prefix + b"".join([head + pack(idx) + tail for idx in chunk])
            timing["read_rpcs"] += 1
            for rsp in self._raw_read_call(req):
                timing["read_entities"] += parse_read_response(rsp, t.data_id, values)
        return values

    def _read_route(self, route, t, indexes, from_hw, timing):
        if route == "raw":
            return self._read_raw(t, indexes, from_hw, timing)
        if route == "fast":
            return self._read_fast(t, indexes, from_hw, timing)
        return self._read_safe(t, indexes, from_hw, timing)

    def _read_table(self, t, indexes, from_hw, timing):
        # First read of the run: compare the route in use with the client's own
        # parser on a sample; on disagreement fall back to the next route.
        while self.route() != "safe" and self.route() not in self.checked:
            route = self.route()
            self.checked.add(route)
            sample = list(indexes[:4])
            probe = dict(read_rpcs=0, read_entities=0)
            want = self._read_safe(t, sample, from_hw, probe)
            try:
                got = self._read_route(route, t, sample, from_hw, probe)
            except Exception as error:
                got = "error: %s" % error
            if want != got:
                log("the %s route disagrees with the client's parser (%r vs %r): not using it" % (route, got, want))
                if route == "raw":
                    self.raw = False
                else:
                    self.fast = False
        return self._read_route(self.route(), t, indexes, from_hw, timing)

    # ---------------------------------------------------------------- clear

    def _clear(self, indexes, timing):
        t0 = time.time()
        if self.raw:
            parts = [self._raw_head(self.pb2.WriteRequest)]
            for t in self.flow_tables:
                head, tail = t.raw_clear_update(self.pb2)
                pack = t.pack_key
                parts.append(b"".join([head + pack(idx) + tail for idx in indexes]))
            self._raw_write_call(b"".join(parts))
            timing["clear_rpcs"] = 1
        elif self.fast:
            req = self.pb2.WriteRequest()
            self._fill_target(req)
            for t in self.flow_tables:
                zero = int_to_bytes(0, t.data_size)
                for idx in indexes:
                    upd = req.updates.add()
                    upd.type = self.pb2.Update.MODIFY
                    te = upd.entity.table_entry
                    te.table_id = t.table_id
                    kf = te.key.fields.add()
                    kf.field_id = t.key_id
                    kf.exact.value = int_to_bytes(idx, t.key_size)
                    df = te.data.fields.add()
                    df.field_id = t.data_id
                    df.stream = zero
            self.rw._write(req)
            timing["clear_rpcs"] = 1
        else:
            gc = self.gc
            kw = {}
            if self.p4_name_in_requests and accepts_kwarg(self.flow_tables[0].tbl.entry_mod, "p4_name"):
                kw["p4_name"] = self.p4_name
            for t in self.flow_tables:
                keys = [t.tbl.make_key([gc.KeyTuple(KEY_FIELD, i)]) for i in indexes]
                datas = [t.tbl.make_data([gc.DataTuple(t.data_name, 0)]) for _ in indexes]
                t.tbl.entry_mod(self.target, keys, datas, **kw)
            timing["clear_rpcs"] = len(self.flow_tables)
        timing["clear_ms"] = round((time.time() - t0) * 1000.0, 3)

    # ---------------------------------------------------------------- window

    def read_window(self, indexes, dst_indexes=None, clear_if_unchanged=None, snapshot="sync",
                    source="batched gRPC", clear_indexes=None):
        """snapshot: "sync" (register sync, then shadow reads), "hw" (hardware
        reads, no sync) or "shadow" (shadow reads without a sync; benchmarks).
        clear_indexes: buckets cleared unconditionally after the read (they need
        not be read; one Write RPC with the clear_if_unchanged clears)."""
        indexes = [int(i) for i in indexes]
        dst_indexes = [int(i) for i in (dst_indexes or [])]
        clear_if_unchanged = clear_if_unchanged or {}
        clear_indexes = [int(i) for i in (clear_indexes or [])]
        timing = OrderedDict([("active", len(indexes)), ("dst", len(dst_indexes)),
                              ("sync_ms", 0.0), ("sync_rpcs", 0), ("read_ms", 0.0), ("read_rpcs", 0),
                              ("read_entities", 0), ("clear_ms", 0.0), ("clear_rpcs", 0),
                              ("cleared", 0), ("cleared_unconditional", 0), ("parser", self.route())])
        t_start = time.time()
        errors = []
        sync_s = None
        sync_tables = list(self.flow_tables)
        if dst_indexes and self.dst_table is not None:
            sync_tables.append(self.dst_table)
        if snapshot == "sync" and not indexes and not dst_indexes:
            sync_s = 0.0          # nothing to read: a clear needs no snapshot
        elif snapshot == "sync":
            try:
                self._sync_all(sync_tables, timing)
                ok = True
            except Exception as error:
                log("register sync failed (%s); reading from hardware" % error)
                ok = False
            sync_s = round(time.time() - t_start, 4)
            if not ok:
                snapshot = "hw"
        from_hw = snapshot == "hw"

        t_read = time.time()
        per_idx = dict((idx, {}) for idx in indexes)
        for name, t in self.tables.items():
            if t is None:
                for idx in indexes:
                    per_idx[idx][name] = [0]
                continue
            try:
                values = self._read_table(t, indexes, from_hw, timing) if indexes else {}
            except Exception as error:
                if self.strict and name in REQUIRED:
                    raise RuntimeError("Could not read required register %s: %s" % (name, error))
                errors.append("%s: %s" % (name, error))
                values = {}
            for idx in indexes:
                v = values.get(idx)
                if v is None:
                    if not errors or not errors[-1].startswith(name + ":"):
                        errors.append("%s[%d]: missing in the response" % (name, idx))
                    v = [0]
                per_idx[idx][name] = list(v)
        rows = rows_from_per_pipe(indexes, per_idx)

        dst_rows = []
        if dst_indexes:
            if self.dst_table is None:
                errors.append("Register is missing from pipeline: " + DST_REG_NAME)
            else:
                try:
                    values = self._read_table(self.dst_table, dst_indexes, from_hw, timing)
                except Exception as error:
                    errors.append("%s: %s" % (DST_REG_NAME, error))
                    values = {}
                for idx in dst_indexes:
                    v = values.get(idx)
                    if v is None:
                        errors.append("%s[%d]: missing in the response" % (DST_REG_NAME, idx))
                        continue
                    dst_rows.append(make_dst_row(idx, list(v)))
        timing["read_ms"] = round((time.time() - t_read) * 1000.0, 3)
        read_s = round(time.time() - t_start, 4)

        # Clear idle buckets whose packet count is still what the caller saw,
        # and the buckets the caller clears unconditionally, in one Write.
        cleared = []
        pkts_now = dict((r["idx"], r["pkts"]) for r in rows)
        to_clear = []
        for key, prev_pkts in sorted(clear_if_unchanged.items(), key=lambda kv: str(kv[0])):
            idx = int(key)
            if pkts_now.get(idx) != int(prev_pkts):
                continue
            to_clear.append(idx)
        seen = set(to_clear)
        unconditional = []
        for idx in clear_indexes:
            if idx not in seen:
                seen.add(idx)
                to_clear.append(idx)
                unconditional.append(idx)
        if to_clear:
            try:
                self._clear(to_clear, timing)
                cleared = list(to_clear)
                timing["cleared_unconditional"] = len(unconditional)
            except Exception as error:
                errors.append("clear %s: %s" % (to_clear, error))
        timing["cleared"] = len(cleared)
        self.windows += 1

        return OrderedDict([
            ("source", source),
            ("flow_count", len(rows)),
            ("snapshot", snapshot),
            ("sync_s", sync_s),
            ("read_s", read_s),
            ("clear_s", round(time.time() - t_start - read_s, 4)),
            ("t_switch", t_start),
            ("errors", errors),
            ("dst_rows", dst_rows),
            ("cleared", cleared),
            ("timing", timing),
            ("rows", rows),
        ])

    def close(self):
        try:
            if not getattr(self.iface, "is_independent", True):
                self.iface.tear_down_stream()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Modes

def parse_clear_arg(text):
    out = {}
    for item in (text or "").split(","):
        item = item.strip()
        if item:
            idx, pkts = item.split(":")
            out[int(idx)] = int(pkts)
    return out


def parse_int_list(text):
    return [int(x) for x in (text or "").replace(",", " ").split() if x.strip()]


def open_reader(args):
    if args.mock_cells:
        import bfrt_mock
        gc = bfrt_mock
        bfrt_mock.serve_from_file(args.mock_cells, args.grpc_addr, hang_on=args.mock_hang_on,
                                  hang_marker=args.mock_hang_marker)
    else:
        gc = import_client(args.sde_install)
    iface, info, bound = connect(gc, args.grpc_addr, args.client_id, args.device_id, args.p4_name, bind=args.bind)
    reader = BatchedRegisterReader(gc, iface, info, p4_name=args.p4_name, strict=args.strict_core_registers,
                                   chunk=args.chunk, fast=not args.safe_parse, device_id=args.device_id,
                                   sync_batched=args.sync_batched, p4_name_in_requests=not bound,
                                   raw=args.raw_wire and not args.safe_parse)
    return gc, reader


def describe(reader):
    return OrderedDict([
        ("p4", reader.p4_name),
        ("tables", [t.name for t in reader.flow_tables]),
        ("missing", [n for n, t in reader.tables.items() if t is None]),
        ("dst_table", reader.dst_table is not None),
        ("sync_ops", dict((t.name, t.sync_op) for t in reader.flow_tables)),
        ("fast", reader.fast),
        ("raw", reader.raw),
        ("parser", reader.route()),
        ("protobuf", protobuf_info()),
        ("bound", not reader.p4_name_in_requests),
        ("sync_batched", reader.sync_batched),
        ("chunk", reader.chunk),
    ])


def serve(args):
    gc, reader = open_reader(args)
    ready = describe(reader)
    ready["ready"] = True
    ready["pid"] = os.getpid()
    sys.stdout.write(json.dumps(ready) + "\n")
    sys.stdout.flush()
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError as error:
            sys.stdout.write(json.dumps({"error": "bad request: %s" % error}) + "\n")
            sys.stdout.flush()
            continue
        cmd = req.get("cmd")
        if cmd == "quit":
            break
        if cmd == "ping":
            sys.stdout.write(json.dumps({"pong": True, "windows": reader.windows}) + "\n")
            sys.stdout.flush()
            continue
        try:
            payload = reader.read_window(req.get("indexes") or [], req.get("dst_indexes") or [],
                                         req.get("clear_if_unchanged") or {}, req.get("snapshot", "sync"),
                                         req.get("source", "batched gRPC"), req.get("clear_indexes") or [])
            out = json.dumps(payload)
        except Exception as error:
            out = json.dumps({"error": "%s: %s" % (type(error).__name__, error)})
        sys.stdout.write(out + "\n")
        sys.stdout.flush()
    reader.close()


def one_shot(args):
    gc, reader = open_reader(args)
    idxs = []
    for i in parse_int_list(args.indexes):
        if not 0 <= i < FLOW_BUCKETS:
            sys.exit("[ERROR] index %d outside [0, %d)" % (i, FLOW_BUCKETS))
        if i not in idxs:
            idxs.append(i)
    dst = []
    for i in parse_int_list(args.dst_indexes):
        if i not in dst:
            dst.append(i)
    clear = parse_clear_arg(args.clear_if_unchanged)
    unread = sorted(set(clear) - set(idxs))
    if unread:
        sys.exit("[ERROR] --clear-if-unchanged lists buckets that are not read: %s" % unread)
    unconditional = []
    for i in parse_int_list(args.clear_indexes):
        if not 0 <= i < FLOW_BUCKETS:
            sys.exit("[ERROR] --clear-indexes: index %d outside [0, %d)" % (i, FLOW_BUCKETS))
        if i not in unconditional:
            unconditional.append(i)
    payload = reader.read_window(idxs, dst, clear, args.snapshot, "indices from CLI (batched gRPC)", unconditional)
    reader.close()
    if args.format == "json":
        print(json.dumps(payload))
        return
    rows = payload["rows"]
    tot_pkts = sum(r["pkts"] for r in rows)
    tot_bytes = sum(r["bytes"] for r in rows)
    print("=== OVERALL (%s, snapshot %s) ===" % (payload["source"], payload["snapshot"]))
    print("Flows: %d" % len(rows))
    print("Total pkts: %d" % tot_pkts)
    print("Total bytes: %d" % tot_bytes)
    print("Timing: %s" % json.dumps(payload["timing"]))
    for r in rows:
        print(json.dumps(r))
    if payload["errors"]:
        print("Errors: %s" % payload["errors"])


def probe(args):
    """Connect and exercise each RPC once; prints one JSON line."""
    out = OrderedDict([("grpc_addr", args.grpc_addr), ("python", sys.version.split()[0])])
    t0 = time.time()
    gc, reader = open_reader(args)
    out["client"] = getattr(gc, "__file__", "?")
    out["connect_s"] = round(time.time() - t0, 3)
    out.update(describe(reader))
    t = reader.tables["reg_pkts"]
    timing = dict(read_rpcs=0, read_entities=0)
    safe = reader._read_safe(t, [0, 1], False, timing)
    out["safe_read"] = dict((str(k), v) for k, v in safe.items())
    if reader.pb2 is not None:
        fast = reader._read_fast(t, [0, 1], False, timing)
        out["fast_read"] = dict((str(k), v) for k, v in fast.items())
        out["fast_equals_safe"] = fast == safe
    if reader.raw:
        try:
            raw = reader._read_raw(t, [0, 1], False, timing)
            out["raw_read"] = dict((str(k), v) for k, v in raw.items())
            out["raw_equals_safe"] = raw == safe
        except Exception as error:
            out["raw_error"] = str(error)
            out["raw_equals_safe"] = False
    out["pipes"] = len(list(safe.values())[0]) if safe else None
    tm = {}
    try:
        reader._sync_all([reader.tables["reg_dir_valid"]], tm)
        out["sync_reg_dir_valid_ms"] = tm.get("sync_ms")
    except Exception as error:
        out["sync_error"] = str(error)
    reader.close()
    print(json.dumps(out))


def bench(args):
    """Timing table: for each active-set size, --bench-windows windows of
    sync + read (+ a clear of all buckets when --bench-clear)."""
    gc, reader = open_reader(args)
    sizes = parse_int_list(args.bench)
    rng = random.Random(args.seed)
    # "shadow": no Sync, read the driver's copy as it is (the Read path alone).
    snapshot = "shadow" if args.bench_nosync else "sync"
    results = []
    print("| active buckets | sync ms | read ms | clear ms | total ms | us/bucket | fits %.1f s? |"
          % args.bench_budget)
    print("|---|---|---|---|---|---|---|")
    for n in sizes:
        indexes = sorted(rng.sample(range(FLOW_BUCKETS), n))
        per = []
        errors = []
        cleared = 0
        for w in range(args.bench_windows):
            clear = {}
            if args.bench_clear:
                # Read first, then clear every bucket at its current count (as the
                # collector would for idle buckets).
                first = reader.read_window(indexes, [], {}, snapshot)
                clear = dict((r["idx"], r["pkts"]) for r in first["rows"])
                errors.extend(first["errors"])
            p = reader.read_window(indexes, [], clear, snapshot)
            per.append(p["timing"])
            errors.extend(p["errors"])
            cleared += len(p["cleared"])
            if p["errors"]:
                # A failed clear or read shows as a short time otherwise.
                log("bench %d buckets, window %d: %d error(s), e.g. %s" % (n, w, len(p["errors"]), p["errors"][0]))
        med = lambda key: sorted(x[key] for x in per)[len(per) // 2]
        sync_ms, read_ms, clear_ms = med("sync_ms"), med("read_ms"), med("clear_ms")
        total = sync_ms + read_ms + clear_ms
        row = OrderedDict([("active", n), ("windows", len(per)), ("sync_ms", sync_ms), ("read_ms", read_ms),
                           ("clear_ms", clear_ms), ("total_ms", round(total, 3)),
                           ("us_per_bucket", round(total * 1000.0 / n, 2)),
                           ("fits", total <= args.bench_budget * 1000.0), ("parser", per[0]["parser"]),
                           ("read_rpcs", per[0]["read_rpcs"]), ("sync_rpcs", per[0]["sync_rpcs"]),
                           ("read_entities", per[0]["read_entities"]), ("cleared", cleared),
                           ("errors", len(errors)), ("first_error", errors[0] if errors else None)])
        results.append(row)
        print("| %d | %.1f | %.1f | %.1f | %.1f | %.1f | %s |" % (
            n, sync_ms, read_ms, clear_ms, total, row["us_per_bucket"],
            ("yes" if row["fits"] else "no") + (" (%d errors)" % len(errors) if errors else "")))
        sys.stdout.flush()
    reader.close()
    if args.out:
        with open(args.out, "w") as f:
            json.dump({"grpc_addr": args.grpc_addr, "python": sys.version.split()[0], "snapshot": snapshot,
                       "chunk": reader.chunk, "parser": reader.route(), "protobuf": protobuf_info(),
                       "sync_batched": reader.sync_batched, "windows": args.bench_windows,
                       "results": results}, f, indent=1)
        print("-> %s" % args.out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--grpc-addr", default=DEFAULT_GRPC_ADDR)
    ap.add_argument("--client-id", type=int, default=DEFAULT_CLIENT_ID)
    ap.add_argument("--device-id", type=int, default=0)
    ap.add_argument("--p4-name", default="basic")
    ap.add_argument("--bind", type=int, default=1, help="bind the client to the program (default 1)")
    ap.add_argument("--sde-install", help="SDE install whose python site-packages hold bfrt_grpc")
    ap.add_argument("--chunk", type=int, default=DEFAULT_CHUNK, help="keys per Read request")
    ap.add_argument("--safe-parse", action="store_true", help="use entry_get()/to_dict() only")
    ap.add_argument("--raw-wire", action="store_true",
                    help="build the requests from byte templates and decode the responses with this module's "
                         "wire-format parser (no protobuf class per entity; checked against the client's parser "
                         "on the first read)")
    ap.add_argument("--sync-batched", action="store_true",
                    help="send the 14 register Syncs in one Write RPC (default: one Write per table)")
    ap.add_argument("--strict-core-registers", action="store_true")
    ap.add_argument("--mock-cells", help="JSON of bfrt_mock cells: use the mock instead of a switch")
    ap.add_argument("--mock-hang-on", type=int, default=0, help="mock: hang on this Read request (tests)")
    ap.add_argument("--mock-hang-marker", help="mock: hang only once, recorded in this file (tests)")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--bench", help="comma-separated active-set sizes")
    ap.add_argument("--bench-windows", type=int, default=5)
    ap.add_argument("--bench-clear", type=int, default=1, help="also time clearing all buckets (default 1)")
    ap.add_argument("--bench-nosync", action="store_true",
                    help="time the Read path alone: shadow reads without a Sync (for the slow model)")
    ap.add_argument("--bench-budget", type=float, default=0.5, help="window length in s")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", help="bench: write the table as JSON")
    ap.add_argument("--indexes", default="", help="one read: comma-separated bucket indexes")
    ap.add_argument("--index-mode", choices=["cli"], default="cli", help="(legacy reader compatibility)")
    ap.add_argument("--dst-indexes", default="")
    ap.add_argument("--clear-if-unchanged", default="")
    ap.add_argument("--clear-indexes", default="",
                    help="comma-separated buckets to clear unconditionally after the read (they need not be read)")
    ap.add_argument("--snapshot", choices=["sync", "hw"], default="sync")
    ap.add_argument("--format", choices=["summary", "json"], default="json")
    args = ap.parse_args()
    if args.serve:
        serve(args)
    elif args.probe:
        probe(args)
    elif args.bench:
        bench(args)
    else:
        one_shot(args)


if __name__ == "__main__":
    main()
