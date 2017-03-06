import socket
import ssl
from threading import Thread
import time
from heapq import heappush, heappop, heapreplace
from copy import deepcopy

from switchyard.lib.packet import *
from switchyard.lib.openflow import openflow10 as of10
from switchyard.lib.openflow import openflow13 as of13
from switchyard.lib.address import *
from switchyard.lib.logging import *
from switchyard.lib.exceptions import *


class ControllerConnection(object):
    def __init__(self, host, port, usetls=True):
        self._host = host
        self._port = port
        self._usetls = usetls
        self._connected = False
        self._socket = None

    def connect(self):
        self._socket = None
        if self._usetls:
            self._socket = ssl.wrap_socket(socket.socket())
        else:
            self._socket = socket.socket()
        self._socket.settimeout(1.0)
        try:
            self._socket.connect((host, port))
            self._connected = True
        except:
            pass

    def isconnected(self):
        return self._connected

    @property
    def sock(self):
        return self._socket

    def send_openflow_message(self, pkt):
        # FIXME: should have some null object stand in for the socket if there's no
        # connection...
        if not self._connected:
            self.connect()
        if not self._connected:
            log_warn("Not connected to controller; could not send OFP message {}".format(pkt))
            return

        log_debug("Sending Openflow message {} ({} bytes)".format(pkt, len(pkt)))
        raw = pkt.to_bytes()
        remain = len(raw)

        while remain > 0:
            rv = self._socket.send(raw[-remain:])
            if rv == -1:
                raise OSError("send error")
            remain -= rv

    def receive_openflow_message(self):
        # FIXME: should have some null object stand in for the socket if there's no
        # connection...
        if not self._connected:
            self.connect()
        if not self._connected:
            return None

        ofheader = of10.OpenflowHeader()
        try:
            data = self._socket.recv(ofheader.size())
        except socket.timeout:
            log_debug("Timeout waiting on receipt of OF message")
            return None
        if len(data) == 0:
            return None
        ofheader.from_bytes(data)

        log_debug("Attempting to receive Openflow message (header: {}) ({} bytes)".format(
            ofheader, ofheader.length))
        remain = ofheader.length - ofheader.size()
        while remain > 0:
            more = self._socket.recv(remain)
            data += more
            remain -= len(more)

        p = Packet.from_bytes(data, of10.OpenflowHeader)
        return p


class FullBuffer(Exception):
    pass

class PacketBufferManager(object):
    def __init__(self, buffsize):
        self._buffsize = buffsize
        self._buffer = {}

    def add(self, port, pkt):
        '''
        Add new input port + packet to buffer.
        '''
        id = len(self._buffer) + 1
        if id > self._buffsize:
            raise FullBuffer()

        self._buffer[id] = (port, deepcopy(pkt))
        return id

    def pop(self, id):
        '''
        Return and remove buffered packet and input port.
        '''
        return self._buffer.pop(id)

    def lookup(self, id):
        '''
        Check whether packet is buffered.  Just return packet (not inport).
        '''
        rv = self._buffer.get(id, (None,None))
        return rv[1]


class TableEntry(object):
    def __init__(self, fmod):
        self._match = fmod.match
        self._cookie = fmod.cookie
        self._idle_timeout = fmod.idle_timeout
        self._hard_timeout = fmod.hard_timeout
        self._actions = fmod.actions
        self._priority = fmod.priority
        self._flags = fmod.flags
        self._packets_matched = 0
        self._bytes_matched = 0
        self._last_match = None
        self._creation_time = time.time()

    @property
    def priority(self):
        return self._priority

    @property
    def match(self):
        return self._match

    @property 
    def actions(self):
        return self._actions

    def __lt__(self, other):
        return self.priority < other.priority

    def __eq__(self, other):
        return self.priority == other.priority

    def __hash__(self):
        return self._cookie

    def update_counters(self, pkt):
        self._last_match = time.time()
        self._packets_matched += 1
        self._bytes_matched += len(pkt)

    def has_expired(self, timestamp):
        idletime = timestamp - self._last_match if self._last_match else timestamp
        createtime = timestamp - self._creation_time
        if self._idle_timeout > 0 and \
           idletime > self._idle_timeout:
            return True
        if self._hard_timeout > 0 and \
           createtime > self._hard_timeout:
            return True
        return False

    def send_expire_notice(self):
        return self._flags & FlowModFlags.SendFlowRemove.value

class FlowTable(object):
    def __init__(self, callbacks):
        self._table = []
        self._action_callbacks = callbacks

    def __len__(self):
        return len(self._table)

    def delete(self, matcher, strict=False):
        tbd = []
        for entry in self._table:
            if entry.match.overlaps_with(matcher, strict):
                tbd.append(entry)

        log_debug("{} table entries deleted".format(len(tbd)))

        # for each entry, remove it, and if flags say so, emit a
        # flow removed message
        notify = []
        for entry in tbd:
            if FlowModFlags.SendFlowRemove in entry.get_flags:
                notify.append(entry)
            self._action_callbacks.beforeTableEntryDelete(self._table, entry)
            self._table.remove(entry)
            self._action_callbacks.afterTableEntryDelete(self._table, entry)
        return notify

    def add(self, fmod):
        newentry = TableEntry(fmod)
        self._action_callbacks.beforeTableEntryAdd(self._table, newentry)
        # match, cookie, idle_timeout, hard_timeout, priority, buffer_id, out_port, flags, actions
        if FlowModFlags.CheckOverlap in fmod.get_flags():
            for entry in self._table:
                if newentry.match.overlaps_with(entry.match, strict=True) and \
                   entry.priority == newentry.priority:
                    return OpenflowFlowModFailedCode.Overlap
        self._table.append(newentry)            
        self._table.sort()
        self._action_callbacks.afterTableEntryAdd(self._table, newentry)
        return None

    def modify(self, fmod, strict=False):
        newentry = TableEntry(fmod)
        self._action_callbacks.beforeTableEntryMod(self._table, newentry)
        matches = []
        for entry in self._table:
            if newentry.match.overlaps_with(entry, strict=strict):
                matches.append(entry)
        if len(matches):
            for entry in matches:
                entry.match.actions = newentry.match.actions
        else:
            self._table.append(newentry)
            self._table.sort()

        self._action_callbacks.afterTableEntryMod(self._table, newentry)

    def match_packet(self, in_port, pkt):
        self._action_callbacks.beforeTableLookup(pkt, self._table)
        for entry in self._table:
            if entry.match.matches_packet(pkt):
                if in_port is None or entry.match.in_port == OpenflowPort.NoPort or \
                   entry.match.in_port == in_port:
                    self._action_callbacks.afterTableLookup(pkt, self._table)
                    entry.update_counters(pkt)
                    return entry.actions
        self._action_callbacks.afterTableLookup(pkt, self._table)
        return None

    def expire_entries(self):
        now = time.time()
        expired = []
        i = 0
        while i < len(self._table):
            entry = self._table[i]
            if entry.has_expired(now) and entry.send_expire_notice():
                expired.append(entry)
                del self._table[i]
            else:
                i += 1
        return expired

class OpenflowSwitch(object):
    '''
    An Openflow v1.0 or v1.3 switch.
    '''
    def __init__(self, switchyard_net, switchid, callbacks, version=0x04):
        if isinstance(switchid, str):
            switchid = switchid.encode()
        self._switchid = switchid
        self._controller_connections = []
        self._switchyard_net = switchyard_net
        self._running = True
        self._version = version # defaults to 0x04==1.3
        self._buffer_manager = PacketBufferManager(100)
        self._xid = 0
        self._miss_len = 1500
        if self._version == 0x01:
            self._oflib = of10
        elif self._version == 0x04:
            self._oflib = of13
        else:
            assert("Unsupported OFP version {}".format(self._version))
        self._flags = self._oflib.OpenflowConfigFlags.FragNormal
        self._tables = [ FlowTable(callbacks) ]
        self._group_table = FlowTable(callbacks)
        self._meter_table = None # not supported yet
        self._action_callbacks = callbacks

    def add_controller(self, host, port, usetls=True):
        log_debug("Switch connecting to controller {}:{}".format(host, port))
        cc = ControllerConnection(host, port, usetls)
        t = Thread(target=self._controller_thread, args=(cc,))
        self._controller_connections.append((t,cc))
        t.start()

    def _send_openflow_message_internal(self, cconn, pkt):
        self._action_callbacks.beforeControllerSend(cconn, pkt)
        cconn.send_openflow_message(pkt)
        self._action_callbacks.afterControllerSend(cconn, pkt)

    def _receive_openflow_message_internal(self, cconn):
        self._action_callbacks.beforeControllerRecv(cconn)
        pkt = cconn.receive_openflow_message()
        self._action_callbacks.afterControllerRecv(cconn, pkt)
        return pkt

    @property
    def xid(self):
        self._xid += 1
        return self._xid

    def _send_packet_in(self, port, packet):
        ofpkt = self._oflib.OpenflowHeader.build(self._oflib.OpenflowType.PacketIn, xid=self.xid)
        ofpkt[1].packet = packet.to_bytes()[:self._miss_len]
        ofpkt[1].buffer_id = self._buffer_manager.add(port, packet)
        ofpkt[1].reason = self._oflib.OpenflowPacketInReason.NoMatch
        ofpkt[1].in_port = port
        for _,cc in self._controller_connections:
            self._send_openflow_message_internal(cc, ofpkt)

    def _controller_thread(self, cconn):
        def _hello_handler(pkt):
            log_debug("Hello version: {}".format(pkt[0].version))
            if pkt[0].version == 0x01:
                log_info("Controller version {}; changing switch version to match.".format(pkt[0].version))
                self._version = pkt[0].version
                self._oflib = of10
                _handler_map = _handler_map_10
            elif pkt[0].version == 0x04:
                log_info("Controller version {}; same as switch.".format(pkt[0].version))
                self._version = pkt[0].version
                self._oflib = of13
                _handler_map = _handler_map_13
            else:
                log_warn("Controller wants a version we don't support ({})".format(pkt[0].version))
                return

            pkt = self._oflib.OpenflowHeader.build(self._oflib.OpenflowType.Hello, xid=pkt[self._oflib.OpenflowHeader].xid)
            self._send_openflow_message_internal(cconn, pkt) 

        def _send_removal_notification(entries, why=self._oflib.FlowRemovedReason.Unknown):
            for e in entries:
                header = self._oflib.OpenflowHeader(self._oflib.OpenflowType.FlowRemoved, xid=self.xid)
                removed = self._oflib.OpenflowFlowRemoved(why, e.match)
                log_debug("Sending flow removal notification: {}".format(removed))
                self._send_openflow_message_internal(cconn, header + removed)

        def _send_error(errortype, errorcode, xid=self.xid):
            header = self._oflib.OpenflowHeader(self._oflib.OpenflowType.Error, xid=xid)
            err = self._oflib.OpenflowError() 
            err.errortype = errortype
            err.errorcode = errorcode
            log_debug("Sending error message: {}".format(err))
            self._send_openflow_message_internal(cconn, header + err)

        def _features_request_handler(pkt):
            header = self._oflib.OpenflowHeader(self._oflib.OpenflowType.FeaturesReply, xid=pkt[self._oflib.OpenflowHeader].xid)
            featuresreply = self._oflib.OpenflowSwitchFeaturesReply()
            featuresreply.dpid = self._switchid
            for i, intf in enumerate(self._switchyard_net.ports()):
                featuresreply.ports.append(
                    self._oflib.OpenflowPhysicalPort(i, intf.ethaddr, intf.name))
            log_debug("Sending features reply: {}".format(featuresreply))
            self._send_openflow_message_internal(cconn, header + featuresreply)

        def _set_config_handler(pkt):
            setconfig = pkt[1]
            self._flags = setconfig.flags
            self._miss_len = setconfig.miss_send_len
            log_debug("Set config: flags {} misslen {}".format(
                self._flags, self._miss_len))

        def _get_config_request_handler(pkt):
            log_debug("Get Config request")
            header = self._oflib.OpenflowHeader(self._oflib.OpenflowType.GetConfigReply, xid=pkt[self._oflib.OpenflowHeader].xid)
            reply = self._oflib.OpenflowGetConfigReply()
            reply.flags = self._flags
            reply.miss_send_len = self._miss_len
            self._send_openflow_message_internal(cconn, header + reply)

        def _flow_mod_handler(pkt):
            fmod = pkt[1]
            if fmod.command == self._oflib.FlowModCommand.Add:
                log_debug("Flow mod add")
                rv = self._table.add(fmod)
                if rv:
                    _send_error(OpenflowErrorType.FlowModFailed, rv)
                elif pkt[1].buffer_id != 2**32-1:
                    pp = self._buffer_manager.pop(pkt[1].buffer_id)
                    self._datapath_action(*pp)

            elif fmod.command == self._oflib.FlowModCommand.Modify:
                log_debug("Flow mod modify")
                self._table.modify(fmod, strict=False)
            elif fmod.command == self._oflib.FlowModCommand.ModifyStrict:
                log_debug("Flow mod modify strict")
                self._table.modify(fmod, strict=True)
            elif fmod.command == self._oflib.FlowModCommand.Delete:
                log_debug("Flow mod delete")
                notify = self._table.delete(fmod.match)
                if notify:
                    _send_removal_notification(notify)
            elif fmod.command == self._oflib.FlowModCommand.DeleteStrict:
                log_debug("Flow mod delete strict")
                notify = self._table.delete(fmod.match, strict=True)
                if notify:
                    _send_removal_notification(notify)
            else:
                raise Exception("Unknown flowmod command {}".format(fmod.command))

        def _barrier_request_handler(pkt):
            log_debug("Barrier request")
            reply = self._oflib.OpenflowHeader.build(self._oflib.OpenflowType.BarrierReply, xid=pkt[self._oflib.OpenflowHeader].xid)
            self._send_openflow_message_internal(cconn, reply)

        def _packet_out_handler(pkt):
            actions = pkt[1].actions
            if pkt[1].buffer_id != 0xffffffff:
                in_port, outpkt = self._buffer_manager.pop(pkt[1].buffer_id)
            else:
                outpkt = pkt[1].packet
            in_port = pkt[1].in_port
            log_debug("pkt {} buffid {} actions {} inport {}".format(outpkt, pkt[1].buffer_id, actions, in_port))
            self._process_actions(actions, in_port, outpkt)

        def _stats_request_handler(pkt):
            log_debug("Stats request: {}".format(str(pkt)))
            rheader = self._oflib.OpenflowHeader(OpenflowType.StatsReply, xid=pkt[self._oflib.OpenflowHeader].xid)
            if pkt[1].type == self._oflib.OpenflowStatsType.SwitchDescription:
                statsbody = self._oflib.SwitchDescriptionStatsReply(mfr_desc='Switchyard', 
                    hw_desc='Switchyard', sw_desc='Switchyard', 
                    serial_num='0000', dp_desc=str(self._switchid))
            elif pkt[1].type == self._oflib.OpenflowStatsType.IndividualFlow:
                pass
            elif pkt[1].type == self._oflib.OpenflowStatsType.AggregateFlow:
                pass
            elif pkt[1].type == self._oflib.OpenflowStatsType.Table:
                pass
            elif pkt[1].type == self._oflib.OpenflowStatsType.Port:
                pass
            elif pkt[1].type == self._oflib.OpenflowStatsType.Queue:
                pass
            elif pkt[1].type == self._oflib.OpenflowStatsType.Vendor:
                pass
            else:
                log_info("Unrecognized stats request type")
            self._send_openflow_message_internal(cconn, rheader + statsbody)

        def _echo_request_handler(pkt):
            log_debug("Echo request: {}".format(str(pkt)))
            reply = self._oflib.OpenflowHeader(self._oflib.OpenflowType.EchoReply, xid=pkt[self._oflib.OpenflowHeader].xid)
            reply[OpenflowEchoReply].data = pkt[OpenflowEchoRequest].data
            self._send_openflow_message_internal(cconn, reply)

        # fixme: once oftest testing is sorted out, need to eliminate this ugly dup
        _handler_map_10 = {
            of10.OpenflowType.Hello: _hello_handler,
            of10.OpenflowType.FeaturesRequest: _features_request_handler,
            of10.OpenflowType.SetConfig: _set_config_handler,
            of10.OpenflowType.GetConfigRequest: _get_config_request_handler,
            of10.OpenflowType.FlowMod: _flow_mod_handler,
            of10.OpenflowType.BarrierRequest: _barrier_request_handler,
            of10.OpenflowType.PacketOut: _packet_out_handler,
            of10.OpenflowType.StatsRequest: _stats_request_handler,
            of10.OpenflowType.EchoRequest: _echo_request_handler,
        }

        _handler_map_13 = {
            of13.OpenflowType.Hello: _hello_handler,
            of13.OpenflowType.FeaturesRequest: _features_request_handler,
            of13.OpenflowType.SetConfig: _set_config_handler,
            of13.OpenflowType.GetConfigRequest: _get_config_request_handler,
            of13.OpenflowType.FlowMod: _flow_mod_handler,
            of13.OpenflowType.BarrierRequest: _barrier_request_handler,
            of13.OpenflowType.PacketOut: _packet_out_handler,
            of13.OpenflowType.EchoRequest: _echo_request_handler,
        }

        _version_to_handler_map = {
            0x01: _handler_map_10,
            0x04: _handler_map_13,
        }
        _handler_map = _version_to_handler_map[self._version]

        def _unknown_type_handler(pkt):
            log_debug("Unknown OF message type: {}".format(pkt[self._oflib.OpenflowHeader].type))
            _send_error(self._oflib.OpenflowErrorType.BadRequest, self._oflib.OpenflowBadRequestCode.BadType, xid=pkt[self._oflib.OpenflowHeader].xid)

        def _expire_table_entries():
            entries = []
            for t in self._tables:
                entries.extend(t.expire_entries())
            if entries:
                _send_removal_notification(entries)

        while True:
            if not cconn.isconnected:
                cconn.connect()

            pkt = self._receive_openflow_message_internal(cconn)
            _expire_table_entries()

            if pkt is not None:
                _handler_map.get(pkt[0].type, _unknown_type_handler)(pkt)

            if not self._running:
                break


    def _process_actions(self, actions, inport, packet):
        '''
        Process actions in order, in two stages.  Each action implements a __call__, which
        applies any packet-level changes or other non-output changes.  The functors
        can optionally return another function to be applied at the second stage.
        '''
        second_stage = []
        for a in actions:
            fn = a(packet=packet, net=self._switchyard_net, controllers=self._controller_connections, inport=inport)
            if (fn):
                second_stage.append(fn)
        for fn in second_stage:
            fn()

    def _datapath_action(self, inport, packet, actions=None):
        log_debug("Datapath action for {}".format(str(packet)))
        if actions is None:
            actions = self._table.match_packet(inport, packet)

        if actions is None:
            log_warn("Fail: in datapath_action but no table match.")
            debugger()
        else:
            log_debug("Applying action {}".format('/'.join([str(a) for a in actions])))
            self._action_callbacks.beforeApplyActions(packet, actions)
            self._process_actions(actions, inport, packet)
            self._action_callbacks.afterApplyActions(packet, actions)        

    def _handle_datapath(self, inport, packet):
        '''
        Handle single packet on the data plane.
        '''
        inport = self._switchyard_net.port_by_name(inport)
        portnum = inport.ifnum
        log_info("Processing packet: {}->{}".format(portnum, packet))

        actions = None
        for tnum,t in enumerate(self._tables):
            actions = t.match_packet(portnum, packet)

            # FIXME: this is all wrong/incomplete

            # if match: Update counters Execute instructions:
            #           update action set
            #           update packet/match set fields
            #            update metadata
            # if no match and table miss entry exists, do the above
            # otherwise, drop the packet
        # actions = self._table.match_packet(portnum, packet)
        if actions is None:
            self._send_packet_in(portnum, packet)
        else:
            self._datapath_action(portnum, packet, actions=actions)

    def datapath_loop(self):
        log_debug("datapath loop: READY to receive")
        while True:
            try:
                timestamp, inport, packet = self._switchyard_net.recv_packet(timeout=1.0)
            except Shutdown:
                break
            except NoPackets:
                continue
            self._handle_datapath(inport, packet)

    def shutdown(self):
        self._running = False
        for t,sock in self._controller_connections:
            t.join()

class SwitchActionCallbacks(object):
    '''
    Callbacks that can be injected at various points of OF message processing
    and in datapath packet processing.  Can be used to modify the nature of how
    packets are processed, how rules are processed, and to inject artificial 
    delays at any of these points.  Inherit from this class and override any
    methods that will be useful for the particular application.
    '''
    def __init__(self):
        pass

    def beforeControllerSend(self, sock, pkt):
        pass

    def afterControllerSend(self, sock, pkt):
        pass

    def beforeControllerRecv(self, sock):
        pass

    def afterControllerRecv(self, sock, pkt):
        pass

    def beforeApplyActions(self, pkt, actions):
        pass

    def afterApplyActions(self, pkt, actions):
        pass

    def beforeTableLookup(self, pkt, table):
        pass

    def afterTableLookup(self, pkt, table):
        pass

    def beforeTableEntryDelete(self, table, entry):
        pass

    def afterTableEntryDelete(self, table, entry):
        pass

    def beforeTableEntryAdd(self, table, entry):
        pass

    def afterTableEntryAdd(self, table, entry):
        pass

    def beforeTableEntryMod(self, table, entry):
        pass

    def afterTableEntryMod(self, table, entry):
        pass


def main(net, host='localhost', port=6653, usetls=False, switchid=b'\xc0\xde' + EthAddr("6a:7e:c0:ff:ee:00").raw, version=0x04):
    callbacks = SwitchActionCallbacks()
    switch = OpenflowSwitch(net, switchid, callbacks, version)
    switch.add_controller(host, port, usetls)
    switch.datapath_loop()
    switch.shutdown()
    net.shutdown()
