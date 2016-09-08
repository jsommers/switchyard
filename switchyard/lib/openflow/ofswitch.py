import socket
import ssl
from threading import Thread
import time
from heapq import heappush, heappop, heapreplace
from copy import deepcopy

from switchyard.lib.packet import *
from switchyard.lib.openflow import *
from switchyard.lib.address import *
from switchyard.lib.common import *


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
    An Openflow v1.0 switch.
    '''
    def __init__(self, switchyard_net, switchid, callbacks):
        self._switchid = switchid  # aka, dpid
        self._controller_connections = []
        self._switchyard_net = switchyard_net
        self._running = True
        self._buffer_manager = PacketBufferManager(100)
        self._xid = 0
        self._miss_len = 1500
        self._flags = OpenflowConfigFlags.FragNormal
        self._ready = False
        self._table = FlowTable(callbacks)
        self._action_callbacks = callbacks

    def add_controller(self, host, port):
        log_debug("Switch connecting to controller {}:{}".format(host, port))
        sock = socket.socket()  # ssl.wrap_socket(socket.socket())
        sock.settimeout(1.0)
        sock.connect((host, port))
        t = Thread(target=self._controller_thread, args=(sock,))
        self._controller_connections.append((t,sock))
        t.start()

    def _send_openflow_message_internal(self, sock, pkt):
        self._action_callbacks.beforeControllerSend(sock, pkt)
        send_openflow_message(sock, pkt)
        self._action_callbacks.afterControllerSend(sock, pkt)

    def _receive_openflow_message_internal(self, sock):
        self._action_callbacks.beforeControllerRecv(sock)
        pkt = receive_openflow_message(sock)
        self._action_callbacks.afterControllerRecv(sock, pkt)
        return pkt

    @property
    def xid(self):
        self._xid += 1
        return self._xid

    def _send_packet_in(self, port, packet):
        ofpkt = OpenflowHeader.build(OpenflowType.PacketIn, xid=self.xid)
        ofpkt[1].packet = packet.to_bytes()[:self._miss_len]
        ofpkt[1].buffer_id = self._buffer_manager.add(port, packet)
        ofpkt[1].reason = OpenflowPacketInReason.NoMatch
        ofpkt[1].in_port = port
        for _,sock in self._controller_connections:
            self._send_openflow_message_internal(sock, ofpkt)

    def _controller_thread(self, sock):
        def _hello_handler(pkt):
            log_debug("Hello version: {}".format(pkt[0].version))
            pkt = Packet()
            pkt += OpenflowHeader(OpenflowType.Hello, self.xid)
            self._send_openflow_message_internal(sock, pkt) 
            self._ready = True

        def _send_removal_notification(entries, why=FlowRemovedReason.Unknown):
            for e in entries:
                header = OpenflowHeader(OpenflowType.FlowRemoved, self.xid)
                removed = OpenflowFlowRemoved(why, e.match)
                log_debug("Sending flow removal notification: {}".format(removed))
                self._send_openflow_message_internal(sock, header + removed)

        def _send_error(errorcode):
            header = OpenflowHeader(OpenflowType.Error, self.xid)
            err = OpenflowError() 
            err.errortype = OpenflowErrorType.FlowModFailed
            err.errorcode = errorcode
            log_debug("Sending error message: {}".format(err))
            self._send_openflow_message_internal(sock, header + err)

        def _features_request_handler(pkt):
            header = OpenflowHeader(OpenflowType.FeaturesReply, self.xid)
            featuresreply = OpenflowSwitchFeaturesReply()
            featuresreply.dpid_low48 = self._switchid
            for i, intf in enumerate(self._switchyard_net.ports()):
                featuresreply.ports.append(
                    OpenflowPhysicalPort(i, intf.ethaddr, intf.name))
            log_debug("Sending features reply: {}".format(featuresreply))
            self._send_openflow_message_internal(sock, header + featuresreply)

        def _set_config_handler(pkt):
            setconfig = pkt[1]
            self._flags = setconfig.flags
            self._miss_len = setconfig.miss_send_len
            log_debug("Set config: flags {} misslen {}".format(
                self._flags, self._miss_len))

        def _get_config_request_handler(pkt):
            log_debug("Get Config request")
            header = OpenflowHeader(OpenflowType.GetConfigReply, self.xid)
            reply = OpenflowGetConfigReply()
            reply.flags = self._flags
            reply.miss_send_len = self._miss_len
            self._send_openflow_message_internal(sock, header + reply)

        def _flow_mod_handler(pkt):
            fmod = pkt[1]
            if fmod.command == FlowModCommand.Add:
                log_debug("Flow mod add")
                rv = self._table.add(fmod)
                if rv:
                    _send_error(rv)
                elif pkt[1].buffer_id != 2**32-1:
                    pp = self._buffer_manager.pop(pkt[1].buffer_id)
                    self._datapath_action(*pp)

            elif fmod.command == FlowModCommand.Modify:
                log_debug("Flow mod modify")
                self._table.modify(fmod, strict=False)
            elif fmod.command == FlowModCommand.ModifyStrict:
                log_debug("Flow mod modify strict")
                self._table.modify(fmod, strict=True)
            elif fmod.command == FlowModCommand.Delete:
                log_debug("Flow mod delete")
                notify = self._table.delete(fmod.match)
                if notify:
                    _send_removal_notification(notify)
            elif fmod.command == FlowModCommand.DeleteStrict:
                log_debug("Flow mod delete strict")
                notify = self._table.delete(fmod.match, strict=True)
                if notify:
                    _send_removal_notification(notify)
            else:
                raise Exception("Unknown flowmod command {}".format(fmod.command))

        def _barrier_request_handler(pkt):
            log_debug("Barrier request")
            reply = OpenflowHeader(OpenflowType.BarrierReply, xid=pkt[0].xid)
            self._send_openflow_message_internal(sock, reply)

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
            rheader = OpenflowHeader(OpenflowType.StatsReply, xid=pkt[0].xid)
            if pkt[1].type == OpenflowStatsType.SwitchDescription:
                statsbody = SwitchDescriptionStatsReply(mfr_desc='Switchyard', 
                    hw_desc='Switchyard', sw_desc='Switchyard', 
                    serial_num='0000', dp_desc=str(self._switchid))
            elif pkt[1].type == OpenflowStatsType.IndividualFlow:
                pass
            elif pkt[1].type == OpenflowStatsType.AggregateFlow:
                pass
            elif pkt[1].type == OpenflowStatsType.Table:
                pass
            elif pkt[1].type == OpenflowStatsType.Port:
                pass
            elif pkt[1].type == OpenflowStatsType.Queue:
                pass
            elif pkt[1].type == OpenflowStatsType.Vendor:
                pass
            else:
                log_info("Unrecognized stats request type")
            self._send_openflow_message_internal(sock, rheader + statsbody)

        def _echo_request_handler(pkt):
            log_debug("Echo request: {}".format(str(pkt)))
            reply = OpenflowHeader(OpenflowType.EchoReply, xid=pkt[0].xid)
            self._send_openflow_message_internal(sock, reply)

        _handler_map = {
            OpenflowType.Hello: _hello_handler,
            OpenflowType.FeaturesRequest: _features_request_handler,
            OpenflowType.SetConfig: _set_config_handler,
            OpenflowType.GetConfigRequest: _get_config_request_handler,
            OpenflowType.FlowMod: _flow_mod_handler,
            OpenflowType.BarrierRequest: _barrier_request_handler,
            OpenflowType.PacketOut: _packet_out_handler,
            OpenflowType.StatsRequest: _stats_request_handler,
            OpenflowType.EchoRequest: _echo_request_handler,
        }

        def _unknown_type_handler(pkt):
            log_debug("Unknown OF message type: {}".format(pkt[0].type))


        while self._running:
            pkt = None
            try:
                pkt = self._receive_openflow_message_internal(sock)
            except socket.timeout:
                pass

            entries = self._table.expire_entries()
            if entries:
                _send_removal_notification(entries)

            if pkt is not None:
                _handler_map.get(pkt[0].type, _unknown_type_handler)(pkt)


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

    def datapath_loop(self):
        log_debug("datapath loop: not ready to receive")
        while not self._ready:
            time.sleep(0.5)

        log_debug("datapath loop: READY to receive")
        while True:
            try:
                inport, packet = self._switchyard_net.recv_packet(timeout=1.0)
            except Shutdown:
                break
            except NoPackets:
                continue

            inport = self._switchyard_net.port_by_name(inport)
            portnum = inport.ifnum
            log_info("Processing packet: {}->{}".format(portnum, packet))
            actions = self._table.match_packet(portnum, packet)
            if actions is None:
                self._send_packet_in(portnum, packet)
            else:
                self._datapath_action(portnum, packet, actions=actions)

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

def main(net, host='localhost', port=6633, switchid=EthAddr("de:ad:00:00:be:ef")):
    callbacks = SwitchActionCallbacks()
    switch = OpenflowSwitch(net, switchid, callbacks)
    switch.add_controller('localhost', 6633)
    switch.datapath_loop()
    switch.shutdown()
    net.shutdown()
