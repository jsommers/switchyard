from switchyard.lib.userlib import *

def main(net):
    # below, recvdata is a namedtuple
    recvdata = net.recv_packet()
    print ("At {}, received {} on {}".format(
        recvdata.timestamp, recvdata.packet, recvdata.input_port))

    # alternatively, the above line could use indexing (though
    # readability suffers:
    #    recvdata[0], recvdata[1], recvdata[2]))
    
    net.send_packet(recvdata.input_port, recvdata.packet)
