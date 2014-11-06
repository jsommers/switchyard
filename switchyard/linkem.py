import sys
import heapq
from queue import Queue,Empty
import time

class LinkEmulator(object):
    def __init__(self, inqueue):
        self.expiryheap = []
        self.inqueue = inqueue
        self.__shutdown = False

    def shutdown(self):
        self.__shutdown = True

    def run(self):
        while not self.__shutdown:

            now = time.time()
            while len(self.expiryheap) and self.expiryheap[0][0] <= now:
                expiretime,item,outqueue = heapq.heappop(self.expiryheap)
                outqueue.put(item)

            if len(self.expiryheap):
                expiretime,item,outqueue = self.expiryheap[0]
                timeout = expiretime - time.time()
            else:
                timeout = 0.1

            try:
                expiretime,item,outqueue = self.inqueue.get(timeout=timeout)
            except Empty:
                pass
            else:
                heapq.heappush(self.expiryheap, (expiretime, item, outqueue))

