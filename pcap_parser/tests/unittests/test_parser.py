import os
from unittest import TestCase
from pcap_parser.parser import ParsePcap

__author__ = 'julianoo@gmail.com'


class TestParser(TestCase):

    def test_parser(self):
        pcap = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data", "smallFlows.pcap")
        parser = ParsePcap(pcap)
        current = parser.get_data("192.168.2.131", None)
        self.assertEquals(len(current["gets"]), 518)
        self.assertEquals(len(current["posts"]), 10)
        self.assertEquals(len(current["others"]), 1204)
