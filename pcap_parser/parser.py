import re
import socket
from dnslib import DNSRecord
from pcap_parser import dpkt
from pcap_parser.exceptions import PcapParserException

__author__ = 'julianoo@gmail.com'

HOST = 'host'
URI = 'uri'
METHOD = 'method'
DATA = 'data'
GETS = 'gets'
POSTS = 'posts'
SRC = 'src'
DST = 'dst'
CONTENT_LENGTH = 'content-length'
TCP_SEQ = 'seq'
SRC_PORT = "src_port"
DST_PORT = "dst_port"
OTHERS = "others"
PROTOCOL = "protocol"
DIRECTION = "direction"
SHRINKED = "...(shrinked)"

class ParsePcap:
    def __init__(self, pcap_path):
        self.pcap_buf = open(pcap_path, 'rb')
        self.pcap = dpkt.pcap.Reader(self.pcap_buf)
        self.used_frames = []  #guarda o (ack, seq)

    def __del__(self):
        self.pcap_buf.close()

    def reassemble_packet(self, tcp_initial_frame, data, frame_number, missing_bytes, max_search=15000):
        i = frame_number + 1
        frames_matching_missing_bytes_len = []

        while i < len(data) and max_search > (i - frame_number):

            eth = dpkt.ethernet.Ethernet(data[i][1])
            ip = eth.data
            tcp = ip.data

            if type(tcp) == dpkt.tcp.TCP:
                # resent packets
                if tcp.ack == tcp_initial_frame.ack and tcp.seq == tcp_initial_frame.seq:
                    if len(tcp_initial_frame.data) < len(tcp.data):
                        tcp_initial_frame.data = tcp.data
                        return tcp_initial_frame

                elif tcp.ack == tcp_initial_frame.ack and \
                                tcp.seq == (tcp_initial_frame.seq + len(tcp_initial_frame.data)):
                    tcp_initial_frame.data += tcp.data
                    tcp_initial_frame.seq += len(tcp.data)
                    missing_bytes -= len(tcp.data)
                    self.used_frames.append((tcp.ack, tcp.seq))

                # sometimes if we sum the packet's size and seq, we find the next seq
                elif tcp.seq == (len(tcp_initial_frame.data) + tcp_initial_frame.seq) \
                        and len(tcp.data) == missing_bytes:
                    tcp_initial_frame.data += tcp.data
                    self.used_frames.append((tcp.ack, tcp.seq))
                    return tcp_initial_frame

                elif len(tcp.data) == missing_bytes:
                    frames_matching_missing_bytes_len.append((missing_bytes, tcp.data))

            if missing_bytes == 0:
                break
            i += 1

        # if its not possible to find a packet that matches, use the first we find with the same length as missing_bytes
        if missing_bytes > 0:
            if len(frames_matching_missing_bytes_len) > 0:
                for frame_size, frame_data in frames_matching_missing_bytes_len:
                    if frame_size == missing_bytes:
                        tcp_initial_frame.data += frame_data
                        return tcp_initial_frame

        return tcp_initial_frame

    def verifiy_request_in_list(self, request_list, dst, seq):
        for key in request_list.keys():
            for i in request_list[key]:
                if i[TCP_SEQ] == seq and i[DST] == dst:
                    return True
        return False

    def decode_data(self, data: bytes):
        decoders = ["utf8", "ISO-8859-1", "cp1252"]
        for i, decoder in enumerate(decoders):
            try:
                return data.decode(decoder)
            except UnicodeDecodeError:
                if i+1 == len(decoders):
                    raise

    def update_content_length(self, tcp_data, content_length, new_size):
        if type(tcp_data) == bytes:
            tcp_data = self.decode_data(tcp_data)
        return tcp_data.replace('Content-Length: %s' % content_length,
                                'Content-Length: %d' % new_size)

    def extract_host_from_tcp_data(self, tcp_data):
        matches = re.findall('Host\:\s([^\r]+)', self.decode_data(tcp_data))
        if len(matches) > 0:
            return matches[0]
        else:
            matches = re.findall('[GET|POST]\s(http\:\/\/[^\s]+)', self.decode_data(tcp_data))
            if len(matches) > 0:
                return matches[0].replace('http://', '')
        return None

    def get_data(self, local_ip: str, max_answer_size=None):
        """
        :param local_ip: it's used to define which package is inbound and outbound
                         (I strongly recommend that you use this param)
        :param max_answer_size: if an answers is to big you might limit it here, just set how many bytes you want
                                otherwise left None if you want it all
        :return:
        """
        PACKETS = {GETS: [], POSTS: []}
        NOT_PARSED = []

        count = 0
        data = self.pcap.readpkts()
        while count < len(data):
            valid = False
            ts, buf = data[count]

            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            if type(ip) != str and type(ip.data) == dpkt.tcp.TCP and len(ip.data.data) > 0 and ip.data.dport == 80:
                tcp = ip.data
                src = (socket.inet_ntoa(ip.src))
                dst = socket.inet_ntoa(ip.dst)

                if (tcp.ack, tcp.seq) not in self.used_frames:
                    self.used_frames.append((tcp.ack, tcp.seq))
                else:
                    count += 1
                    continue

                try:
                    # we have a problem with big packets, they are splitted into 2 or more frames
                    # and the content-length is bigger than the real packet's size
                    # so we search the next package and join them until complete the packet
                    http = dpkt.http.Request(tcp.data)

                    host = self.extract_host_from_tcp_data(tcp.data)
                    # when its no possible to extract the host from header and the header is full,
                    # it means that we have an error extracting host
                    if not host and http.headers != {}:
                        raise PcapParserException("Can't find Host on tcp.data")

                    # when it is malformed, keep goind
                    elif not host and http.headers == {}:
                        count += 1
                        continue
                    valid = True

                except dpkt.NeedData as e:
                    if 'premature end of headers' in repr(e):
                        count += 1
                        continue
                    missing_bytes_len = int(re.findall('missing\s(\d+)\sbytes', repr(e))[0])

                    http = None
                    old_tcp_data = tcp.data

                    tcp = self.reassemble_packet(tcp, data, count, missing_bytes_len)

                    if self.verifiy_request_in_list(PACKETS, dst, tcp.seq):
                        count += 1
                        continue

                    # there are some cases where content-length indicates the packet length + header size
                    # and not just the body's size
                    content_length = int(re.findall('Content-Length:\s(\d+)', self.decode_data(tcp.data))[0])
                    if old_tcp_data == tcp.data:
                        if content_length == len(tcp.data):
                            tcp.data = self.update_content_length(tcp.data, content_length, missing_bytes_len)
                            http = dpkt.http.Request(tcp.data)
                            tcp.data = old_tcp_data

                        # in case we do not find the frames to fill the packet, leave it as it is
                        else:
                            # set content length to 0 so we can use dpkt.http.request function
                            tcp.data = self.update_content_length(tcp.data, content_length, 0)
                            http = dpkt.http.Request(tcp.data)
                            tcp.data = old_tcp_data

                    if http is None:
                        try:
                            http = dpkt.http.Request(tcp.data)
                        except dpkt.NeedData as e:
                            # if its now possible to reassemble, keep going...
                            tcp.data = self.update_content_length(tcp.data, content_length, 0)
                            http = dpkt.http.Request(tcp.data)

                    host = self.extract_host_from_tcp_data(tcp.data)
                    if not host:
                        raise Exception("Can't find Host on tcp.data")
                    valid = True

                except dpkt.UnpackError as e:
                    count += 1
                    continue

            if valid:
                direction = None
                if local_ip:
                    direction = "outbound" if src == local_ip else "inbound"
                package_info = {HOST: host, URI: http.uri, METHOD: http.method,
                                DATA: self.decode_data(tcp.data), SRC: src, DST: dst, TCP_SEQ: tcp.seq,
                                SRC_PORT: ip.data.sport, DST_PORT: ip.data.dport,
                                PROTOCOL: "tcp", DIRECTION: direction
                                }
                if http.method == "GET":
                    PACKETS[GETS].append(package_info)
                elif http.method == "POST":
                    PACKETS[POSTS].append(package_info)

            else:
                try:
                    src = socket.inet_ntoa(ip.src)
                    dst = socket.inet_ntoa(ip.dst)
                    src_port = ip.data.sport
                    dst_port = ip.data.dport
                    tmp_data = None
                    protocol = None
                    direction = None
                    if local_ip:
                        direction = "outbound" if src == local_ip else "inbound"

                    if hasattr(ip.data, 'data'):
                        try:
                            tmp_data = self.decode_data(ip.data.data)
                        except:
                            pass

                    if type(ip.data) == dpkt.tcp.TCP:
                        protocol = "tcp"
                    elif type(ip.data) == dpkt.udp.UDP:
                        protocol = "udp"
                        if dst_port == 53:
                            dns = DNSRecord.parse(ip.data.data)
                            tmp_data = str(dns.get_q().get_qname())
                            if tmp_data.endswith("."): tmp_data = tmp_data[:-1]

                        elif src_port == 53:
                            dns = DNSRecord.parse(ip.data.data)
                            tmp_data = str(dns.get_a().rdata)
                            if tmp_data.endswith("."):
                                tmp_data = tmp_data[:-1]

                    tmp = {SRC: src, DST: dst, SRC_PORT: src_port, DST_PORT: dst_port,
                           PROTOCOL: protocol, DATA: tmp_data, DIRECTION: direction}
                    if tmp not in NOT_PARSED:

                        # if its an answer, try to find and join the answers
                        if direction == "inbound":
                            for j, tk in enumerate(NOT_PARSED):
                                if tk[SRC] == src and tk[DST] == dst \
                                        and src_port == tk[SRC_PORT] \
                                        and dst_port == tk[DST_PORT]:
                                    if max_answer_size is not None and len(tk[DATA]) >= max_answer_size:
                                        if not tk[DATA].endswith(SHRINKED):
                                            tk[DATA] += SHRINKED
                                    else:
                                        tk[DATA] += tmp_data
                                    tmp = tk
                                    NOT_PARSED.pop(j)
                        NOT_PARSED.append(tmp)
                except:
                    # unhandled yet :/
                    pass

            count += 1
        PACKETS.update({OTHERS: NOT_PARSED})
        return PACKETS
