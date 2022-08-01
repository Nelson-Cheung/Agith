from bcc import BPF
import time, sys


class BPFFrame():
    def __init__(self, bpf_code_path_list) -> None:
        code_content = ""
        for filename in bpf_code_path_list:
            with open(filename, "r") as f:
                code_content += f.read()
        self.bpf = BPF(text=code_content)
        print("load bpf code done.")

    def run(self) -> None:

        try:
            while True:
                self.bpf.ring_buffer_poll()
        except KeyboardInterrupt:
            sys.exit(0)

    def set_ringbuf_callback(self, ringbuf_name, callback):

        self.bpf[ringbuf_name].open_ring_buffer(callback)

    def get_ringbuf_event(self, ringbuf_name, data):

        return self.bpf[ringbuf_name].event(data)

    def get_table(self, table_name):
        
        return self.bpf[table_name]