import argparse
import sys
from Monitor import Monitor

parser = argparse.ArgumentParser()
parser.add_argument('--pid', type=int, required=True, help="pid of the monitored process.", metavar='number')
arg = parser.parse_args(sys.argv[1:])

monitor = Monitor(arg.pid)
monitor.run()
