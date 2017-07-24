#!/usr/bin/env python3

# Usage (run the script as root):
#   check_races.py [OPTIONS] FILE
#
# The script monitors the instructions listed in FILE (one per line) in the
# same format as RaceHound accepts in its 'breakpoints' file. It operates
# in a similar way to what DataCollider tool does on MS Windows.
#
# The script chooses some of the listed instructions and tells RaceHound
# to look for races involving them. RaceHound places breakpoints on these
# instructions, etc.
#
# The initial number of the breakpoints to be set can be specified in
# '--num-bps' parameter.
#
# If the breakpoints hit too often or too rarely, the script removes or adds
# some breakpoints to balance things. See --min_hit_rate and --max_hit_rate
# options.
#
# If a breakpoint hits, the script removes it, randomly chooses another one
# that is not currently set and sets it.
#
# All this allows to check all the given instructions in time.
#
# If RaceHound finds races, it reports them to the system log (dmesg). This
# script will not be notified of such events.
#
# Note. Python 3.4 or newer is required.
#
# If -v (--verbose) is present, the script will output more info as it
# works.
#
# The script assumes debugfs is mounted to /sys/kernel/debug/.
#
# Note. Per-breakpoint delays ('delay=...' in the breakpoint specification)
# are not supported here. Use the parameters of the kernel part of RaceHound
# to set the delays globally if needed.

import sys
import os.path
import selectors
import argparse
import re

from datetime import datetime
from random import SystemRandom


BPS_FILE = '/sys/kernel/debug/racehound/breakpoints'
EVENTS_FILE = '/sys/kernel/debug/racehound/events'

ERR_NO_FILES = ''.join([
    'Please check that debugfs is mounted to /sys/kernel/debug ',
    'and kernel module \"racehound\" is loaded.'])

# [<module_name>:]{init|core}+0xoffset
RE_BP_SPEC = re.compile(r'^([^:]+:)?(core|init)\+0x[a-f0-9]{1,8}$')

# How many breakpoints to set initially.
num_bps = 10

# How many BPs to add if the hit rate is too low.
bps_to_add = 10

# The desirable boundaries of the breakpoint hit rate (BPs/second).
min_hit_rate = 0.01
max_hit_rate = 1.0

# Each HIT_CHECK_INTERVAL seconds, the breakpoint hit rate will be
# evaluated and, if necessary, the set of breakpoints will be adjusted.
HIT_CHECK_INTERVAL = 10

# See -v/--verbose argument.
verbose = 0

# The random number generator to use.
rng = SystemRandom()


def positive_int(string):
    value = int(string)
    if value <= 0:
        msg = "%r is not a positive integer" % string
        raise argparse.ArgumentTypeError(msg)
    return value

def place_bp(bp, bps):
    '''Tell RaceHound to place the given BP and mark the BP as set.
    See the Readme for RaceHound for the format and detais.'''
    try:
        with open(BPS_FILE, 'w') as f:
            f.write('{0}\n'.format(bp))
        bps[bp] = True
        if verbose:
            print('Placed breakpoint at {0}.'.format(bp))
    except OSError as err:
        sys.stderr.write(
            'Failed to place a breakpoint at \"{0}\": {1}\n'.format(
                bp, err))
        # If the BP cannot be set, it might be incorrect or not applicable
        # for some other reason.
        del bps[bp]
        if not bps:
            sys.stderr.write('No valid breakpoints remain, exiting.\n')
            sys.exit(1)

def remove_bp(bp):
    '''Tell RaceHound to remove the given BP.
    See the Readme for RaceHound for the format and detais.'''
    try:
        with open(BPS_FILE, 'w') as f:
            f.write('-{0}\n'.format(bp))
        if verbose:
            print('Removed breakpoint at {0}.'.format(bp))
    except OSError as err:
        sys.stderr.write(
            'Failed to remove the breakpoint at \"{0}\": {1}\n'.format(
                bp, err))

def replace_bp(bp, bps, hit_rate):
    '''Remove the given BP and set a new one, if available.'''
    remove_bp(bp)
    bps[bp] = False

    if hit_rate > max_hit_rate:
        if verbose:
            print('Hit rate is too high, not adding new BPs this time.')
        return

    # The same BP has a chance to be chosen again, which is OK.
    add_bps(1, bps)


def add_bps(num, bps):
    '''Select the given number of BPs randomly and try to set them.'''
    available = [bp for bp in bps.keys() if not bps[bp]]
    if not available:
        if verbose:
            print('No breakpoints can be set.\n')
        return

    if num > len(available):
        num = len(available)

    selected = rng.sample(available, num)
    for bp in selected:
        place_bp(bp, bps)


if __name__ == '__main__':
    desc = 'This script checks the given set of instructions to find races.'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument(
        '--num-bps', metavar='N', nargs='?', type=positive_int,
        default=num_bps,
        help='how many breakpoints to set initially')
    parser.add_argument(
        '--bps-to-add', metavar='N', nargs='?', type=positive_int,
        default=bps_to_add,
        help='how many breakpoints to add if hit rate is low')
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='output more info about the events, etc.')
    parser.add_argument(
        '--min-hit-rate', nargs='?', type=float, default=min_hit_rate,
        help='the minimum desirable BP hit rate (BPs/sec)')
    parser.add_argument(
        '--max-hit-rate', nargs='?', type=float, default=max_hit_rate,
        help='the maximum desirable BP hit rate (BPs/sec)')
    parser.add_argument("input_file", metavar='FILE')
    args = parser.parse_args()

    num_bps = args.num_bps
    bps_to_add = args.bps_to_add
    min_hit_rate = args.min_hit_rate
    max_hit_rate = args.max_hit_rate
    verbose = args.verbose

    if min_hit_rate < 0 or max_hit_rate < 0:
        raise ValueError(
            'min_hit_rate and max_hit_rate should be non-negative.')
    if min_hit_rate >= max_hit_rate:
        raise ValueError(
            'max_hit_rate should be greater than min_hit_rate.')

    # Mapping BP=>bool (True - BP is set, False - not set)
    bps = {}

    with open(args.input_file, 'r') as f:
        for line in f:
            line = line.strip().lower()
            if not line:
                continue
            if RE_BP_SPEC.match(line):
                bps[line] = False
            else:
                print('Invalid breakpoint specification: %s' % line)

    if not bps:
        sys.stderr.write('No valid breakpoints specified.\n')
        sys.exit(1)

    if num_bps > len(bps):
        num_bps = len(bps)

    for fl in [BPS_FILE, EVENTS_FILE]:
        if not os.path.exists(fl):
            sys.stderr.write('File not found: %s.\n' % fl)
            sys.stderr.write(ERR_NO_FILES)
            sys.stderr.write('\n')
            sys.exit(1)

    sel = selectors.DefaultSelector()
    with open(EVENTS_FILE, 'r') as f:
        sel.register(f, selectors.EVENT_READ)

        start_time = datetime.utcnow()
        hits = 0
        hit_rate = (min_hit_rate + max_hit_rate) / 2.0

        add_bps(num_bps, bps)

        # Poll the "events" file and read the lines from it as they become
        # available.
        # If the user presses Ctrl-C, just exit.
        try:
            while True:
                events = sel.select(timeout=HIT_CHECK_INTERVAL)
                for key, mask in events:
                    for line in f:
                        bp = line.rstrip()
                        if verbose:
                            print('BP hit:', bp)
                        # When we have removed a BP, we may still receive
                        # some hit events for it after that, because the
                        # events are reported asynchronously by the kernel
                        # module. Let us ignore these additional events.
                        if bps[bp]:
                            hits = hits + 1
                            replace_bp(bp, bps, hit_rate)

                elapsed = (datetime.utcnow() - start_time).total_seconds()
                if elapsed >= HIT_CHECK_INTERVAL:
                    hit_rate = float(hits) / elapsed
                    if hit_rate < min_hit_rate:
                        if verbose:
                            print("Hit rate is too low, trying to add BPs.")
                        add_bps(bps_to_add, bps)

                    start_time = datetime.utcnow()
                    hits = 0

        except KeyboardInterrupt:
            sys.exit(1)
