### libtalloc.py - GDB talloc analysis plugin
# Written by Aaron Adams
# NCC 2015
### 
# USAGE:
# Run tchelp to see commands
# Always run tcprobe once before other commands
# See README.md for extensive usage
#
# TODO:
# - Add color-coded corrupted chunks when validating the whole heap, instead of 
#   printing
# - Add more functions that use the heap walk: find all pools, find all pool
#   members, find all with size greater than X, etc
# - Add support for the samba-specific stackframe memory contexts
# - Add memlimit support
# - Add pretty printer for talloc_pool_chunk
# - Add an item that shows the amount of data left in a talloc pool, even though
#   there isn't an explicit field that holds it.
# - A lot of the chunk reading logic can be put into a superclass that all the
#   different chunk objects inherit from
# - If you have pagination on in gdb and prematurely kill the tcreport command
#   output, you'll have chunks remaining looped which isn't ideal. Could catch the
#   exception and walk the whole heap unsetting the loop flags...
# - Maybe make it auto execute tcprobe on initialization?
###

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    exit()

import re
import sys
import struct
from os import uname

# bash color support
color_support = True
if color_support:
    c_red      = "\033[31m"
    c_red_b    = "\033[01;31m"
    c_green    = "\033[32m"
    c_green_b  = "\033[01;32m"
    c_yellow   = "\033[33m"
    c_yellow_b = "\033[01;33m"
    c_blue     = "\033[34m"
    c_blue_b   = "\033[01;34m"
    c_purple   = "\033[35m"
    c_purple_b = "\033[01;35m"
    c_teal     = "\033[36m"
    c_teal_b   = "\033[01;36m"
    c_none     = "\033[0m"
else:
    c_red      = ""
    c_red_b    = ""
    c_green    = ""
    c_green_b  = ""
    c_yellow   = ""
    c_yellow_b = ""
    c_blue     = ""
    c_blue_b   = ""
    c_purple   = ""
    c_purple_b = ""
    c_teal     = ""
    c_teal_b   = ""
    c_none     = ""
c_error  = c_red
c_title  = c_green_b
c_header = c_yellow_b
c_value  = c_blue_b

_machine = uname()[4]
if _machine == "x86_64":
    SIZE_SZ = 8
elif _machine in ("i386", "i686"):
    SIZE_SZ = 4

# We use this as the root of operations on the whole heap.
null_context         = None

TALLOC_ALIGNMENT     = 16
TALLOC_ALIGN_MASK    = TALLOC_ALIGNMENT - 1
if SIZE_SZ == 4:
    TC_SIZE              = SIZE_SZ * 10
elif SIZE_SZ == 8:
    TC_SIZE              = SIZE_SZ * 12

TC_HDR_SIZE          = (TC_SIZE+TALLOC_ALIGN_MASK) & ~TALLOC_ALIGN_MASK
if SIZE_SZ == 4:
    TP_SIZE              = SIZE_SZ * 3
elif SIZE_SZ == 8:
    TP_SIZE              = SIZE_SZ * 4
TP_HDR_SIZE          = (TP_SIZE+TALLOC_ALIGN_MASK) & ~TALLOC_ALIGN_MASK

def talloc_chunk_from_ptr(p):
    "Ptr to talloc_chunk header"
    return (p - TC_HDR_SIZE)

def ptr_from_talloc_chunk(tc):
    "Ptr to chunk data"
    return (tc.address + tc.header_size)

TALLOC_MAGIC_BASE      = 0xe814ec70
TALLOC_VERSION_MAJOR   = 2
TALLOC_VERSION_MINOR   = 0
TALLOC_MAGIC           = TALLOC_MAGIC_BASE + (TALLOC_VERSION_MAJOR << 12) \
                                           + (TALLOC_VERSION_MINOR << 4)

TALLOC_MAGIC_REFERENCE = 1
MAX_TALLOC_SIZE        = 0x10000000

TALLOC_FLAG_FREE       = 1
TALLOC_FLAG_LOOP       = 2
TALLOC_FLAG_POOL       = 4
TALLOC_FLAG_POOLMEM    = 8
TALLOC_FLAG_MASK       = ~0xF

# version found dynamically by tcprobe and friends. heavily relied on for proper
# structure versions
talloc_version         = None
# File location of library
talloc_path            = None
# Checked against to determine if the script is likely to fail or not.
tested_versions = []

# Used by a variety of callbacks that can't relay their data back to callers
# easily
chunklist = []

def find_talloc_version():
    "tries to find the talloc version so we can make sure the structures are setup sanely"

    global talloc_version
    global talloc_path

    output = gdb.execute("info proc mappings", False, True)
    start = output.find("0x")
    output = output[start-2:]
    found = 0
    # [1:] is to skip a blank entry that is at the start
    for entry in output.split("\n")[1:]:
        if entry.find("talloc") != -1:
            found = 1
            break

    if found == 0:
        print(c_error + "Couldn't find talloc shared library" + c_none)
        return

    talloc_lib = entry.split()
    talloc_path = talloc_lib[4]
    results = gdb.execute("find %s, %s, 'T', 'A', 'L', 'L', 'O', 'C', '_'" % (talloc_lib[0], talloc_lib[1]), False, True)
    for version in results.split("\n"):
        if version.find("0x") != -1:
            ver = read_string(int(version, 16))
            # Weed out anything that's not TALLOC_x.y.z
            if ver.find('.') != -1:
                idx = ver.find("_")
                if idx == -1:
                    print(c_error + "Version string found seems wrong: %s" % (ver) + c_none)
                ver = ver[idx+1:]
                ver = ver.split('.')
                talloc_version = int(ver[0]), int(ver[1]), int(ver[2])

def version_eq_or_newer(wanted_version=(0,0,0)):
    return version_cmp(wanted_version) >= 0

def version_eq_or_older(wanted_version=(0,0,0)):
    return version_cmp(wanted_version) <= 0

def version_cmp(w):
    global talloc_version
    if talloc_version == None:
        find_talloc_version()
        if talloc_version == None:
            return False
    t = talloc_version
    for i in xrange(len(t)):
        if (t[i] != w[i]):
            return t[i] - w[i];
    return 0

def tc_chunk(p, warn=True, fixup=True):
    '''Creates a talloc_chunk() object from a given address. Tries to help by
    testing for a legitimate header and if not found, tries again a header's
    length backwards'''
    tc = talloc_chunk(p)
    if not fixup:
        return tc
    old = tc
    if bad_magic(tc):
        if warn:
            print(c_error + "WARNING: 0x%lx not a talloc_chunk. Assuming ptr to chunk data" % p + c_none)
        tc = talloc_chunk(talloc_chunk_from_ptr(p))
        if bad_magic(tc):
            # Assume they wanted to pass in the first wrong one if both are wrong...
            tc = old
            if warn:
                print(c_error + "WARNING: 0x%lx also not a talloc_chunk. Corrupt chunk?" % talloc_chunk_from_ptr(p) + c_none)
    return tc

def tc_version(flags):
    version = (flags & TALLOC_FLAG_MASK) - TALLOC_MAGIC_BASE
    major = version >> 12
    minor = (version - (major << 12)) >> 4
    return (major, minor)

def annotate_entry(p):
    tc = tc_chunk(p)
    print("  - name: %s" % talloc_get_name(tc))
    print("  - size: %d (0x%x) bytes" % (tc.size, tc.size))
    print("  - valid: %s" % is_valid_chunk(tc))

# TODO
# - Would be nice to resolve destructor symbols
# - Also more info about tc->refs
def annotate_chunk(p):
    "verbosely describe a chunk with all flags"
    print(c_title + "===========================")
    print("Chunk @ 0x%lx" % p.address)
    print(" valid: %s" % is_valid_chunk(p))
    print("===========================" + c_none)
    print("next = 0x%lx" % p.next_tc)
    if p.next_tc:
        tc = annotate_entry(p.next_tc)
    print("prev = 0x%lx" % p.prev_tc)
    if p.prev_tc:
        tc = annotate_entry(p.prev_tc)
    print("parent = 0x%lx" % p.parent)
    if p.parent:
        tc = annotate_entry(p.parent)
    print("child = 0x%lx" % p.child)
    if p.child:
        tc = annotate_entry(p.child)
    print("refs = 0x%lx" % p.refs)
    print("destructor = 0x%lx" % p.destructor)
    print("name = 0x%lx" % p.name)
    if p.name:
        print("  - %s" % talloc_get_name(p))
    print("size = %d (0x%lx) bytes" % (p.size, p.size))
    print("flags = 0x%lx" % p.flags)
    if is_free(p):
        print("  - TALLOC_FLAG_FREE")
    if is_loop(p):
        print("  - TALLOC_FLAG_LOOP")
    if is_pool(p):
        print("  - TALLOC_FLAG_POOL")
    if is_pool_member(p):
        print("  - TALLOC_FLAG_POOLMEM")
    print("pool = 0x%lx" % p.pool)
    if p.pool:
        tc = annotate_entry(p.pool)
    print("===========================")
    if is_valid_chunk(p) == False:
        print("  Validation output:")
        print("===========================")
        validate_chunk(p)

def get_mappings():
    output = gdb.execute("info proc mappings", False, True)
    start = output.find("0x")
    output = output[start-2:]
    address_map = []
    # [1:] is to skip a blank entry that is at the start
    for entry in output.split("\n"):
        data =  re.sub("\s+", " ", entry.lstrip()).split(" ")
        if len(data) < 2:
            continue
        start_addr = data[0]
        end_addr = data[1]
        address_map.append((start_addr, end_addr))
    return address_map

def is_valid_addr(p):
    asmap = get_mappings()
    for entry in asmap:
        if (p >= int(entry[0], 16)) and (p < int(entry[1], 16)):
            return True
    return False

def is_valid_chunk(p):
    return validate_chunk(p, False)

def validate_chunk(p, talk=True):
    valid = True
    if bad_magic(p):
        valid = False
        if talk:
            print("0x%lx: Chunk has bad magic 0x%lx" % (p.address, (p.flags & TALLOC_FLAG_MASK)))
    if p.next_tc:
        if not is_valid_addr(p.next_tc):
            valid = False
            if talk:
                print("0x%lx: Chunk has bad next pointer 0x%lx" % (p.address, p.next_tc))
    if p.prev_tc:
        if not is_valid_addr(p.prev_tc):
            valid = False
            if talk:
                print("0x%lx: Chunk has bad prev pointer 0x%lx" % (p.address, p.prev_tc))
    if p.child:
        if not is_valid_addr(p.child):
            valid = False
            if talk:
                print("0x%lx: Chunk has bad child pointer 0x%lx" % (p.address, p.child))
    if p.parent:
        if not is_valid_addr(p.parent):
            valid = False
            if talk:
                print("0x%lx: Chunk has bad parent pointer 0x%lx" % (p.address, p.parent))
    if p.refs and (p.refs != TALLOC_MAGIC_REFERENCE):
        if not is_valid_addr(p.refs):
            valid = False
            if talk:
                print("0x%lx: Chunk has bad refs pointer 0x%lx" % (p.address, p.refs))
    if p.destructor:
        if not is_valid_addr(p.destructor):
            valid = False
            if talk:
                print("0x%lx: Chunk has bad destructor pointer 0x%lx" % (p.address, p.destructor))
    if p.pool:
        if not is_valid_addr(p.pool):
            valid = False
            if talk:
                print("0x%lx: Chunk has bad pool pointer 0x%lx" % (p.address, p.pool))
    if p.size >= MAX_TALLOC_SIZE:
        valid = False
        if talk:
            print("0x%lx: Chunk has bad size 0x%lx" % (p.address, p.size))

    return valid

def search_chunk(p, search_for):
    "searches a chunk. includes the chunk header in the search"
    results = []
    try:
        out_str = gdb.execute('find 0x%x, 0x%x, %s' % \
            (p.address, p.address + p.header_size + p.size, search_for), \
            to_string = True)
    except:
        #print(sys.exc_info()[0])
        return results

    str_results = out_str.split('\n')

    for str_result in str_results:
        if str_result.startswith('0x'):
            results.append(p.address)

    return results

def tc_search_heap(p, search_for, depth=0, find_top=True):
    "walk chunks searching for specified value"
    results = []
    if (depth == 0) and (find_top == True):
        top = talloc_top_chunk(p)
        p = top

    results = search_chunk(p, search_for)

    if p.child:
        p = tc_chunk(p.child)
        while True:
            results.extend(tc_search_heap(p, search_for, (depth+1)))
            if not p.next_tc:
                break;
            p = tc_chunk(p.next_tc)

    return results

def tc_find_addr(p, search_addr, depth=0, find_top=True):
    "walk chunks searching if address falls within chunk"
    results = []
    if (depth == 0) and (find_top == True):
        top = talloc_top_chunk(p)
        p = top

    if (p.address <= search_addr) and ((p.address + TC_HDR_SIZE + p.size) >= search_addr):
        results.append(p)

    if p.child:
        p = tc_chunk(p.child)
        while True:
            results.extend(tc_find_addr(p, search_addr, (depth+1)))
            if not p.next_tc:
                break;
            p = tc_chunk(p.next_tc)

    return results

# This is our workhorse for analyzing the entire heap. Supply a callback and it
# will be passed every encountered chunk and depth. It recurses through every memory
# context from the top (typically null_context)
def tc_walk_heap(p, cb=None, depth=0, find_top=True):
    if cb == None:
        print(c_error + "WARNING: tc_walk_heap requires a callback..." + c_none)
        return
    if (depth == 0) and (find_top == True):
        top = talloc_top_chunk(p)
        p = top

    cb(p)
    if p.child:
        p = tc_chunk(p.child)
        while True:
            tc_walk_heap(p, cb, (depth+1))
            if not p.next_tc:
                break;
            p = tc_chunk(p.next_tc)

def tc_heap_validate_all(p, depth=0):
    tc_walk_heap(p, validate_chunk)

def tc_print_heap(p, sort=False, find_top=True):
    global chunklist
    if sort == True:
        chunklist[:] = []
        tc_walk_heap(p, collect_chunk, find_top)
        chunklist.sort()
        for chunk in chunklist:
            print(chunk)
    else:
        tc_walk_heap(p, print_chunk, find_top)

def collect_chunk(p):
    chunklist.append(chunk_info(p))

def print_chunk(p):
    print(chunk_info(p))

def chunk_info(p):
    info = []
    info.append(("0x%lx " % p.address))
    info.append(("sz:0x%.08x, " % p.size))
    info.append(("flags:"))
    if (is_free(p)):
        info.append("F")
    else:
        info.append(".")
    if (is_pool(p)):
        info.append("P")
    else:
        info.append(".")
    if (is_pool_member(p)):
        info.append("p")
    else:
        info.append(".")
    if (is_loop(p)):
        info.append("L")
    else:
        info.append(".")
    info.append((", name:%s" % talloc_get_name(p)))
    return ''.join(info)

def bad_magic(p):
    return (p.flags & TALLOC_FLAG_MASK != TALLOC_MAGIC)

def is_free(p):
    "Extract p's TALLOC_FLAG_FREE bit"
    return (p.flags & TALLOC_FLAG_FREE)

def set_free(p):
    "set chunk as being free without otherwise disturbing"
    p.flags |= TALLOC_FLAG_FREE
    p.write()
    return

def clear_free(p):
    "set chunk as being inuse without otherwise disturbing"
    p.flags &= ~TALLOC_FLAG_FREE
    p.write()
    return

def is_loop(p):
    "Extract p's TALLOC_FLAG_LOOP bit"
    return (p.flags & TALLOC_FLAG_LOOP)

def set_loop(p):
    "set chunk as looped without otherwise disturbing"
    p.flags |= TALLOC_FLAG_LOOP
    p.write()
    return

def clear_loop(p):
    "set chunk as non-looped without otherwise disturbing"
    p.flags &= ~TALLOC_FLAG_LOOP
    p.write()
    return

def set_destructor(p, fptr):
    p.destructor = fptr
    p.write()
    return

def set_size(p, sz):
    "set chunks size without otherwise disturbing"
    p.size = sz
    p.write()
    return

def talloc_total_blocks(tc):
    total = 0
    if is_loop(tc):
        return total
    set_loop(tc)
    total += 1
    if tc.child:
        p = talloc_chunk(tc.child)
        while True:
            total += talloc_total_blocks(p)
            if not p.next_tc:
                break
            p = talloc_chunk(p.next_tc)

    clear_loop(tc)
    return total

def talloc_total_size(tc):
    total = 0
    if is_loop(tc):
        return total
    set_loop(tc)

    if tc.name != TALLOC_MAGIC_REFERENCE:
        total = tc.size
    if tc.child:
        p = talloc_chunk(tc.child)
        while True:
            total += talloc_total_size(p)
            if not p.next_tc:
                break
            p = talloc_chunk(p.next_tc)

    clear_loop(tc)
    return total

def talloc_parent_chunk(tc):
    "ptr to parent talloc_chunk"
    while tc.prev_tc:
        tc = talloc_chunk(tc.prev_tc)
    if tc.parent:
        return talloc_chunk(tc.parent)
    return None

def talloc_top_chunk(tc):
    global null_context
    while True:
        last = tc
        tc = talloc_parent_chunk(tc)
        if (null_context == None) and (tc != None) and (talloc_get_name(tc) == "null_context"):
            null_context = tc
        if tc == None:
            return last

def talloc_reference_count(tc):
    "number of external references to a pointer"
    ret = 0
    while tc.next_tc:
        ret += 1
        tc = talloc_chunk(tc.next_tc)
    return ret

def tc_hexdump(p):
    data = ptr_from_talloc_chunk(p)
    print(c_title + "Chunk data (%d bytes):" % p.size + c_none)
    cmd = "x/%dwx 0x%x\n" % (p.size/4, data)
    gdb.execute(cmd, True)
    return

def is_pool(p):
    return (p.flags & TALLOC_FLAG_POOL)

def is_pool_member(p):
    return (p.flags & TALLOC_FLAG_POOLMEM)

def get_chunk_pool(p):
    if p.flags & TALLOC_FLAG_POOLMEM == 0:
        print(c_error + "WARNING: 0x%lx not part of a pool." \
             % p + c_none)
        return None
    return p.pool

def read_string(p, inferior=None):
    if inferior == None:
        inferior = get_inferior()
        if inferior == -1:
            return None
    string = []
    curp = p
    while True:
        byte = inferior.read_memory(curp, 1)
        if byte[0] == b'\x00':
            break;
        string.append(byte[0])
        curp += 1

    return b''.join(string).decode('utf-8')

def talloc_print_parents(tc):
    parents = []
    parents.append(tc)
    while True:
        tc = talloc_parent_chunk(tc)
        if tc == None:
            break;
        parents.append(tc)

    depth = 0
    parents.reverse()
    for tc in parents:
        print("%*s0x%lx: %s" % (depth*2, "", tc.address, talloc_get_name(tc)))
        depth += 1
    return

def talloc_print_children(tc, depth=0):
    p = tc
    if p.child:
        p = tc_chunk(p.child)
        while True:
            poolstr = ""
            if is_pool(p):
                poolstr = " (POOL)"
            print("%*s0x%lx: %s%s" % (depth*2, "", p.address, talloc_get_name(p), poolstr))
            talloc_print_children(p, depth+1)
            if not p.next_tc:
                break;
            p = tc_chunk(p.next_tc)

def talloc_get_name(tc):
    if tc.name == TALLOC_MAGIC_REFERENCE:
        return ".reference"
    elif tc.name:
        try:
            return read_string(tc.name);
        except RuntimeError:
            print(c_error + "Could not read name" + c_none)
            return None
    else:
        return "UNNAMED"

def talloc_report_callback(tc, depth, is_ref=False):
    name = talloc_get_name(tc)
    if is_ref:
       print("%*sreference to: %s" % (depth*4, "", name))
    elif depth == 0:
        print("Full talloc report on '%s' (total %6lu bytes in %3lu blocks)" % \
            (name, talloc_total_size(tc), talloc_total_blocks(tc)))
        return
    else:
        print("%*s%-30s contains %6lu bytes in %3lu blocks (ref %d) 0x%lx" % \
            (depth*4, "", name, talloc_total_size(tc), \
            talloc_total_blocks(tc), talloc_reference_count(tc), tc.address))

def talloc_report_full(tc, full=False):
    if full == True:
        tc = talloc_top_chunk(tc)
    talloc_report_depth(tc, 0)

def talloc_report_depth(tc, depth):
    if is_loop(tc):
        return
    talloc_report_callback(tc, depth)
    set_loop(tc)
    p = tc
    if p.child:
        p = talloc_chunk(p.child)
        while True:
            if p.name == TALLOC_MAGIC_REFERENCE:
                h = talloc_reference_handle(ptr_from_talloc_chunk(p))
                talloc_report_callback(talloc_chunk(h.ptr), depth+1, True)
            else:
                talloc_report_depth(p, depth+1)
            if not p.next_tc:
                break
            p = talloc_chunk(p.next_tc)

    clear_loop(tc)

def get_inferior():
    try:
        if len(gdb.inferiors()) == 0:
            print(c_error + "No gdb inferior could be found." + c_none)
            return -1
        else:
            inferior = gdb.inferiors()[0]
            return inferior
    except AttributeError:
        print(c_error + "This gdb's python support is too old." + c_none)
        exit()


################################################################################
class talloc_chunk:
    "python representation of a struct talloc_chunk"

    def __init__(self,addr=None,mem=None,min_size=TC_HDR_SIZE,inferior=None,read_data=True,show_pad=False, pool=None):
        global talloc_version
        self.vspecific  = None
        self.str_name   = "talloc_chunk"

        # Struct members
        self.next_tc    = None
        self.prev_tc    = None
        self.parent     = None
        self.child      = None
        self.refs       = None
        self.destructor = None
        self.name       = None
        self.size       = None
        self.flags      = None
        self.pool       = None
        self.limit      = None
        self.pad1       = None
        self.pad2       = None
        self.pad3       = None

        # Used by child objects to know read offsets
        self.struct_size = 0
        self.header_size = TC_HDR_SIZE

        # >= TALLOC 2.1.0 we might have a prefixed talloc_pool_hdr
        self.pool_hdr = None

        # Init these now to adjust header_size
        if version_eq_or_newer((2, 0, 8)):
            self.vspecific = talloc_chunk_v208(self)
        elif version_eq_or_older((2, 0, 7)):
            self.vspecific = talloc_chunk_v207(self)
        else:
            print("No version detected")

        if addr == None or addr == 0:
            if mem == None:
                sys.stdout.write(c_error)
                sys.stdout.write("Please specify a valid struct talloc_chunk address.")
                sys.stdout.write(c_none)
                return None
            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if SIZE_SZ == 4:
                    # XXX - Size is arbitrary. copied from libheap
                    self.mem = inferior.read_memory(addr, 0x44c)
                elif SIZE_SZ == 8:
                    # XXX - Size is arbitrary. copied from libheap
                    self.mem = inferior.read_memory(addr, 0x880)
            except TypeError:
                print(c_error + "Invalid address specified." + c_none)
                return None
            except RuntimeError:
                print(c_error + "Could not read address 0x%x" % addr + c_none)
                return None
        else:
            # a string of raw memory was provided
            if len(self.mem) < self.header_size:
                sys.stdout.write(c_error)
                sys.stdout.write("Insufficient memory provided for a talloc_chunk.")
                sys.stdout.write(c_none)
                return None
            if len(self.mem) == header_size:
                #header only provided
                read_data = False

        if SIZE_SZ == 4:
            (self.next_tc, \
            self.prev_tc,  \
            self.parent,  \
            self.child,  \
            self.refs,  \
            self.destructor,  \
            self.name,  \
            self.size,  \
            self.flags,  \
            ) = struct.unpack_from("<9I", self.mem, 0x0)
            self.struct_size = 9*4
        elif SIZE_SZ == 8:
            (self.next_tc, \
            self.prev_tc,  \
            self.parent,  \
            self.child,  \
            self.refs,  \
            self.destructor,  \
            self.name,  \
            self.size,  \
            self.flags,  \
            ) = struct.unpack_from("<8QI", self.mem, 0x0)
            self.struct_size = ((8*8) + 4)

        # Depending on the version we have to read in additional data...
        if version_eq_or_newer((2, 0, 8)):
            self.vspecific.getdata(self)
        if version_eq_or_older((2, 0, 7)):
            self.vspecific.getdata(self)

        # Create a copy of the pool header
        if is_pool(self) and version_eq_or_newer((2, 1, 0)):
            if pool != None:
                self.pool_hdr = talloc_pool_hdr(self.address-TP_HDR_SIZE, parent=self)
            else:
                self.pool_hdr

        # always try to find null_context asap
        global null_context
        if null_context == None and is_valid_chunk(self):
            talloc_top_chunk(self)

    def write(self, inferior=None, do_write=True):
        if inferior == None:
            self.inferior = get_inferior()
            if self.inferior == -1:
                return None
        if SIZE_SZ == 4:
            self.mem = struct.pack("<9I", self.next_tc, self.prev_tc, \
            self.parent, self.child, self.refs, self.destructor, self.name,\
            self.size, self.flags)
        elif SIZE_SZ == 8:
            self.mem = struct.pack("<8QI", self.next_tc, self.prev_tc, \
            self.parent, self.child, self.refs, self.destructor, self.name,\
            self.size, self.flags)

        # Add the version-specific bits
        self.vspecific.write(self)

        if do_write:
            self.inferior.write_memory(self.address, self.mem)

    def get_flags(self):
        "return a string indicating what flags are set"
        string = []
        flags = [(is_free,        "FREE"),
                 (is_pool,        "POOL"),
                 (is_pool_member, "POOLMEM"),
                 (is_loop,        "LOOP")
                ]

        seen_flag = 0
        for item in flags:
            if (item[0](self)):
                if seen_flag:
                    string.append(", ")
                string.append(item[1])
                seen_flag = 1

        return ''.join(string)

    def __str__(self):
        string = []
        string.append("%s%lx%s%s%lx%s%lx%s%lx%s%lx%s%lx%s%lx%s%lx%s%s%lx%s%lx%s%s" %    \
                (c_title + "struct " + self.str_name + " @ 0x", \
                self.address, \
                " {", \
                c_none + "\nnext         = " + c_value + "0x",
                self.next_tc,                                \
                c_none + "\nprev         = " + c_value + "0x", \
                self.prev_tc,                                     \
                c_none + "\nparent       = " + c_value + "0x", \
                self.parent,                                       \
                c_none + "\nchild        = " + c_value + "0x", \
                self.child,                                       \
                c_none + "\nrefs         = " + c_value + "0x", \
                self.refs,                              \
                c_none + "\ndestructor   = " + c_value + "0x", \
                self.destructor,
                c_none + "\nname         = " + c_value + "0x", \
                self.name, \
                c_none + (" (%s)" % talloc_get_name(self)), \
                c_none + "\nsize         = " + c_value + "0x", \
                self.size, \
                c_none + "\nflags        = " + c_value + "0x", \
                self.flags, \
                c_none + (" (%s)" % self.get_flags()),
                c_none))

        string.append("%s" % self.vspecific)
        return ''.join(string)

class talloc_chunk_v208():
    "python representation of a struct talloc_chunk with a limit member"

    def __init__(self, parent):
        self.parent = parent
        # TODO: talloc_chunk already assumes TC_HDR_SIZE so we don't need to
        # adjust, but if that changes, we'll need to adjust here
        #if SIZE_SZ == 4:
        #            parent.header_size += (3*4)
        #elif SIZE_SZ == 8:
        #            parent.header_size += ((2*8) + (3*4))

    def getdata(self, parent):
        if SIZE_SZ == 4:
            (parent.limit, \
            parent.pool,   \
            parent.pad1) = struct.unpack_from("<3I", parent.mem, parent.struct_size)
        elif SIZE_SZ == 8:
            (parent.pad1,   \
            parent.limit, \
            parent.pool) = struct.unpack_from("<IQQ", parent.mem, parent.struct_size)

    def write(self, parent):
        if SIZE_SZ == 4:
            parent.mem += struct.pack("<3I", parent.limit, parent.pool, parent.pad1)
        elif SIZE_SZ == 8:
            parent.mem += struct.pack("<QQI", parent.limit, parent.pool, parent.pad1)

    def __str__(self):
        return "%s0x%lx%s0x%lx%s" % (\
                c_none + "\nlimit        = " + c_value, \
                self.parent.limit, \
                c_none + "\npool         = " + c_value, \
                self.parent.pool,\
                c_none)

class talloc_chunk_v207():
    "python representation of a struct talloc_chunk without a limit member"

    def __init__(self, parent):
        self.parent = parent
        #if SIZE_SZ == 4:
            #parent.header_size += (3*4)
        #else:
            #parent.header_size += (8 + (2*4))

    def getdata(self, parent):
        if SIZE_SZ == 4:
            (parent.pool,  \
            parent.pad1,   \
            parent.pad2) = struct.unpack_from("<3I", parent.mem, parent.struct_size)
        elif SIZE_SZ == 8:
            (parent.pad1,   \
             parent.pool,  \
             parent.pad2) = struct.unpack_from("<IQI", parent.mem, parent.struct_size)

    def write(self, parent, do_write=True):
        if SIZE_SZ == 4:
            parent.mem += struct.pack("<3I", parent.pool, parent.pad1, parent.pad2)
        elif SIZE_SZ == 8:
            parent.mem += struct.pack("<QII", parent.pool, parent.pad1, parent.pad2)

    def __str__(self):
        return "%s0x%lx%s" % (\
            c_none + "\npool         = " + c_value, \
            self.parent.pool,\
            c_none)

# Note that pool chunks changed in Talloc 2.1.0, they know have their own header
# prefixing the talloc chunk. So the below is only for <2.1.0
class talloc_pool_chunk(talloc_chunk, object):
    "python representation of a struct talloc_pool_chunk"

    def __init__(self,addr=None,mem=None,min_size=TC_HDR_SIZE,inferior=None,read_data=True,show_pad=False):
        super(talloc_pool_chunk, self).__init__(addr, mem, min_size, inferior, read_data, show_pad)
        global talloc_version
        self.str_name     = "talloc_pool_chunk"
        # Padding is ordered differently on 32-bit vs 64-bit
        if SIZE_SZ == 4:
            if version_eq_or_newer((2, 0, 8)):
                self.object_count = self.pad1
            # On 2.0.7 there is actually a separate 16 byte header after the chunk lol... ugh
            elif version_eq_or_older((2, 0, 7)):
                self.object_count = struct.unpack_from("<I", self.mem, self.header_size)[0]
                self.header_size += 16
        elif SIZE_SZ == 8:
            # XXX - This is untested. Likely broken
            self.object_count = self.pad2

    def dump(self):
        pool_start = self.address + self.header_size
        pool_end = self.pool
        p = talloc_chunk(pool_start)
        while p.address < pool_end:
            print_chunk(p)
            p = p.address + (((p.header_size + p.size) + TALLOC_ALIGN_MASK) & ~TALLOC_ALIGN_MASK)
            p = talloc_chunk(p)

    def __str__(self):
        string = []
        string.append("%s\n" % super(talloc_pool_chunk, self).__str__())
        string.append("%s%lx%s" % (\
                        "object_count = " + c_value + "0x", \
                        self.object_count, \
                        c_none))
        return ''.join(string)

class talloc_pool_hdr:
    "python representation of a struct talloc_pool_hdr"

    def __init__(self,addr=None,mem=None,min_size=TP_HDR_SIZE,inferior=None, parent=None):
        self.chunk        = None
        self.end          = None
        self.object_count = None
        self.pad1         = None
        self.poolsize     = None
        self.header_size  = TP_HDR_SIZE

        if addr == None or addr == 0:
            if mem == None:
                sys.stdout.write(c_error)
                sys.stdout.write("Please specify a valid struct talloc_pool_hdr address.")
                sys.stdout.write(c_none)
                return None
            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if SIZE_SZ == 4:
                    # XXX - Size is arbitrary. copied from libheap
                    self.mem = inferior.read_memory(addr, 0x44c)
                elif SIZE_SZ == 8:
                    # XXX - Size is arbitrary. copied from libheap
                    self.mem = inferior.read_memory(addr, 0x880)
            except TypeError:
                print(c_error + "Invalid address specified." + c_none)
                return None
            except RuntimeError:
                print(c_error + "Could not read address 0x%x" % addr + c_none)
                return None
        else:
            # a string of raw memory was provided
            if len(self.mem) < self.header_size:
                sys.stdout.write(c_error)
                sys.stdout.write("Insufficient memory provided for a talloc_chunk.")
                sys.stdout.write(c_none)
                return None
            if len(self.mem) == header_size:
                #header only provided
                read_data = False

        if SIZE_SZ == 4:
            (self.end, \
            self.object_count,  \
            self.poolsize,  \
            ) = struct.unpack_from("<3I", self.mem, 0x0)
        elif SIZE_SZ == 8:
            (self.end, \
            self.object_count,  \
            self.pad1, \
            self.poolsize,  \
            ) = struct.unpack_from("QIIQ", self.mem, 0x0)

        if parent != None:
            self.chunk = parent
        elif self.address != None:
            self.chunk = talloc_chunk(self.address+TP_HDR_SIZE)

    def dump(self):
        pool_start = self.address + self.header_size + self.chunk.header_size + self.chunk.size
        pool_end = self.end
        p = talloc_chunk(pool_start)
        while p.address < pool_end:
            print_chunk(p)
            p = p.address + (((p.header_size + p.size) + TALLOC_ALIGN_MASK) & ~TALLOC_ALIGN_MASK)
            p = talloc_chunk(p)

    def write(self):
        "todo"

    def __str__(self):
        string = []
        string.append(''.join("%s0x%lx%s%s0x%lx%s0x%lx%s0x%lx%s" % (\
                c_title + "struct talloc_pool_hdr @ ", \
                self.address, \
                " {", \
                c_none + "\nend          = " + c_value, \
                self.end, \
                c_none + "\nobject_count = " + c_value, \
                self.object_count, \
                c_none + "\npoolsize     = " + c_value, \
                self.poolsize, \
                c_none)))
        string.append("\n%s" % self.chunk)
        return ''.join(string)

class talloc_reference_handle:
    "python representation of a struct talloc_reference_handle"

    def __init__(self,addr=None,mem=None,size=None,inferior=None):
        self.next_ref    = None
        self.prev_ref    = None
        self.ptr         = None
        self.location    = None

        if addr == None or addr == 0:
            if mem == None:
                sys.stdout.write(c_error)
                sys.stdout.write("Please specify a valid struct \
                                talloc_reference_handle address.")
                sys.stdout.write(c_none)
                return None
            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x10)
                elif SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x20)
            except TypeError:
                print(c_error + "Invalid address specified." + c_none)
                return None
            except RuntimeError:
                print(c_error + "Could not read address 0x%x" % addr + c_none)
                return None

        if SIZE_SZ == 4:
            if len(mem) < 0x10:
                print(c_error + "Not enough data to populate talloc_reference_handle" % addr + c_none)
                return None
            (self.next_ref, \
            self.prev_ref,  \
            self.ptr,       \
            self.location,  \
            ) = struct.unpack_from("<IIII", mem, 0x0)
        elif SIZE_SZ == 8:
            if len(mem) < 0x20:
                print(c_error + "Not enough data to populate talloc_reference_handle" % addr + c_none)
                return None
            (self.next_ref, \
            self.prev_ref,  \
            self.ptr,       \
            self.location,  \
            ) = struct.unpack_from("<QQQQ", mem, 0x0)

# This is a super class with few convenience methods to let all the cmds parse
# gdb variables easily
class tccmd(gdb.Command):
    def parse_var(self, var):
        if SIZE_SZ == 4:
            p = self.tohex(long(gdb.parse_and_eval(var)), 32)
        elif SIZE_SZ == 8:
            p = self.tohex(long(gdb.parse_and_eval(var)), 64)
        return int(p, 16)

    # Because python is incapable of turning a negative integer into a hex value
    # easily apparently...
    def tohex(self, val, nbits):
        # -1 because hex() tacks on a L to hex values...
        return hex((val + (1 << nbits)) % (1 << nbits))[:-1]

class tchelp(tccmd):
    "Details about all libtalloc gdb commands"

    def __init__(self):
        super(tchelp, self).__init__("tchelp", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        print('[libtalloc] talloc commands for gdb')
        print('[libtalloc] tcchunk -v -x <addr>      : show chunk contents (-v for verbose, -x for data dump)')
        print('[libtalloc] tcvalidate -a <addr>      : validate chunk (-a for whole heap)')
        print('[libtalloc] tcsearch <hex> <addr>     : search heap for hex value or address')
        print('[libtalloc] tcfindaddr <addr>         : search heap for address')
        print('[libtalloc] tcwalk <func> <addr>      : walk whole heap calling func on every chunk')
        print('[libtalloc] tcreport <addr>           : give talloc_report_full\(\) info on memory context')
        print('[libtalloc] tcdump -s <addr>          : dump chunks linked to memory context (-s for sorted by addr)')
        print('[libtalloc] tcparents <addr>          : show all parents of chunk')
        print('[libtalloc] tcchildren <addr>         : show all children of chunk')
        print('[libtalloc] tcinfo                    : show information known about heap')
        print('[libtalloc] tcprobe                   : try to collect information about talloc version')
        print('[libtalloc] tcpool -v -f -l -x <addr> : dump information about a talloc pool')
        print('[libtalloc] tchelp                    : this help message')

class tcchunk(tccmd):
    def __init__(self):
        super(tcchunk, self).__init__("tcchunk", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def help(self):
        print('[libtalloc] usage: tcchunk [-v] [-f] [-x] <addr>')
        print('[libtalloc]  <addr> a talloc chunk header')
        print('[libtalloc]  -v     use verbose output (multiples for more verbosity)')
        print('[libtalloc]  -f     use <addr> explicitly, rather than be smart')
        print('[libtalloc]  -x     hexdump the chunk contents')

    def invoke(self, arg, from_tty):
        verbose = 0
        force = False
        hexdump = False
        p = None
        if arg == '':
            self.help()
            return
        for item in arg.split():
            if item.find("-v") != -1:
                verbose += 1
            if item.find("-f") != -1:
                force = True
            if item.find("-x") != -1:
                hexdump = True
            if item.find("0x") != -1:
                p = int(item, 16)
            if item.find("$") != -1:
                p = self.parse_var(item)
            if item.find("-h") != -1:
                self.help()
                return
        if p == None:
            print(c_error + "WARNING: No address supplied?" + c_none)
            self.help()
            return
        if force:
            p = talloc_chunk(p)
        else:
            p = tc_chunk(p)
        if verbose == 0:
            print(chunk_info(p))
        elif verbose == 1:
            print(p)
        else:
            annotate_chunk(p)
        if hexdump:
            tc_hexdump(p)

# TODO - Move the chunk listing to a separate command eventually
class tcpool(tccmd):
    def __init__(self):
        super(tcpool, self).__init__("tcpool", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def help(self):
        print('[libtalloc] usage: tcpool [-v] [-f] [-x] <addr>')
        print('[libtalloc]  <addr> a talloc pool chunk header')
        print('[libtalloc]  -v     use verbose output (multiples for more verbosity)')
        print('[libtalloc]  -f     use <addr> explicitly, rather than be smart')
        print('[libtalloc]  -l     list all chunks inside pool')
        print('[libtalloc]  -x     hexdump the chunk contents')

    def invoke(self, arg, from_tty):
        verbose = 0
        force = False
        hexdump = False
        list_chunks = False
        p = None
        if arg == '':
            self.help()
            return
        for item in arg.split():
            if item.find("-v") != -1:
                verbose += 1
            if item.find("-f") != -1:
                force = True
            if item.find("-l") != -1:
                list_chunks = True
            if item.find("-x") != -1:
                hexdump = True
            if item.find("0x") != -1:
                p = int(item, 16)
            if item.find("$") != -1:
                p = self.parse_var(item)
            if item.find("-h") != -1:
                self.help()
                return
        if p == None:
            print(c_error + "WARNING: No address supplied?" + c_none)
            self.help()
            return
        if version_eq_or_older((2, 0, 8)):
            p = talloc_pool_chunk(p)
            if list_chunks:
                print("Pool - objects: 0x%lx, total size: 0x%lx, space left: 0x%lx, next free: 0x%lx" % \
                        (p.object_count, \
                        p.size, \
                        (p.size - (p.pool - (p.address + p.header_size))), \
                        p.pool))
            if verbose == 0:
                print_chunk(p)
            else:
                print(p)
        elif version_eq_or_newer((2, 1, 0)):
            p = talloc_pool_hdr(p)
            if list_chunks:
                print("Pool - objects: 0x%lx, total size: 0x%lx, space left: 0x%lx, next free: 0x%lx" % \
                        (p.object_count, \
                        p.poolsize, \
                        (p.poolsize - (p.end - (p.address + p.header_size + p.chunk.header_size))), \
                        p.end))

            if verbose == 0:
                print_chunk(p.chunk)
            else:
                print(p)

        if list_chunks:
            p.dump()

class tcvalidate(tccmd):
    def __init__(self):
        super(tcvalidate, self).__init__("tcvalidate", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def help(self):
        print('[libtalloc] usage: tcvalidate <addr>')
        print('[libtalloc]  <addr> a talloc chunk header')
        print('[libtalloc] ex: tcvalidate 0x41414141')
        return

    def invoke(self, arg, from_tty):
        arg = arg.split()
        if len(arg) != 1:
            self.help()
            return
        if arg[0].find("0x") != -1:
            p = int(arg[0], 16)
        elif arg[0].find("$") != -1:
            p = self.parse_var(arg[0])
        else:
            self.help()
            return

        # not tc_chunk() because we don't want to fixup
        p = talloc_chunk(p)
        if is_valid_chunk(p) == True:
            print("Chunk header is valid")

        else:
            print("Chunk header is invalid:")
            validate_chunk(p)

class tcsearch(tccmd):
    def __init__(self):
        super(tcsearch, self).__init__("tcsearch", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def help(self):
        print('[libtalloc] usage: tcsearch <hex> <chunk>')

    def invoke(self, arg, from_tty):
        global null_context
        if arg == '':
            self.help()
            return
        arg = arg.split()
        search_for = arg[0]
        if len(arg) != 2 or arg[1] == '':
            if null_context != None:
                p = null_context
            else:
                print(c_error + "WARNING: Don't know null_context and no address given" + c_none)
                self.help()
                return
        elif arg[1].find("0x") != -1:
            p = int(arg[1], 16)
            p = tc_chunk(p)
        elif arg[1].find("$") != -1:
            p = self.parse_var(arg[1])
            p = tc_chunk(p)
        else:
            self.help()
            return

        results = tc_search_heap(p, search_for)

        if len(results) == 0:
            print('[libtalloc] value %s not found' % (search_for))
            return

        for result in results:
            print("[libtalloc] %s found in chunk at 0x%lx" % (search_for, int(result)))

class tcdump(tccmd):
    def __init__(self):
        super(tcdump, self).__init__("tcdump", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def help(self):
        print('[libtalloc] usage: tcdump [-s] [-a] <addr>')
        print('[libtalloc]  <addr> a talloc chunk header')
        print('[libtalloc]  -s sort output linearly by address')
        print('[libtalloc]  -a walk from upper most parent chunk')
        print('[libtalloc] ex: tcdump -s -a 0x41414141')

    def invoke(self, arg, from_tty):
        global null_context
        p = None
        sort = False
        find_top = False
        if arg == '':
            if null_context == None:
                self.help()
                return
            else:
                p = null_context
        else:
            for item in arg.split():
                if item.find("-a") != -1:
                    find_top = True
                if item.find("-s") != -1:
                    sort = True
                if item.find("-h") != -1:
                    self.help()
                    return
                if item.find("0x") != -1:
                    p = int(item,16)
                if item.find("$") != -1:
                    p = self.parse_var(item)

        if p == None:
            self.help()
            return

        if find_top:
            p = talloc_top_chunk(talloc_chunk(p))
        else:
            p = talloc_chunk(p)

        try:
            tc_print_heap(p, sort, find_top)
        except KeyboardInterrupt:
            return

class tcreport(tccmd):
    def __init__(self):
        super(tcreport, self).__init__("tcreport", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def help(self):
        print('[libtalloc] usage: tcreport [-a] <addr>')
        print('[libtalloc]  <addr> a talloc chunk header')
        print('[libtalloc]  -a     report on the full heap')

    def invoke(self, arg, from_tty):
        full = False
        if arg == '':
            self.help()
            return
        for item in arg.split():
            if item.find("-a") != -1:
                full = True
            if item.find("0x") != -1:
                p = int(item, 16)
            if item.find("$") != -1:
                p = self.parse_var(item)
            if item.find("-h") != -1:
                self.help()
                return
        talloc_report_full(tc_chunk(p), full)

class tcwalk(tccmd):

    def __init__(self):
        super(tcwalk, self).__init__("tcwalk", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def help(self):
        print('[libtalloc] This is a convenience cmd for running callback methods across the whole heap')
        print('[libtalloc] usage: tcwalk <func> <addr>')
        print('[libtalloc]  <func> a python callback method')
        print('[libtalloc]  <addr> a talloc chunk header')

    def invoke(self, arg, from_tty):
        arg = arg.split()
        global null_context
        if len(arg) != 2 and null_context == None:
            self.help()
            return
        method = arg[0]
        if null_context:
            chunk = null_context
        elif (arg[1].find("0x") != -1):
            chunk = arg[1]
        elif (arg[1].find("$") != -1):
            chunk = self.parse_var(arg[1])
        else:
            print(arg[1])
            self.help()
            return

        if chunk == null_context:
            gdb.execute(("python tc_walk_heap(tc_chunk(0x%lx), %s)" % (chunk.address, method)), True)
        else:
            gdb.execute(("python tc_walk_heap(tc_chunk(%s), %s)" % (chunk, method)), True)

class tcparents(tccmd):
    def __init__(self):
        super(tcparents, self).__init__("tcparents", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def help(self):
        print('[libtalloc] usage: tcparents <addr>')
        print('[libtalloc]  <addr> a talloc chunk header')

    def invoke(self, arg, from_tty):
        if arg == '':
            self.help()
            return
        arg = arg.split()
        if arg[0].find("0x") != -1:
            p = int(arg[0], 16)
        elif arg[0].find("$") != -1:
            p = self.parse_var(arg[0])
        else:
            self.help()
            return
        talloc_print_parents(tc_chunk(p))

class tcchildren(tccmd):
    def __init__(self):
        super(tcchildren, self).__init__("tcchildren", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def help(self):
        print('[libtalloc] usage: tcchildren <addr>')
        print('[libtalloc]  <addr> a talloc header')

    def invoke(self, arg, from_tty):
        if arg == '':
            self.help()
            return
        arg = arg.split()
        if arg[0].find("0x") != -1:
            p = int(arg[0], 16)
        elif arg[0].find("$") != -1:
            p = self.parse_var(arg[0])
        else:
            self.help()
            return
        talloc_print_children(tc_chunk(p))

class tcprobe(tccmd):
    def __init__(self):
        super(tcprobe, self).__init__("tcprobe", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def help(self):
        print('[libtalloc] Find information about libtalloc used by process')
        print('[libtalloc] usage: tcprobe')

    # TODO - The version finding logic assumes the last entry found is the highest
    # version. It works in testing, but might not always be true. Should actually
    # compute the highest of the read values or something.
    def invoke(self, arg, from_tty):
        global talloc_version
        global talloc_path

        if talloc_version == None:
            find_talloc_version()

        print("Version: " + ''.join(str(i) + "." for i in talloc_version) + '\b ')
        print("File: " + talloc_path)

class tcinfo(tccmd):
    def __init__(self):
        super(tcinfo, self).__init__("tcinfo", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        global null_context
        global talloc_version
        global talloc_path

        if null_context != None:
            print("[libtalloc] null_context: 0x%x" % null_context.address)
        else:
            print("[libtalloc] null_context not yet found yet")

        if talloc_version == None or talloc_path == None:
            print("[libtalloc] UNKNOWN version! run tcprobe command!")
        else:
            print("[libtalloc] Version: " + ''.join(str(i) + "." for i in talloc_version) + '\b ')
            print("[libtalloc] File: " + talloc_path)

class tcfindaddr(tccmd):
    def __init__(self):
        super(tcfindaddr, self).__init__("tcfindaddr", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def help(self):
        print('[libtalloc] usage: tcsearch <hex> <chunk>')
        print('[libtalloc]  -a <address> search if address falls within known chunks')
        print('[libtalloc]  <addr> talloc chunk address. needed only if null_context not known')

    def invoke(self, arg, from_tty):
        global null_context
        if arg == '':
            self.help()
            return
        arg = arg.split()
        search_addr = int(arg[0], 16)
        if len(arg) != 2 or arg[1] == '':
            if null_context != None:
                p = null_context
            else:
                print(c_error + "WARNING: Don't know null_context and no address given" + c_none)
                self.help()
                return
        elif arg[1].find("0x") != -1:
            p = int(arg[1], 16)
            p = tc_chunk(p)
        elif arg[1].find("$") != -1:
            p = self.parse_var(arg[1])
            p = tc_chunk(p)
        else:
            self.help()
            return

        results = tc_find_addr(p, search_addr)

        if len(results) == 0:
            print('[libtalloc] value %s not found' % (search_for))
            return

        for chunk in results:
            print('[libtalloc] address 0x%lx falls within chunk @ 0x%lx (size 0x%lx)' % \
                    (search_addr, chunk.address, chunk.size))

################################################################################
# GDB PRETTY PRINTERS
################################################################################

class TallocChunkPrinter:
    "pretty print a struct talloc_chunk"
    def __init__(self, val):
        self.val = val

    def to_string(self):
        global talloc_version
        string = []
        string.append("%s%s%lx%s%lx%s%lx%s%lx%s%lx%s%lx%s%lx%s%lx%s%x" %    \
                    (c_title + "struct talloc_chunk {",
                    c_none + "\nnext        = " + c_value + "0x",
                    self.val['next'],                               \
                    c_none + "\nprev        = " + c_value + "0x", \
                    self.val['prev'],                                    \
                    c_none + "\nparent      = " + c_value + "0x", \
                    self.val['parent'],                                      \
                    c_none + "\nchild       = " + c_value + "0x", \
                    self.val['child'],                                      \
                    c_none + "\nrefs        = " + c_value + "0x", \
                    self.val['refs'],                             \
                    c_none + "\ndestructor  = " + c_value + "0x", \
                    self.val['destructor'],
                    c_none + "\nname        = " + c_value + "0x", \
                    self.val['name'], \
                    c_none + "\nsize        = " + c_value + "0x", \
                    self.val['size'], \
                    c_none + "\nflags       = " + c_value + "0x", \
                    self.val['flags']))

        if version_eq_or_newer((2, 0, 8)):
            string.append("%s%lx" %
                    c_none + "\nlimit        = " + c_value + "0x", \
                    self.val['limit'])

        string.append("%s%lx%s" %
                    c_none + "\npool        = " + c_value + "0x", \
                    self.val['pool'], \
                    c_none)
        return ''.join(string)

################################################################################
def pretty_print_tc_heap_lookup(val):
    "Look-up and return a pretty-printer that can print val."

    # Get the type.
    type = val.type

    # If it points to a reference, get the reference.
    if type.code == gdb.TYPE_CODE_REF:
        type = type.target()

    # Get the unqualified type, stripped of typedefs.
    type = type.unqualified().strip_typedefs()

    # Get the type name.
    typename = type.tag
    if typename == None:
        return None
    elif (typename == "talloc_chunk") or (typename == "tc_chunk"):
        return TallocChunkPrinter(val)
    else:
        print(typename)

    # Cannot find a pretty printer.  Return None.
    return None

tchelp()
tcinfo()
tcchunk()
tcpool()
tcvalidate()
tcsearch()
tcwalk()
tcreport()
tcdump()
tcparents ()
tcchildren()
tcprobe()
tcfindaddr()
gdb.pretty_printers.append(pretty_print_tc_heap_lookup)
