# libtalloc

libtalloc is a python script for use with GDB that can be used to analyse the
"trivial allocator" (talloc). An introduction is about talloc can be found here:

https://talloc.samba.org/talloc/doc/html/index.html

libtalloc was inspired by other gdb python scripts for analyzing heaps like
unmask_jemalloc and libheap. Some basic functionality is identical to these
projects.

https://github.com/cloudburst/libheap
https://github.com/argp/unmask_jemalloc

Please note that I am no python guru and the code quality reflects this. If you
see something that disgusts you, feel free to send a patch or give me some
suggestions. All feedback is welcome.

# Testing

libtalloc has been tested on a variety of 2.x releases of talloc and supports
dynamic version detection in order to try to overcome various structural
differences across the versions. It has been tested on 32-bit and 64-bit,
however not exhaustively, so don't be surprised if it breaks from time to time.

It has been tested to some degree on x86 and x64: 
* 2.0.7
* 2.0.8
* 2.1.0
* 2.1.1

If you test it on another version, please let me know if it worked, or what
broke and I will try to update it and/or the docs accordingly.

# Installation

The script just requires a relatively modern version of GDB with python support.

Some LTS distros, like Ubuntu 12.04, still use GDB with python 2.7, whereas
newer versions like 14.04 use python 3.0. I tried to make this script work with
both, so you should only need to:

    (gdb) source libtalloc.py

# Usage

Most of the functionality is modeled after the approach by unmask_jemalloc,
where a separate GDB command is provided rather than a complex set of switches.

A number of methods specifically designed to mimic the talloc library C
functions are available, to help people trying to extend libtalloc if they're
already familiar with the library.

To see a full list of commands you can issue the tchelp command:

    (gdb) tchelp
    [libtalloc] talloc commands for gdb
    [libtalloc] tcchunk -v -x <addr>  : show chunk contents (-v for verbose, -x for data dump)
    [libtalloc] tcvalidate -a <addr>  : validate chunk (-a for whole heap)
    [libtalloc] tcsearch <addr>       : search heap for hex value or address
    [libtalloc] tcwalk <func>         : walk whole heap calling func on every chunk
    [libtalloc] tcreport <addr>       : give talloc_report_full() info on memory context
    [libtalloc] tcdump -s <addr>      : dump chunks linked to memory context (-s for sorted by addr)
    [libtalloc] tcparents <addr>      : show all parents of chunk
    [libtalloc] tcchildren <addr>     : show all children of chunk
    [libtalloc] tcinfo                : show information known about heap
    [libtalloc] tcprobe               : try to collect information about talloc version
    [libtalloc] tchelp                : this help message

## Dynamic Version Probing

One of the most important commands is tcprobe. It needs to be run in order to
figure out what version of talloc is actually installed. The structure layouts
for different versions can vary significantly, so in order for most functions to
work the version must be known.

If the command works, it should tell you the detected version:

    (gdb) tcprobe
    Version: 2.1.1 
    File: /usr/lib/libtalloc.so.2.1.1

## Meta information 

The tcinfo command is meant to show as much information collected about the heap
as possible, such as the information from tcprobe, the null_context structure if
it was found, and more. Atm it only shows the version and if the null_context is
set. The null_context is required for most of the functions that walk the actual
heirarchy, and in order to find it most other functionality, like tchunk, etc
will try to auto-find it.

After tcprobe is run but before tchunk is actually used:

(gdb) tcinfo
[libtalloc] null_context not yet found yet
[libtalloc] Version: 2.0.7 
[libtalloc] File: /usr/lib/i386-linux-gnu/libtalloc.so.2.0.7

Then after analyzing a chunk, like so:

(gdb) tcchunk 0xb94a52b0
WARNING: 0xb94a52b0 not a talloc_chunk. Assuming ptr to chunk data
0xb94a5280 sz:0x0000003c, flags:...., name:struct tevent_context

You can confirm that it was found after the fact using tcinfo.

(gdb) tcinfo
[libtalloc] null_context: 0xb94a5028
[libtalloc] Version: 2.0.7 
[libtalloc] File: /usr/lib/i386-linux-gnu/libtalloc.so.2.0.7

Now that the null_context is set you could run other commands that would
normally complain that it wasn't set, like the tcsearch command.

## Chunk analysis

tcchunk can provide you with a summary of the chunk, a more verbose output of
every field, or extremely verbose information about every surrounding chunk. 
    
NOTE: One important think to note about tcchunk is that internally it uses the
tc_chunk() method, which attempts to correct errors made when passing in the
chunk address. Specifically if you pass in the address of the chunk data
itself, if it doesn't find the expected talloc magic, it will look for a
legitimate chunk header slightly earlier in memory. This can mess with you in
corrupted scenarios, so always be sure you're passing in the explicit address
unless you're doing cursory analysis.

Summary output:

    (gdb) tcchunk 0x80a13c88
    0x80a13c88 sz:0x00000020, flags:..p., name:struct netr_ServerPasswordSet

The following is a legend for chunks within the summary output:

    p - Member of a pool (POOLMEM flag)
    P - Chunk is a pool (POOL flag)
    F - Chunk is free (FREE flag)
    L - Chunk is looped (LOOP flag)

Verbose output:

    (gdb) tcchunk -v 0x80a13c88
    struct talloc_chunk @ 0x80a13c88 {
    next         = 0x0
    prev         = 0x80a140c8
    parent       = 0x0
    child        = 0x80a14088
    refs         = 0x0
    destructor   = 0x0
    name         = 0x807d9f2f (struct netr_ServerPasswordSet)
    size         = 0x20
    flags        = 0xe8150c78 (POOLMEM)
    limit        = 0x0
    pool         = 0x80a13248

### Validation

talloc chunks contain some magic values that can be used to validate if they are
sane. The tcvalidate command will analyze a chunk to ensure that the chunk magic
is as expected. Additionally, it analyzes all other pointer members to ensure
they actually fall into memory ranges (as known by gdb), if the size is valid,
etc.

    (gdb) tcvalidate 0x80a13c88
    Chunk header is valid

We'll use a built-in method to modify a value to show how it could fail:

    (gdb) python set_destructor(tc_chunk(0x80a13c88), 0x41414141)
    (gdb) tcchunk -v 0x80a13c88
    struct talloc_chunk @ 0x80a13c88 {
    next         = 0x0
    prev         = 0x80a140c8
    parent       = 0x0
    child        = 0x80a14088
    refs         = 0x0
    destructor   = 0x41414141
    name         = 0x807d9f2f (struct netr_ServerPasswordSet)
    size         = 0x20
    flags        = 0xe8150c78 (POOLMEM)
    limit        = 0x0
    pool         = 0x80a13248
    (gdb) tcvalidate 0x80a13c88
    Chunk header is invalid:
    0x80a13c88: Chunk has bad destructor pointer 0x41414141

### Finding parents

tcparents can be used to view all parents of the provided chunk:

    (gdb) tcparents 0x80a13c88
    0x809f8300: null_context
      0x80a08660: TALLOC_CTX *
        0x809f8370: talloc_new: ../lib/util/talloc_stack.c:147
          0x809fb680: talloc_new: ../lib/util/talloc_stack.c:147
            0x80a13258: UNNAMED
              0x80a13c58: talloc_new: ../lib/util/talloc_stack.c:147
                0x80a13c88: struct netr_ServerPasswordSet

### Finding children

tchildren can be used to view all children (and grandchildren, etc) of the
provided chunk:

    (gdb) tcchildren 0x80a13c88
    0x80a14088: struct netr_Authenticator
    0x80a14048: librpc/gen_ndr/ndr_netlogon.c:10964
    0x80a14008: librpc/gen_ndr/ndr_netlogon.c:10958
    0x80a13fc8: librpc/gen_ndr/ndr_netlogon.c:10951
    0x80a13f88: lib/charcnv.c:506
    0x80a13ec8: lib/charcnv.c:506
    0x80a13d48: librpc/gen_ndr/ndr_netlogon.c:10913
      0x80a13e08: 
    0x80a13cd8: struct ndr_pull
      0x80a13f48: struct ndr_token_list
      0x80a13f08: struct ndr_token_list
      0x80a13e88: struct ndr_token_list
      0x80a13e48: struct ndr_token_list
      0x80a13dc8: struct ndr_token_list
      0x80a13d88: struct ndr_token_list

## Pool analysis

talloc has the concept of pool chunks. These are basically regular talloc chunks
but that are used for allocating new chunks rather than falling back on the
underlying malloc() implementation of the system. A pool chunk has slightly
different headers depending on the version used, sometimes using padding, and
sometimes using a prefix/suffix header.

tcpool can be used to analyze a pool chunk header, similar to tcchunk:

    # First we find a pool to analyze
    (gdb) tcchunk -v 0x80a13c88
    struct talloc_chunk @ 0x80a13c88 {
    next         = 0x0
    prev         = 0x80a140c8
    parent       = 0x0
    child        = 0x80a14088
    refs         = 0x0
    destructor   = 0x0
    name         = 0x807d9f2f (struct netr_ServerPasswordSet)
    size         = 0x20
    flags        = 0xe8150c78 (POOLMEM)
    limit        = 0x0
    pool         = 0x80a13248

    (gdb) tcpool -v 0x80a13248
    struct talloc_pool_hdr @ 0x80a13248 {
    end          = 0x80a14108
    object_count = 0x19
    poolsize     = 0x2000
    struct talloc_chunk @ 0x80a13258 {
    next         = 0x0
    prev         = 0x0
    parent       = 0x809fb680
    child        = 0x80a13c58
    refs         = 0x0
    destructor   = 0x80429aa0
    name         = 0x0 (UNNAMED)
    size         = 0x0
    flags        = 0xe8150c74 (POOL)
    limit        = 0x0
    pool         = 0x0

In the case above the pool had a prefixed talloc_pool_hdr, which is shown. The
-l option can be passed to tcpool to list all of the allocated chunks within a
pool:

    (gdb) tcpool -l 0x80a13248
    Pool summary -- objects: 0x19, total size: 0x2000, space left: 0x1180, next free: 0x80a14108
    0x80a13258 sz:0x00000000, flags:.P.., name:UNNAMED
    0x80a13288 sz:0x000007a3, flags:..p., name:char
    0x80a13a68 sz:0x0000005c, flags:..p., name:struct smb_request
    0x80a13af8 sz:0x00000008, flags:..p., name:struct pipe_write_andx_state
    0x80a13b38 sz:0x00000038, flags:..p., name:struct tevent_req
    0x80a13ba8 sz:0x00000028, flags:..p., name:struct tevent_immediate
    0x80a13c08 sz:0x00000014, flags:..p., name:struct np_write_state
    0x80a13c58 sz:0x00000000, flags:..p., name:talloc_new: ../lib/util/talloc_stack.c:147
    0x80a13c88 sz:0x00000020, flags:..p., name:struct netr_ServerPasswordSet
    0x80a13cd8 sz:0x00000038, flags:..p., name:struct ndr_pull
    0x80a13d48 sz:0x00000001, flags:..p., name:librpc/gen_ndr/ndr_netlogon.c:10913
    0x80a13d88 sz:0x00000010, flags:..p., name:struct ndr_token_list
    0x80a13dc8 sz:0x00000010, flags:..p., name:struct ndr_token_list
    0x80a13e08 sz:0x00000001, flags:..p., name:
    0x80a13e48 sz:0x00000010, flags:..p., name:struct ndr_token_list
    0x80a13e88 sz:0x00000010, flags:..p., name:struct ndr_token_list
    0x80a13ec8 sz:0x00000008, flags:..p., name:lib/charcnv.c:506
    0x80a13f08 sz:0x00000010, flags:..p., name:struct ndr_token_list
    0x80a13f48 sz:0x00000010, flags:..p., name:struct ndr_token_list
    0x80a13f88 sz:0x00000008, flags:..p., name:lib/charcnv.c:506
    0x80a13fc8 sz:0x0000000c, flags:..p., name:librpc/gen_ndr/ndr_netlogon.c:10951
    0x80a14008 sz:0x00000010, flags:..p., name:librpc/gen_ndr/ndr_netlogon.c:10958
    0x80a14048 sz:0x0000000c, flags:..p., name:librpc/gen_ndr/ndr_netlogon.c:10964
    0x80a14088 sz:0x0000000c, flags:..p., name:struct netr_Authenticator
    0x80a140c8 sz:0x0000000b, flags:..p., name:/etc/samba

Note the P flag in the output above, the top chunk being the pool chunk that
holds all of the chunks below.

## Heap dumping

tcdump can be used to dump all chunks in the entire tree. By default they are
shown in a heirarchical order, however the -s option can be used to sort the
output by address.

    (gdb) tcdump -a 0x809f8300
    0x809f8300 sz:0x00000000, flags:...., name:null_context
    0x80a0b3f8 sz:0x0000000c, flags:...., name:struct handle_list
    0x809ff178 sz:0x00000014, flags:...., name:struct security_token
    0x80a089e8 sz:0x00000198, flags:...., name:lib/util_nttoken.c:50
    0x80a07268 sz:0x00000188, flags:...., name:connection_struct
    0x80a08bc8 sz:0x00000020, flags:...., name:struct fd_handle
    0x80a00c30 sz:0x000000f0, flags:...., name:struct files_struct
    0x80a083b8 sz:0x00000008, flags:...., name:struct fake_file_handle
    0x80a08c20 sz:0x0000009c, flags:...., name:struct pipes_struct
    0x80a07900 sz:0x00000760, flags:...., name:uint8_t
    0x80a07428 sz:0x000000c0, flags:...., name:struct auth_serversupplied_info
    0x80a06390 sz:0x00000001, flags:...., name:
    0x80a06350 sz:0x00000007, flags:...., name:nobody
    0x80a06158 sz:0x000000cc, flags:...., name:struct netr_SamInfo3
    0x80a062d8 sz:0x00000044, flags:...., name:struct dom_sid
    [SNIP]

tcreport is a command similar to tcdump but it prettifies the output somewhat
and is meant to mimic the talloc_report_full() debug function provided by the
talloc library itself.

    (gdb) tcreport 0x80a0b3f8 -a
    Full talloc report on 'null_context' (total 558651 bytes in 446 blocks)
        struct handle_list             contains     12 bytes in   1 blocks (ref 67) 0x80a0b3f8
        struct security_token          contains    428 bytes in   2 blocks (ref 66) 0x809ff178
            lib/util_nttoken.c:50          contains    408 bytes in   1 blocks (ref 0) 0x80a089e8
        connection_struct              contains 531071 bytes in  36 blocks (ref 65) 0x80a07268
            struct fd_handle               contains     32 bytes in   1 blocks (ref 4) 0x80a08bc8
            struct files_struct            contains 529681 bytes in  22 blocks (ref 3) 0x80a00c30
                struct fake_file_handle        contains 529308 bytes in  19 blocks (ref 1) 0x80a083b8
                    struct pipes_struct            contains 529300 bytes in  18 blocks (ref 0) 0x80a08c20
                        uint8_t                        contains   1888 bytes in   1 blocks (ref 2) 0x80a07900
                        struct auth_serversupplied_info contains    934 bytes in  10 blocks (ref 1) 0x80a07428
                                                           contains      1 bytes in   1 blocks (ref 4) 0x80a06390
                            nobody                         contains      7 bytes in   1 blocks (ref 3) 0x80a06350
                            struct netr_SamInfo3           contains    290 bytes in   4 blocks (ref 2) 0x80a06158
    [SNIP]

## Searching

There are two commands for searching: tcsearch and tcfindaddr.

tcsearch can be used to find chunks that contain the provided hexadecimal value.
It works by walking the entire tree heirarchy starting from the null_context (if
known), or from a starting chunk provided.

    (gdb) python set_destructor(tc_chunk(0x80a13c88), 0x41414141)
    (gdb) tcsearch 0x41414141 0x809f8300
    [libtalloc] 0x41414141 found in chunk at 0x80a1d218
    [libtalloc] 0x41414141 found in chunk at 0x80a13c88
    (gdb) tcchunk -v 0x80a1d218
    struct talloc_chunk @ 0x80a1d218 {
    next         = 0x80a00158
    prev         = 0x809fb0c8
    parent       = 0x0
    child        = 0x0
    refs         = 0x0
    destructor   = 0x0
    name         = 0x8071fcbd (uint8_t)
    size         = 0x80050
    flags        = 0xe8150c70 ()
    limit        = 0x0
    pool         = 0x0
    (gdb) tcchunk -x 0x80a1d218
    0x80a1d218 sz:0x00080050, flags:...., name:uint8_t
    Chunk data (524368 bytes):
    0x80a1d248:	0x41414141	0x00000000	0x00000000	0x00000000
    0x80a1d258:	0x00000001	0x00000000	0x00000001	0x00020000
    0x80a1d268:	0x00000001	0x00000000	0x00000001	0xaaaa0000
    [SNIP]    
    (gdb) tcchunk -v 0x80a13c88
    struct talloc_chunk @ 0x80a13c88 {
    next         = 0x0
    prev         = 0x80a140c8
    parent       = 0x0
    child        = 0x80a14088
    refs         = 0x0
    destructor   = 0x41414141
    name         = 0x807d9f2f (struct netr_ServerPasswordSet)
    size         = 0x20
    flags        = 0xe8150c78 (POOLMEM)
    limit        = 0x0
    pool         = 0x80a13248

tcfindaddr can be used to determine if an address falls within the boundary of a
chunk within the talloc tree. Say you know that 0x80a1d3280 has some data you
control, so you want to see if it falls within a chunk. Note the second address
is the null_context, but can be any chunk that lets us find the top of the heap. 

    (gdb) tcfindaddr 0x80a1d328 0x809f8300
    [libtalloc] address 0x80a1d328 falls within chunk @ 0x80a1d218 (size 0x80050)

## Heap walking

Some of the tree searching is done using a recursive function that I exposed via
the tcwalk command. It is a helper function that lets you specify a python
method that will be called on every discovered chunk in the tree.

In the example below we'll call the heap validation method on every chunk in the
heap to see if anything is corrupted.

    (gdb) tcwalk validate_chunk 
    0x80a13c88: Chunk has bad destructor pointer 0x41414141

Note that if null_context hasn't been set you have to pass a chunk address as
the second argument.

# Contact

Written by Aaron Adams

Email: aaron<dot>adams<at>nccgroup<dot>trust
Twitter: @fidgetingbits
