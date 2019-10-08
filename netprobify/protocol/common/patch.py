"""Monkey patching."""
# pylama:ignore=W0401

from scapy.all import *


def attach_filter_linux(s, bpf_filter, iface):
    """Monkey patch from https://github.com/secdev/scapy/pull/1653/files."""
    # mode
    if not TCPDUMP:
        return
    try:
        f = os.popen(
            "%s -p -i %s -ddd -s %d '%s'"
            % (conf.prog.tcpdump, conf.iface if iface is None else iface, MTU, bpf_filter)
        )
    except OSError:
        log_interactive.warning("Failed to attach filter.", exc_info=True)
        return
    lines = f.readlines()
    ret = f.close()
    if ret:
        log_interactive.warning("Failed to attach filter: tcpdump returned %d", ret)
        return

    bp = get_bpf_pointer(lines)
    s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bp)


def attach_filter_core(fd, iface, bpf_filter_string):
    """Monkey patch from https://github.com/secdev/scapy/pull/1653/files."""
    # Retrieve the BPF byte code in decimal
    cmd_fmt = "%s -p -i %s -ddd -s 1600 '%s'"
    command = cmd_fmt % (conf.prog.tcpdump, iface, bpf_filter_string)
    try:
        f = os.popen(command)
    except OSError as msg:
        raise Scapy_Exception("Failed to execute tcpdump: (%s)" % msg)

    # Convert the byte code to a BPF program structure
    lines = f.readlines()
    if lines == []:
        raise Scapy_Exception("Got an empty BPF filter from tcpdump !")

    bp = get_bpf_pointer(lines)
    # Assign the BPF program to the interface
    ret = LIBC.ioctl(c_int(fd), BIOCSETF, cast(pointer(bp), c_char_p))
    if ret < 0:
        raise Scapy_Exception("Can't attach the BPF filter !")
