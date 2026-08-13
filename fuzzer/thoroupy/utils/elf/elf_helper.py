from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarfinfo import DWARFInfo

from elftools.dwarf.descriptions import describe_form_class

class ELF:
    def __init__(self, path) -> None:
        self.elf = ELFFile(open(path, 'rb'))
        if self.elf.has_dwarf_info():
            self.dwarf = self.elf.get_dwarf_info()
        else:
            self.dwarf = None
    
    def get_loc(self, address:int) -> tuple[str, str, int] | tuple[None, None, None]:
        if self.dwarf:
            try:
                return get_address(self.dwarf, address)
            except:
                return (None, None, None)
        else:
            return (None, None, None)


def get_address(dwarfinfo:DWARFInfo, address:int) -> tuple[str, str, int]:
    """
    Parse the given debuginfo and address and return the filename, function name and lineno
    """

    funcname:bytes = decode_funcname(dwarfinfo, address)   # type: ignore
    file: bytes
    line: int
    file, line, col = decode_file_line(dwarfinfo, address) # type: ignore

    return file.decode("latin-1"), funcname.decode("latin-1"), line, col

def decode_funcname(dwarfinfo, address):
    # Go over all DIEs in the DWARF information, looking for a subprogram
    # entry with an address range that includes the given address. Note that
    # this simplifies things by disregarding subprograms that may have
    # split address ranges.
    for CU in dwarfinfo.iter_CUs():
        for DIE in CU.iter_DIEs():
            try:
                if DIE.tag == 'DW_TAG_subprogram':
                    lowpc = DIE.attributes['DW_AT_low_pc'].value

                    # DWARF v4 in section 2.17 describes how to interpret the
                    # DW_AT_high_pc attribute based on the class of its form.
                    # For class 'address' it's taken as an absolute address
                    # (similarly to DW_AT_low_pc); for class 'constant', it's
                    # an offset from DW_AT_low_pc.
                    highpc_attr = DIE.attributes['DW_AT_high_pc']
                    highpc_attr_class = describe_form_class(highpc_attr.form)
                    if highpc_attr_class == 'address':
                        highpc = highpc_attr.value
                    elif highpc_attr_class == 'constant':
                        highpc = lowpc + highpc_attr.value
                    else:
                        print('Error: invalid DW_AT_high_pc class:',
                              highpc_attr_class)
                        continue

                    if lowpc <= address < highpc:
                        return DIE.attributes['DW_AT_name'].value
            except KeyError:
                continue
    return None


def decode_file_line(dwarfinfo, address):
    # Go over all the line programs in the DWARF information, looking for
    # one that describes the given address.
    for CU in dwarfinfo.iter_CUs():
        # First, look at line programs to find the file/line for the address
        lineprog = dwarfinfo.line_program_for_CU(CU)
        delta = 1 if lineprog.header.version < 5 else 0
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None:
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate and prevstate.address <= address < entry.state.address:
                filename = lineprog['file_entry'][prevstate.file - delta].name
                line = prevstate.line
                column = prevstate.column
                return filename, line, column
            if entry.state.end_sequence:
                # For the state with `end_sequence`, `address` means the address
                # of the first byte after the target machine instruction
                # sequence and other information is meaningless. We clear
                # prevstate so that it's not used in the next iteration. Address
                # info is used in the above comparison to see if we need to use
                # the line information for the prevstate.
                prevstate = None
            else:
                prevstate = entry.state
    return None, None, None




if __name__ == "__main__":
    elf = ELFFile(open("/workdir/ucsan/testsuite/binary/checker_ubi.ucsan", 'rb'))
    dwarf = elf.get_dwarf_info()
    print(get_address(dwarf, 0x700000205d0c))

