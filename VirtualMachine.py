from cmd import Cmd

############# globals (helper) ##############
hex_values = {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7,
              "8": 8, "9": 9, "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15}
op_codes = {"0000": "HALT", "0001": "ADD", "0010": "AND", "0011": "NOT",
            "0100": "LD", "0101": "LDI", "0110": "LDR", "0111": "ST",
            "1000": "STI", "1001": "STR", "1010": "GET", "1011": "PUT",
            "1100": "BR", "1101": "JMP", "1110": "JMPR", "1111": "RET"}

assemble_codes = {"HALT": "0000", "ADD": "0001", "AND": "0010", "NOT": "0011",
                  "LD": "0100", "LDI": "0101", "LDR": "0110", "ST": "0111",
                  "STI": "1000", "STR": "1001", "GET": "1010 0", "GETC": "1010 1", "PUT": "1011 0", "PUTC": "1011 1",
                  "BR": "1100", "JMP": "11010", "JSR": "11011", "JMPR": "11100", "JSRR": "11101", "RET": "1111"}


class AssemblyException(Exception):
    pass


class OperationException(Exception):
    pass


############# globals (VM values) ##############
########## also set by initialize() ############
memory = []
registers = []
instr_pt = ""
instr_reg = ""
nzp = [0, 0, 0]
run = False  # global so halt can touch it


############# helper functions ##############
def update_nzp(bin_str):
    global nzp
    if bin_str[0] == "1":  # negative
        nzp = [1, 0, 0]
    else:
        nzp = [0, 1, 0]  # zero
        for d in bin_str:
            if d == "1":  # positive
                nzp = [0, 0, 1]
                # print(f"DEBUG:\nInstr = {bin_str};\nNZP = {nzp}")
    # print(f"DEBUG: nzp = {nzp}")
    return

    # print(f"DEBUG:\nInstr = {bin_str};\nNZP = {nzp}")


def bin_add(bin1, bin2):
    # assuming 2's complement, not signed magnitude
    # also assuming 16-bit strings
    result = ""
    carry = 0
    for i in range(15, -1, -1):
        bit_sum = int(bin1[i]) + int(bin2[i]) + carry
        # print("[DEBUG] bitSum:",bitSum," | i:",i)
        if bit_sum > 1:
            carry = 1
            if bit_sum == 2:
                result = "0" + result
            elif bit_sum == 3:
                result = "1" + result
            else:
                raise ArithmeticError("bit_add() messed something up")
        else:
            carry = 0
            result = str(bit_sum) + result
        # print("[DEBUG] current result: "+ result)
    # if carry == 1:
    #     result = "1" + result
    return result


def bin_not(bin_str):
    return "".join([("1" if bin_str[i] == "0" else "0") for i in range(16)])


def sign_extend(bin_str):
    return bin_str[0] * (16 - len(bin_str)) + bin_str


def int_to_hex(num):
    hex_key = list(hex_values.keys())
    bits = ["0", "0", "0", "0"]
    bits[0] = hex_key[int(num / 4096)]
    bits[1] = hex_key[int((num - hex_values[bits[0]] * 4096) / 256)]
    bits[2] = hex_key[int((num - hex_values[bits[0]] * 4096 - hex_values[bits[1]] * 256) / 16)]
    bits[3] = hex_key[int((num - hex_values[bits[0]] * 4096 - hex_values[bits[1]] * 256 - hex_values[bits[2]] * 16))]
    return "x" + "".join(bits)


def hex_to_int(hex_str):
    return hex_values[hex_str[1].upper()] * 4096 + hex_values[hex_str[2].upper()] * 256 + \
           hex_values[hex_str[3].upper()] * 16 + hex_values[hex_str[4].upper()]


def hex_to_bin(hex_str):
    return bin(hex_values[hex_str[1]])[2:].zfill(4) + bin(hex_values[hex_str[2]])[2:].zfill(4) + \
           bin(hex_values[hex_str[3]])[2:].zfill(4) + bin(hex_values[hex_str[4]])[2:].zfill(4)


def bin_to_hex(bin_str):
    hex_key = list(hex_values.keys())
    hexes = ["0", "0", "0", "0"]
    for i in range(1, 5):
        val = 0
        chunk = bin_str[i * 4 - 4: i * 4]
        for b in range(4):
            val += int(chunk[b]) * 2 ** (3 - b)
        hexes[i - 1] = hex_key[val]
    return "x" + "".join(hexes)


def bin_to_int(bin_str):
    return sum([2 ** (15 - i) * int(bin_str[i]) for i in range(len(bin_str))])


def int_to_bin(num):
    return hex_to_bin(int_to_hex(num))


def bin_to_reg(bin_str):
    return 4 * int(bin_str[0]) + 2 * int(bin_str[1]) + int(bin_str[2])


def int_to_tc(num):
    if num > 32767 or num < -32768:
        raise OperationException("Integer passed to int_to_tc exceeds 16-bit limit")
    if num >= 0:
        return int_to_bin(num)
    else:
        return bin_add(bin_not(int_to_bin(-num)), sign_extend("01"))


def tc_to_int(bin_str):
    if bin_str[0] == "0":
        return sum([2 ** (15 - i) * int(bin_str[i]) for i in range(len(bin_str))])
    else:
        count = 0
        total = 0
        for i in range(15, -1, -1):
            if int(bin_str[i]) == 1:
                total += 2 ** count
            count += 1
        return (-1 * (2 ** count)) + total


def bin_and(bin_s1, bin_s2):
    return "".join([("1" if ((bin_s1[i] == bin_s2[i]) and (bin_s1[i] == "1")) else "0") for i in range(16)])


def page_offset9(page_reg, offset):
    """16-bit register(1st 7 bits) + offset(9 bits)"""
    return page_reg[0:7] + offset


def ascii_to_bin(char):
    return format(ord(char), "016b")


def bin_to_ascii(bin_str):
    return chr(bin_to_int(bin_str))


############# EOC-21 OP code functions ##############
# TODO: make HALT into TRAP
def vm_halt():
    global run, instr_reg
    run = False
    op = op_codes[instr_reg[0:4]]
    # temporary Decode line
    # print(f"{op}")
    return


def vm_add(instr):
    global nzp, registers
    op = op_codes[instr[0:4]]
    sr1_idx = bin_to_reg(instr[7:10])
    dr_idx = bin_to_reg(instr[4:7])
    sr1 = registers[sr1_idx]
    if int(instr[10]):  # immediate bits
        imm5 = sign_extend(instr[11:16])
        dr = bin_add(sr1, imm5)
        # temporary Decode line
        # print(f"{op} R{dr_idx} R{sr1_idx} {imm5}")
    else:  # register 2
        sr2_idx = bin_to_reg(instr[13:16])
        sr2 = registers[sr2_idx]
        dr = bin_add(sr1, sr2)
        # temporary Decode line
        # print(f"{op} R{dr_idx} R{sr1_idx} R{sr2_idx}")
    registers[dr_idx] = dr
    update_nzp(dr)
    return


def vm_and(instr):
    op = op_codes[instr[0:4]]
    sr1_idx = bin_to_reg(instr[7:10])
    dr_idx = bin_to_reg(instr[4:7])
    sr1 = registers[sr1_idx]
    if int(instr[10]):  # immediate bits
        imm5 = sign_extend(instr[11:16])
        dr = bin_and(sr1, imm5)
        # temporary Decode line
        # print(f"{op} R{dr_idx} R{sr1_idx} {imm5}")
    else:  # register 2
        sr2_idx = bin_to_reg(instr[13:16])
        sr2 = registers[sr2_idx]
        dr = bin_and(sr1, sr2)
        # temporary Decode line
        # print(f"{op} R{dr_idx} R{sr1_idx} R{sr2_idx}")
    registers[dr_idx] = dr
    update_nzp(dr)
    return


def vm_not(instr):
    op = op_codes[instr[0:4]]
    sr1_idx = bin_to_reg(instr[7:10])
    dr_idx = bin_to_reg(instr[4:7])
    sr = registers[sr1_idx]  # get contents of SR1
    dr = bin_not(sr)  # NOT the contents
    registers[dr_idx] = dr  # set DR to the result
    update_nzp(dr)
    # temporary Decode line
    # print(f"{op} R{dr_idx} R{sr1_idx}")
    return


def vm_ld(instr):
    op = op_codes[instr[0:4]]
    dr_idx = bin_to_reg(instr[4:7])
    dr = memory[bin_to_int(page_offset9(instr_pt, instr[7:16]))].strip()
    registers[dr_idx] = dr  # set DR to the page loaded from memory
    update_nzp(dr)
    # temporary Decode line
    # print(f"{op} R{dr_idx} {dr}")
    return


def vm_ldi(instr):
    op = op_codes[instr[0:4]]
    dr_idx = bin_to_reg(instr[4:7])
    dr = memory[bin_to_int(memory[bin_to_int(page_offset9(instr_pt, instr[7:16]))])]
    # TODO: confirm that this is indirect now
    registers[dr_idx] = dr  # set DR to the page loaded from memory
    update_nzp(dr)
    # temporary Decode line
    # print(f"{op} R{dr_idx} {dr}")
    return


# location = bin_add(registers[bin_to_reg(instr[7:10])],sign_extend(instr[10:16]))
# idx = bin_to_int(location)

def vm_ldr(instr):
    op = op_codes[instr[0:4]]
    dr_idx = bin_to_reg(instr[4:7])
    dr = memory[bin_to_int(bin_add(registers[bin_to_reg(instr[7:10])], sign_extend(instr[10:16])))].strip()
    registers[dr_idx] = dr  # set DR to the page loaded from memory
    update_nzp(dr)
    # temporary Decode line
    # print(f"{op} R{dr_idx} {dr}")
    return


def vm_st(instr):
    op = op_codes[instr[0:4]]
    sr_idx = bin_to_reg(instr[4:7])
    sr = registers[sr_idx]
    memory[bin_to_int(page_offset9(instr_pt, instr[7:16]))] = sr  # save contents of SR to memory (instr_pt + offset)
    # temporary Decode line
    # print(f"{op} R{sr_idx} {page_offset9(instr_pt, instr[7:16])}")
    return


def vm_sti(instr):
    op = op_codes[instr[0:4]]
    sr_idx = bin_to_reg(instr[4:7])
    sr = registers[sr_idx]
    # TODO: confirm that this is indirect now
    # save contents of SR to address found at memory(instr_pt + offset)
    memory[bin_to_int(memory[bin_to_int(page_offset9(instr_pt, instr[7:16]))])] = sr
    # temporary Decode line
    # print(f"{op} R{sr_idx} {page_offset9(instr_pt, instr[7:16])}")
    return


def vm_str(instr):
    op = op_codes[instr[0:4]]
    sr_idx = bin_to_reg(instr[4:7])
    sr = registers[sr_idx]
    memory[bin_to_int(bin_add(registers[bin_to_reg(instr[7:10])],
                              sign_extend(instr[10:16])))] = sr  # save contents of SR to memory (instr_pt + offset)
    # temporary Decode line
    # print(f"{op} R{sr_idx} {page_offset9(instr_pt, instr[7:16])}")
    return


def vm_get(instr):
    op = op_codes[instr[0:4]]
    dr_idx = bin_to_reg(instr[4:7])
    if int(instr[7]):  # GETC
        # op = "GETC"
        while True:
            inp = input("ASCII>> ")
            try:
                dr = ascii_to_bin(inp)
                break
            except:
                print("Invalid input.")
    else:  # GET
        while True:
            inp = input("INT>> ")
            try:
                dr = int_to_tc(int(inp))
                break
            except:
                print("Invalid input.")
    registers[dr_idx] = dr
    update_nzp(dr)
    # Decode line
    # print(f"{op} R{dr_idx} = {dr}")
    return


def vm_put(instr):
    # op = op_codes[instr[0:4]]
    sr_idx = bin_to_reg(instr[4:7])
    if int(instr[7]):  # PUTC
        sr = bin_to_ascii(registers[sr_idx])
    else:  # PUT
        sr = tc_to_int(registers[sr_idx])
    # print(f"{op} R{sr_idx}")
    print(sr, end='')
    return


def vm_br(instr):
    global instr_pt, instr_reg
    op = op_codes[instr[0:4]]
    n = int(instr[4])
    z = int(instr[5])
    p = int(instr[6])
    idx = bin_to_int(page_offset9(instr_pt, instr[7:16]))
    # print(f"DEBUG: {idx}")
    if (n and nzp[0]) or (z and nzp[1]) or (p and nzp[2]):  # if tests match
        instr_pt = int_to_bin(idx)
        instr_reg = memory[bin_to_int(instr_pt)]
    else:  # otherwise increment ip like normal
        instr_pt = int_to_bin(bin_to_int(instr_pt) + 1)
    # temporary Decode line
    # print(f"{op} {'n' if n else '' + 'z' if z else '' + 'p' if p else ''} {instr_pt}")
    return


def vm_jmp_jsr(instr):
    """JMP: Set Instruction Pointer to offset of current page unconditionally
       JSR: Store current Instruction Pointer value in Register 7"""
    global instr_pt, instr_reg, registers
    op = op_codes[instr[0:4]]
    L = int(instr[4])
    idx = bin_to_int(page_offset9(instr_pt, instr[7:16]))
    if L:  # JSR: Store current Instr_pt value in Reg 7
        op = "JSR"
        registers[7] = instr_pt
        instr_pt = int_to_bin(idx)
        instr_reg = memory[idx]
    else:  # JMP: Set instr_pt to memory address, and instr_reg to those contents
        instr_pt = int_to_bin(idx)
        instr_reg = memory[idx]
    # temporary Decode line
    # print(f"{op} {int_to_bin(idx)}")
    return


def vm_jmpr_jsrr(instr):
    global instr_pt, instr_reg, registers
    op = op_codes[instr[0:4]]
    L = int(instr[4])
    location = bin_add(registers[bin_to_reg(instr[7:10])], sign_extend(instr[10:16]))
    idx = bin_to_int(location)
    if L:  # JSR: Store current Instr_pt value in Reg 7
        op = "JSR"
        registers[7] = instr_pt
        instr_pt = int_to_bin(idx)
        instr_reg = memory[idx]
    else:  # JMP: Set instr_pt to memory address, and instr_reg to those contents
        instr_pt = int_to_bin(idx)
        instr_reg = memory[idx]
    # temporary Decode line
    # print(f"{op} {int_to_bin(idx)}")
    return


def vm_ret():
    """Set Instruction Pointer to contents of Register 7"""
    global instr_pt, instr_reg, registers
    op = op_codes[instr_pt[0:4]]
    instr_pt = registers[7]
    instr_reg = memory[bin_to_int(instr_pt)]
    # temporary Decode line
    # print(f"{op}")
    return


############# VM operations ##############
def initialize():
    global memory
    memory = []
    for i in range(2 ** 16):
        memory.append("0000000000000000".strip())
    global registers
    registers = []
    for i in range(8):
        registers.append("0000000000000000".strip())
    global nzp
    nzp = [0, 0, 0]
    global instr_pt
    instr_pt = "0000000000000000".strip()
    global instr_reg
    instr_reg = "0000000000000000".strip()


def load(inp):
    args = inp.split()
    if len(args) > 2:
        print(f"Expected two arguments (fname addr), got {len(args)}")
        return
    fname = args[0]
    if len(args[1].strip()) == 5:  # hex
        addr = hex_to_bin(args[1].strip())
    elif len(args[1].strip()) == 16:  # bin
        addr = args[1].strip()
    else:
        try:
            addr = int_to_bin(int(args[1].strip()))
        except:
            print("LOAD failed")
            return
    global instr_pt
    instr_pt = addr
    # print(f"fname: {fname}, addr: {addr}")
    line_num = 0
    with open(fname, 'r') as f:
        for line in f:
            if line[0] == ";":
                pass  # allows for line comments in .eoc files
            else:
                if len(line.strip()) != 16:
                    print(f"Line {line_num + 1} does not contain a 16-bit instruction: {line}")
                    return
                memory[bin_to_int(addr) + line_num] = line
                line_num += 1


def assemble_line(line, symbol_table):
    # TODO: Make this work with new bits (labels)
    parts = line.split()
    # print(f"DEBUG parts = {parts}")
    op = assemble_codes[parts[0]]
    if op == "1100":  # BR
        if parts[2] in symbol_table.keys():
            addr = symbol_table[parts[2]][-9:]
        else:
            addr = hex_to_bin(parts[2])[-9:]
        return op + \
               "".join(["1" if "n" in parts[1].lower() else "0",
                        "1" if "z" in parts[1].lower() else "0",
                        "1" if "p" in parts[1].lower() else "0"]) + \
               addr
    elif op[0:4] == "1101":  # JMP/JSR
        if parts[1] in symbol_table.keys():
            addr = symbol_table[parts[1]][-9:]
        else:
            addr = hex_to_bin(parts[1])[-9:]
        return op + "00" + addr
    elif op[0:4] == "1110":  # JMPR/JSRR
        # TODO: this
        return
    elif op == "0000" or op == "1111":  # HALT or RET
        # TODO: make HALT into TRAP
        return op + "000000000000"
    else:  # any of the ones taking registers first
        reg1 = int_to_bin(int(parts[1][-1:]))[-3:]
        if op == "0001" or op == "0010" or op == "0011":  # ADD or AND or NOT
            reg2 = int_to_bin(int(parts[2][-1:]))[-3:]
            if parts[2][0] == "#":
                return op + reg1 + reg1 + "1" + int_to_tc(int(parts[2][-1:]))[-5:]
            if op == "0011":  # NOT
                return op + reg1 + reg2 + "111111"
            if parts[3][0] == "R":  # SR2 AND or ADD
                return op + reg1 + reg2 + "000" + int_to_tc(int(parts[3][-1:]))[-3:]
            elif parts[3][0] == "#":  # imm5 AND or ADD
                return op + reg1 + reg2 + "1" + int_to_tc(int(parts[3][-1:]))[-5:]
        elif op[0:4] == "1010" or op[0:4] == "1011":  # GET or PUT
            return op.split()[0] + reg1 + op.split()[1] + "11111111"
        else:  # LD/ST
            if parts[2] in symbol_table.keys():
                addr = symbol_table[parts[2]][-9:]
            else:
                addr = hex_to_bin(parts[2])[-9:]
            return op + reg1 + addr
        return "ERROR"


def vm_assemble(fname):
    translated = []
    sym_tab = {}
    line_num = 0
    ln = 0
    with open(fname, 'r') as f:
        for line in f:  # first pass to create symbol table
            if line[0] != ';':
                parts = line.upper().split("\t")
                # print(f"DEBUG: {parts}")
                label = parts[0]
                op = parts[1].strip()
                if label != '':
                    sym_tab.update({label: int_to_bin(ln)})
                if op == ".ASCII":
                    ln += len(parts[2].strip())
                elif op == ".BLOCK":
                    ln += int(parts[2].strip()) - 1
                elif op == ".ORIG":
                    ln += hex_to_int(parts[2].strip()) - 1
                ln += 1
    with open(fname, 'r') as f:
        for line in f:
            if line[0] != ';':
                parts = line.upper().split("\t")
                # label = parts[0]
                op = parts[1].strip()  # .upper() allows for .end, get, etc. for convenience
                # try:
                if op == ".ORIG":
                    # translated = [hex_to_bin(parts[2].strip())] + translated
                    line_num += hex_to_int(parts[2].strip())
                elif op == ".END":
                    translated.append("0000000000000000")
                    line_num += 1
                    break
                elif op == ".SET":
                    translated.append(int_to_bin(int(parts[2].strip())))
                    line_num += 1
                elif op == ".FILL":
                    translated.append(hex_to_bin(parts[2].strip()))
                    line_num += 1
                elif op == ".ASCII":
                    for char in parts[2].strip():
                        translated.append(ascii_to_bin(char))
                        line_num += 1
                    translated.append("0000000000000000")
                    line_num += 1
                elif op == ".BLOCK":
                    for i in range(int(parts[2].strip())):
                        translated.append("0000000000000000")
                        line_num += 1
                else:
                    # print(f"DEBUG: op = {op}\nparts = {parts}")
                    parts.append("")
                    translated.append(assemble_line(op + " " + parts[2], sym_tab))
                    line_num += 1
                # except:  # if assembling the line is unsuccessful
                # raise AssemblyException(f"Assembly Error on line {line_num}")
                # else:  # if assembling the line was successful
    print(translated)
    with open(fname[:-4] + ".eoc" if "." in fname else fname + ".eoc", 'w') as nf:
        for line in translated:
            nf.write(line + "\n")


def dump_mem():
    addr = bin_to_int(instr_pt)
    page = int_to_bin(addr)[0:7]
    # print(f"page: {page}")
    for i in range(2 ** 9):
        # print(int_to_bin(i)[7:])
        address = bin_to_int(page + int_to_bin(i)[7:])
        mem = memory[address]
        print(f"{int_to_hex(address)}: {mem[0:4]} {mem[4:8]} {mem[8:12]} {mem[12:16]}")


def dump_reg():
    for i in range(len(registers)):
        print(f"R{i}: {registers[i]}")


def clean_state():
    print("Instruction Pointer: " + instr_pt)
    print("Instruction Register: " + instr_reg)
    print(f"NZP = {nzp[0]} {nzp[1]} {nzp[2]}")
    print("CPU Registers:")
    dump_reg()
    print("Memory contents:")
    addr = bin_to_int(instr_pt)
    page = int_to_bin(addr)[0:7]
    # print(f"page: {page}")
    for i in range(2 ** 9):
        # print(int_to_bin(i)[7:])
        address = bin_to_int(page + int_to_bin(i)[7:])
        mem = memory[address]
        if not mem == "0000000000000000":
            print(f"{int_to_hex(address)}: {mem[0:4]} {mem[4:8]} {mem[8:12]} {mem[12:16]}")


def print_state():
    print("Instruction Pointer: " + instr_pt)
    print("Instruction Register: " + instr_reg)
    print(f"NZP = {nzp[0]} {nzp[1]} {nzp[2]}")
    print("CPU Registers:")
    dump_reg()
    print("Memory contents:")
    dump_mem()


def decode(instr):
    global instr_pt
    op = instr[0:4]
    if op_codes[op] == "HALT":
        vm_halt()
    elif op_codes[op] == "ADD":
        vm_add(instr)
    elif op_codes[op] == "AND":
        vm_and(instr)
    elif op_codes[op] == "NOT":
        vm_not(instr)
    elif op_codes[op] == "LD":
        vm_ld(instr)
    elif op_codes[op] == "LDI":
        vm_ldi(instr)
    elif op_codes[op] == "LDR":
        vm_ldr(instr)
    elif op_codes[op] == "ST":
        vm_st(instr)
    elif op_codes[op] == "STI":
        vm_sti(instr)
    elif op_codes[op] == "STR":
        vm_str(instr)
    elif op_codes[op] == "GET":
        vm_get(instr)
    elif op_codes[op] == "PUT":
        vm_put(instr)
    elif op_codes[op] == "BR":
        vm_br(instr)
    elif op_codes[op] == "JMP":
        vm_jmp_jsr(instr)
    elif op_codes[op] == "JMPR":
        vm_jmpr_jsrr(instr)
    elif op_codes[op] == "RET":
        vm_ret()
    else:
        print("OP code not recognized")  # commenting this bit out fixed subroutine.eoc
    if not (op_codes[op] == "BR" or op_codes[op] == "JMP" or op_codes[op] == "JMPR"):  # or op_codes[op] == "RET"):
        instr_pt = int_to_bin(bin_to_int(instr_pt) + 1)


def run_vm():
    global instr_reg, instr_pt, run
    run = True
    while run:
        ip_int = bin_to_int(instr_pt)
        instr_reg = memory[ip_int].strip()
        # print(f"DEBUG: Instruction {int_to_hex(ip_int)}: {instr_reg}")
        decode(instr_reg)
        # print(f"DEBUG: P={p}")
    print("\n---")


############# start of shell class ##############
class shell(Cmd):
    prompt = ">> "
    intro = "===============================\n" \
            "EOC-21 16-Bit Virtual Machine\n" \
            "-------------------------------\n" \
            "Copyright 2021 Cameron Woodbury\n" \
            "-------------------------------\n" \
            "Enter '?' for help\n" \
            "==============================="

    def do_exit(self, args):
        print("Exiting...")
        return True

    def help_exit(self):
        print("Exits the VM.\nShortcuts: x ctrl-D")

    def do_reboot(self, args):
        print("REBOOTING... ", end="")
        initialize()
        print("Reinitialized all states to 0000000000000000")

    def help_reboot(self):
        print("Reinitialize the VM with all states to 0.\n"
              "Shortcut: rb")

    def do_goto(self, args):
        global instr_pt, instr_reg
        if len(args.strip()) == 5:  # hex
            instr_pt = hex_to_bin(args.strip())
        elif len(args.strip()) == 16:  # bin
            instr_pt = args.strip()
        else:
            try:
                instr_pt = int_to_bin(int(args.strip()))
            except:
                print("GOTO failed")
                return
        instr_reg = memory[bin_to_int(instr_pt)]

    def help_goto(self):
        print("For convenience, sets Instruction Pointer address given (accepts int, hex, or bin (16-bit string))\n "
              "and sets Instruction Register to associated value in memory")

    def do_IP(self, args):
        print(f"Instruction Pointer: {instr_pt}\nInstruction Register: {instr_reg}")

    def help_IP(self):
        print("Prints current contents of the Instruction Pointer and Register")

    def do_LOAD(self, args):
        load(args)

    def help_LOAD(self):
        print("Load binary instructions from fname, starting at addr.\n"
              "fname: .txt (or equivalent) file with 16-bit binary instructions.\n"
              "addr: memory address, formatted as Int, Hex, or Bin.\n"
              "Pages start at (int): 0, 256, 512, 768, 1024,...; 256*x, x: int = 0-255\n"
              "            Or (hex): xXX00, X = 00-FF")

    def do_ASSEMBLE(self, args):
        vm_assemble(args)

    def help_ASSEMBLE(self):
        print("Translates a file written in EOC assembly to its associated binary instructions.\n"
              "Will accept any basic text file (convention: .amb -> .eoc)\n"
              "Format: ASSEMBLE <fname>")

    def do_DUMP(self, args):
        dump_mem()

    def help_DUMP(self):
        print(
            "Prints the contents of the memory page where the Instruction Pointer is located (xXX00 - xYY00; Y = X+1).")

    def do_REGISTERS(self, args):
        dump_reg()

    def help_REGISTERS(self):
        print("Prints the contents of the CPU registers (R0 - R7).")

    def do_STATE(self, args):
        print_state()

    def help_STATE(self):
        print("Prints the current contents of the active page of memory,\n"
              "CPU registers, NZP registers, & Instruction Pointer and Register.\n"
              "Shortcut: s")

    def do_CDUMP(self, args):
        clean_state()

    def help_CDUMP(self):
        print("Same as state, but filters out NULL memory ('0000000000000000')\n"
              "Shortcut: c")

    def do_RUN(self, args):
        run_vm()

    def help_RUN(self):
        print("Runs the Fetch, -----, ----- cycle.\n"
              "Shortcut: r")

    def do_GET(self, args):
        if len(args) > 3:
            vm_get("1010" + args[0:3] + args[3:].strip() + "11111111")
        else:
            print("Format: GET XXX Y (use 'help GET' for details)")

    def help_GET(self):
        print("Take user input and store in CPU register\n"
              ">> GET XXX Y \n"
              "XXX: 3-bit register (R0-R7)\n"
              "Y: 0 - 16-bit code, 1 - Ascii character")

    def do_PUT(self, args):
        if len(args) > 3:
            vm_put("1011" + args[0:3] + args[3:].strip() + "11111111")
            print("")
        else:
            print("Format: PUT XXX Y (use 'help PUT' for details)")

    def help_PUT(self):
        print("Put contents of CPU register to screen/console\n "
              ">> PUT XXX Y \n "
              "XXX: 3-bit register (R0-R7)\n "
              "Y: 0 - 16-bit code, 1 - Ascii character")

    def default(self, args):
        if args.lower() == 'x' or args == "EXIT":
            return self.do_exit(args)
        elif args.lower() == "rb":
            return self.do_reboot(args)
        elif "load" in args.lower()[:4]:
            return self.do_LOAD(args[4:])
        elif "assemble" in args.lower()[:8]:
            return self.do_ASSEMBLE(args[8:].strip())
        elif args == "run" or args.lower() == "r":
            return self.do_RUN(args)
        elif args == 'cdump' or args.lower() == "c":
            return self.do_CDUMP(args)
        elif args == "ip":
            return self.do_IP(args)
        elif args == "state" or args.lower() == "s":
            return self.do_STATE(args)

        print("Command not recognized: {}".format(args))

    do_EOF = do_exit
    help_EOF = help_exit


############# end of shell class ##############

if __name__ == "__main__":
    initialize()
    # TEST
    # START INTERACTIVE VM SHELL
    shell().cmdloop()
