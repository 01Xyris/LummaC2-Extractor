# xor_decrypt and extract_b64_strings are from RussianPanda (https://x.com/RussianPanda9xx). Thanks, 🐼! 


import pefile
import distorm3
import binascii
import sys
import base64
import json
import re
from collections import namedtuple
from typing import List, Optional, Tuple

# Constants
MAX_ITERATIONS = 2000
VALID_ASCII_RANGE = range(32, 127)
TEXT_SECTION_NAME = b'.text'
LUMMA_C2_MARKER = "LummaC2 Build:"

# Named tuple to store encrypted sequence details
EncryptedSequence = namedtuple('EncryptedSequence', [
    'start_address', 'encrypted_values', 'initial_key', 'key_modifier', 'decrypted_string', 'disassembly'
])

class AnalysisState:
    def __init__(self):
        self.reset()

    def reset(self, sequence_start_address=None, initial_key=None, key_modifier=None):
        self.immediate_values = []
        self.sequence_start_address = sequence_start_address
        self.initial_key = initial_key
        self.key_modifier = key_modifier
        self.current_instructions = []
        self.in_mov_sequence = False
        self.first_add = None
        self.continue_search_for_add = False


# Helper function to filter printable characters
def sanitize_string(decoded_str: str) -> str:
    return ''.join(filter(lambda c: 32 <= ord(c) <= 126, decoded_str))


# Decrypts an encrypted string based on provided keys
def decrypt_encrypted_string(encrypted_hex: str, initial_key: int, key_modifier: int, max_iterations: Optional[int] = None) -> bytearray:
    encrypted_bytes = bytearray(binascii.unhexlify(encrypted_hex))
    
    # Ensure max_iterations doesn't exceed the length of encrypted_bytes
    max_iterations = min(max_iterations or len(encrypted_bytes), len(encrypted_bytes))
    
    decrypted_data = bytearray()

    for index in range(max_iterations):
        original_byte = encrypted_bytes[index]
        negated_value = (~original_byte) & 0xFF
        intermediate_value = (
            index + original_byte + initial_key +
            (negated_value - ((index + initial_key) | negated_value)) * 2
        ) & 0xFFFFFFFF
        decrypted_byte = (intermediate_value + key_modifier) & 0xFF
        decrypted_data.append(decrypted_byte)

    return decrypted_data



# Determines if a string contains meaningful characters
def is_meaningful_string(s: str) -> bool:
    return sum(1 for c in s if c.isalnum()) >= 2


# Attempts to decode a byte sequence into a readable string using multiple encodings
def attempt_string_decoding(data: bytes) -> Optional[str]:
    encodings = ['utf-16', 'utf-8', 'latin1']
    for encoding in encodings:
        try:
            decoded_str = sanitize_string(data.decode(encoding).strip('\x00'))
            if is_meaningful_string(decoded_str):
                return decoded_str
        except UnicodeDecodeError:
            continue
    return None


# Extracts URLs from a decoded string
def extract_urls(data: str) -> List[str]:
    url_pattern = re.compile(r'(https?://[^\s]+)')
    return url_pattern.findall(data)


# Extracts Base64 encoded strings from a file
def extract_b64_strings(file_path: str, min_length: int = 60, max_length: int = 100) -> List[str]:
    try:
        with open(file_path, 'rb') as file:
            file_content = file.read()
    except FileNotFoundError as e:
        raise FileNotFoundError(f"File not found: {file_path}") from e

    try:
        data = file_content.decode('utf-8')
    except UnicodeDecodeError:
        data = file_content.decode('latin1')

    pattern = re.compile(r'(?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)')
    matches = pattern.findall(data)
    return [match for match in matches if min_length <= len(match) <= max_length]


# Decrypts Base64-encoded data using XOR and extracts a domain or readable string
def xor_decrypt(encoded_str: str) -> Optional[str]:
    try:
        dec_data = base64.b64decode(encoded_str)
        key = dec_data[32:]
        data = dec_data[:32]

        decrypted = bytearray(data[i] ^ key[i % len(key)] for i in range(len(data)))

        decrypted_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in decrypted)
        domain_match = re.search(r'\.[a-z]{2,8}', decrypted_str)

        if domain_match:
            return decrypted_str[:domain_match.end()]
        return decrypted_str
    except Exception as e:
        raise ValueError(f"Error decrypting data: {e}")


# Parses an instruction and extracts relevant details
def parse_instruction(instruction) -> Tuple[bool, bool, List[str], str]:
    is_memory_dword = any(op.type == distorm3.OPERAND_MEMORY and op.size == 32 for op in instruction.operands)
    has_immediate_value = any(op.type == distorm3.OPERAND_IMMEDIATE for op in instruction.operands)

    little_endian_immediates = [get_little_endian_hex(op.value) for op in instruction.operands if op.type == distorm3.OPERAND_IMMEDIATE]
    formatted_operands = ', '.join(format_operand(op) for op in instruction.operands)

    return is_memory_dword, has_immediate_value, little_endian_immediates, formatted_operands


# Helper to format operands
def format_operand(operand) -> str:
    if operand.type == distorm3.OPERAND_MEMORY and operand.size == 32:
        return f"[{operand.base} + 0x{operand.disp:X}]"
    elif operand.type == distorm3.OPERAND_REGISTER:
        return f"{operand.name}"
    elif operand.type == distorm3.OPERAND_IMMEDIATE:
        return f"0x{operand.value:X}"
    return ""


# Converts a value into a little-endian hex representation
def get_little_endian_hex(value: int) -> str:
    if value < 0:
        return ""
    little_endian_bytes = value.to_bytes(4, byteorder='little')
    return ''.join(f'{b:02x}' for b in little_endian_bytes)


# Processes an instruction and updates the analysis state accordingly
def process_instruction(instruction, state: AnalysisState):
    is_memory_dword, has_immediate_value, little_endian_immediates, formatted_operands = parse_instruction(instruction)
    state.current_instructions.append(f"{hex(instruction.address)}: {instruction.mnemonic} {formatted_operands}")

    if instruction.mnemonic == 'MOV' and is_memory_dword and has_immediate_value:
        if not state.sequence_start_address:
            state.sequence_start_address = instruction.address
        state.immediate_values.extend(little_endian_immediates)
        state.in_mov_sequence = True

    elif instruction.mnemonic == 'ADD' and len(instruction.operands) > 1 and state.in_mov_sequence:
        if state.initial_key is None and instruction.operands[1].type == distorm3.OPERAND_IMMEDIATE:
            state.initial_key = instruction.operands[1].value
            state.first_add = instruction.operands[1].value
        elif state.key_modifier is None and instruction.operands[1].type == distorm3.OPERAND_IMMEDIATE:
            if state.first_add is not None and state.first_add != instruction.operands[1].value:
                state.key_modifier = instruction.operands[1].value
                state.continue_search_for_add = False
            else:
                state.continue_search_for_add = True

    if state.continue_search_for_add:
        if instruction.mnemonic == 'ADD' and len(instruction.operands) > 1:
            if instruction.operands[1].type == distorm3.OPERAND_IMMEDIATE and instruction.operands[1].value != state.first_add:
                state.key_modifier = instruction.operands[1].value
                state.continue_search_for_add = False


# Analyzes a potential encrypted sequence and extracts URLs, if present
def analyze_potential_encrypted_sequence(state: AnalysisState, c2_urls: List[str], asm_file: str = 'strings.asm') -> Optional[EncryptedSequence]:
    state.immediate_values = [val for val in state.immediate_values if val != '00000000']
    if state.immediate_values:
        encrypted_string = ''.join(state.immediate_values)

        # Ensure Initial Key is at least 2 bytes (16 bits, 4 hex digits)
        if state.initial_key is not None and len(hex(state.initial_key)[2:]) >= 4:
            decrypted_data = decrypt_encrypted_string(encrypted_string, state.initial_key, state.key_modifier, MAX_ITERATIONS)
            decoded_string = attempt_string_decoding(decrypted_data)

            if decoded_string:
                # Check for "LummaC2 Build:" in the decoded string
                if LUMMA_C2_MARKER in decoded_string:
                    build_info = decoded_string.split(LUMMA_C2_MARKER)[-1].strip()
                    lumma_c2_json = json.dumps({"Version": build_info}, indent=4)
                    print("\nExtracted LummaC2 Build Info:\n", lumma_c2_json)

                # Extract URLs from the decrypted string
                urls = extract_urls(decoded_string)
                if urls:
                    c2_urls.extend(urls)
                    return EncryptedSequence(
                        start_address=hex(state.sequence_start_address),
                        encrypted_values=state.immediate_values,
                        initial_key=hex(state.initial_key),
                        key_modifier=hex(state.key_modifier),
                        decrypted_string=decoded_string + "\nExtracted URLs: " + ", ".join(urls),
                        disassembly=state.current_instructions
                    )
                else:
                    with open(asm_file, 'a', encoding='utf-8') as asm_file_obj:
                        asm_file_obj.write(f"Start Address: {hex(state.sequence_start_address)}\n")
                        asm_file_obj.write(f"Initial Key: {hex(state.initial_key)}\n")
                        asm_file_obj.write(f"Key Modifier: {hex(state.key_modifier)}\n")
                        asm_file_obj.write(f"Decrypted String: {decoded_string}\n")
                        asm_file_obj.write("\n" + "-"*50 + "\n\n")
    return None


# Analyzes a PE section and extracts potential encrypted sequences
def analyze_pe_section(binary_data: bytes, base_address: int, c2_urls: List[str]) -> List[EncryptedSequence]:
    disassembler = distorm3.DecomposeGenerator(base_address, binary_data, distorm3.Decode32Bits)
    state = AnalysisState()
    encrypted_sequences = []

    for instruction in disassembler:
        if not instruction.valid:
            continue
        process_instruction(instruction, state)

        if state.immediate_values and state.initial_key is not None and state.key_modifier is not None:
            sequence = analyze_potential_encrypted_sequence(state, c2_urls)
            if sequence:
                encrypted_sequences.append(sequence)
            state.reset()

    return encrypted_sequences


# Analyzes the given PE file for encrypted sequences and Base64-encoded data
def analyze_pe_file(file_path: str):
    pe = pefile.PE(file_path)
    text_section = next(section for section in pe.sections if TEXT_SECTION_NAME in section.Name)
    section_start = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress
    section_end = section_start + text_section.Misc_VirtualSize
    pe_image = pe.get_memory_mapped_image()
    section_data = pe_image[section_start - pe.OPTIONAL_HEADER.ImageBase: section_end - pe.OPTIONAL_HEADER.ImageBase]

    print(f"Analyzing .text section: {hex(section_start)} - {hex(section_end)}")

    c2_urls = []
    encrypted_sequences = analyze_pe_section(section_data, section_start, c2_urls)

    base64_strs = extract_b64_strings(file_path)
    for encoded_str in base64_strs:
        result = xor_decrypt(encoded_str)
        if result:
            c2_urls.append(f"URL: {result}")

    if c2_urls:
        json_output = json.dumps(c2_urls, indent=4)
        print("\nDecrypted C2 URLs:\n", json_output)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pe_analyzer.py <path_to_pe_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    analyze_pe_file(file_path)
