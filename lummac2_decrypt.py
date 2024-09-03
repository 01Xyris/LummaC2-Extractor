import re
import argparse
from typing import List, Optional
from speakeasy import Speakeasy

__version__ = "1.0.0"
__author__ = "Xyris"
__github__ = "https://github.com/01Xyris/"
__twitter__ = "https://x.com/01Xyris"

class MemoryChunk:
    """Represents a chunk of memory with its offset and value."""

    def __init__(self, offset: int, esp_offset: int, value: int):
        self.offset = offset
        self.esp_offset = esp_offset
        self.value = value

class LummaC2Analyzer:
    """Analyzes binary files for encrypted URLs in LummaC2."""

    START_SEARCH = 0x400000
    END_SEARCH = 0x500000
    CHUNK_SIZE = 0x1000
    
    DECRYPT_CONSTANT_PATTERN = rb'\x0f\xb6\x4c\x0c\x10\x05'
    DECRYPT_AL_PATTERN = rb'\x8b\x84\x24\x10\x01\x00\x00\x04'

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.emulator = Speakeasy()
        self.memory_dump = bytearray()
        self.start_address = self.START_SEARCH
        self.decrypt_constant = None
        self.decrypt_al = None

    @staticmethod
    def add_uint_to_buffer(buffer: bytearray, value: int) -> None:
        """Adds an unsigned integer to a buffer in little-endian format."""
        if value == 0:
            buffer.append(0)
            return
        while value:
            buffer.append(value & 0xFF)
            value >>= 8

    @classmethod
    def encode_buffer(cls, values: List[int]) -> bytearray:
        """Encodes a list of integers into a bytearray."""
        buffer = bytearray()
        for value in values:
            cls.add_uint_to_buffer(buffer, value)
        return buffer

    def emulate_and_dump_memory(self) -> None:
        """Emulates the binary and dumps its memory."""
        module = self.emulator.load_module(self.file_path)
        self.emulator.run_module(module)
        
        for addr in range(self.START_SEARCH, self.END_SEARCH, self.CHUNK_SIZE):
            try:
                chunk = self.emulator.mem_read(addr, self.CHUNK_SIZE)
                self.memory_dump.extend(chunk)
            except Exception:
                pass  # Silently skip unreadable memory regions

    def find_pattern_and_extract(self, pattern: bytes, bytes_to_extract: int = 4) -> Optional[int]:
        """Finds a pattern in memory dump and extracts following bytes as an integer."""
        match = re.search(pattern, self.memory_dump)
        if match and match.end() + bytes_to_extract <= len(self.memory_dump):
            start_index = match.end()
            return int.from_bytes(self.memory_dump[start_index:start_index + bytes_to_extract], byteorder='little')
        return None

    @staticmethod
    def find_mov_patterns(data: bytes) -> List[MemoryChunk]:
        """Finds all MOV instruction patterns in the given data."""
        pattern = re.compile(rb'\xC7\x44\x24([\x10-\x78])([\x00-\xFF]{4})')
        return [MemoryChunk(match.start(), match.group(1)[0], int.from_bytes(match.group(2), byteorder='little'))
                for match in re.finditer(pattern, data)]

    def decrypt_large_block(self, data: bytes) -> bytearray:
        """Decrypts a large block of data using extracted decrypt values."""
        if self.decrypt_constant is None or self.decrypt_al is None:
            raise ValueError("Decrypt values not set. Call extract_decrypt_values() first.")
        decrypted = bytearray(data)
        for i in range(len(decrypted)):
            temp = (i + self.decrypt_constant) ^ decrypted[i]
            decrypted[i] = (temp & 0xFF) + self.decrypt_al & 0xFF
        return decrypted

    def process_data(self, data: bytes) -> str:
        """Processes and decrypts data, converting to a readable string."""
        decrypted_data = self.decrypt_large_block(data)
        return ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in decrypted_data)

    @staticmethod
    def fix_url_string(s: str) -> str:
        """Fixes common issues in decrypted URL strings."""
        s = s.replace('.', '')
        return s.replace('steamcommunitycom', 'steamcommunity.com')

    def extract_decrypt_values(self) -> None:
        """Extracts decrypt values from memory dump."""
        self.decrypt_constant = self.find_pattern_and_extract(self.DECRYPT_CONSTANT_PATTERN)
        self.decrypt_al = self.find_pattern_and_extract(self.DECRYPT_AL_PATTERN, 1)
        if self.decrypt_constant is None or self.decrypt_al is None:
            raise ValueError("Failed to extract decrypt values")

    @staticmethod
    def decrypt_char(char: str) -> str:
        """Decrypts a single character using LummaC2's algorithm."""
        bVar18 = ord(char)
        if (bVar18 + 0x9f) & 0xFF < 0x1a:
            iVar11 = (bVar18 & 0x1e) - (~bVar18 & 1)
            uVar19 = iVar11 + 0xf
            if uVar19 > 0x19:
                uVar19 = (iVar11 - 0xb) & 0xFF
            bVar18 = (uVar19 + 0x61) & 0xFF
        return chr(bVar18)

    @classmethod
    def decrypt_string(cls, encrypted: str) -> str:
        """Decrypts a string using LummaC2's algorithm."""
        return ''.join(cls.decrypt_char(c) for c in encrypted)

    def analyze(self) -> None:
        """Performs the main analysis of the binary file."""
        print(f"[*] Analyzing file: {self.file_path}")
        self.emulate_and_dump_memory()
        if not self.memory_dump:
            print("[!] Failed to dump memory.")
            return

        self.extract_decrypt_values()
        mov_matches = self.find_mov_patterns(self.memory_dump)
        self._process_chunks(mov_matches)

    def _process_chunks(self, mov_matches: List[MemoryChunk]) -> None:
        """Processes chunks of memory to find and decrypt URLs."""
        current_chunk = []
        chunk_start_address = self.start_address

        for chunk in mov_matches:
            if chunk.esp_offset == 0x10:
                self._process_single_chunk(current_chunk, chunk_start_address)
                current_chunk = []
                chunk_start_address = self.start_address + chunk.offset

            if 0x10 <= chunk.esp_offset <= 0x78:
                current_chunk.append(chunk)

        # Process the last chunk if it exists
        self._process_single_chunk(current_chunk, chunk_start_address)

    def _process_single_chunk(self, chunk: List[MemoryChunk], start_address: int) -> None:
        """Processes a single chunk of memory, decrypting and displaying URLs if found."""
        if not chunk:
            return

        chunk_values = [c.value for c in chunk]
        chunk_data = self.encode_buffer(chunk_values)
        decrypted_string = self.process_data(chunk_data)

        if decrypted_string.startswith('h.t.t.p.s'):
            print("\n[+] Found encrypted URL:")
            for c in chunk:
                print(f"    Offset 0x{self.start_address + c.offset:08x}: ESP+0x{c.esp_offset:02x} -> 0x{c.value:08x}")

            fixed_string = self.fix_url_string(decrypted_string)
            print(f"\n[+] Decrypted URL: {fixed_string}")

            steam_name = input("Enter the SteamName to decrypt (or press Enter to skip): ").strip()
            if steam_name:
                decrypted_name = self.decrypt_string(steam_name)
                print(f"\n[+] Final URL: {decrypted_name}")
            else:
                print("\n[!] SteamName decryption skipped.")

def print_credits() -> None:
    """Prints the credits information."""
    print(f"LummaC2 Extractor v{__version__}")
    print(f"Author: {__author__}")
    print(f"GitHub: {__github__}")
    print(f"Twitter: {__twitter__}")
    print("=" * 40)

def main() -> None:
    """Main function to run the LummaC2 Binary Analyzer."""
    parser = argparse.ArgumentParser(description="LummaC2 Extractor")
    parser.add_argument("file_path", help="Path to the binary file to analyze")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    print_credits()

    analyzer = LummaC2Analyzer(args.file_path)
    analyzer.analyze()

if __name__ == "__main__":
    main()
