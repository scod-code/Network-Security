class AntiTrafficAnalysis:
    """
    TRANSEC / Traffic Analysis Defense:
    - Implements deterministic block padding (e.g. 512 bytes)
    - Prevents packet size fingerprinting, metadata leakage, and length-based traffic analysis
    """

    @staticmethod
    def pad_payload(data: bytes, block_size: int = 512) -> bytes:
        """
        Pads data with 4-byte big-endian original length + padding bytes
        Format: [Original Length (4B)] + [Data] + [Random Padding]
        Total length is rounded up to the nearest multiple of block_size.
        """
        orig_len = len(data)
        len_header = orig_len.to_bytes(4, byteorder="big")
        unpadded = len_header + data
        
        pad_needed = (block_size - (len(unpadded) % block_size)) % block_size
        if pad_needed == 0 and len(unpadded) == 0:
            pad_needed = block_size
            
        import os
        padding = os.urandom(pad_needed)
        return unpadded + padding

    @staticmethod
    def strip_padding(padded_data: bytes) -> bytes:
        """
        Extracts original payload from padded block
        """
        if len(padded_data) < 4:
            raise ValueError("Padded data too short to contain length header")
            
        orig_len = int.from_bytes(padded_data[:4], byteorder="big")
        if len(padded_data) < 4 + orig_len:
            raise ValueError(f"Corrupted padding length header: declared {orig_len}, available {len(padded_data)-4}")
            
        return padded_data[4:4 + orig_len]
