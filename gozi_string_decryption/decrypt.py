import pefile
import struct


def get_bss(pe_file_path):
    section_name = ".bss"
    pe = pefile.PE(pe_file_path)
    for section in pe.sections:
        current_section_name = section.Name.decode().strip('\x00')
        if current_section_name == section_name:
            return section.VirtualAddress, section.PointerToRawData, section.SizeOfRawData


def get_key(date, bss_va, random):
    # Apr 26 2022
    first_dword_date = struct.unpack("<I", date[0:4])[0]
    second_dword_date = struct.unpack("<I", date[4:8])[0]
    key = first_dword_date + second_dword_date + bss_va + random - 1
    return key


def decrypt(data, key):
    index = 0
    dec_bss = b""
    prev_dword = 0
    for index in range(0, len(data), 4):
        curr_dword = struct.unpack("<I", data[index:index + 4])[0]
        if curr_dword:
            dec_bss += struct.pack("I", (curr_dword +
                                   (prev_dword - key)) & 0xffffffff)
            prev_dword = curr_dword
        else:
            dec_bss += struct.pack("I", 0x0)
    return dec_bss


if __name__ == "__main__":
    file_path = ".\\unpacked_gozi.dll"
    sample_data = open(file_path, 'rb').read()
    date = "Apr 26 2022".encode('ascii')
    random = 0x17
    bss_va, bss_addr, bss_size = get_bss(file_path)
    bss_data = sample_data[bss_addr: bss_addr + bss_size]
    for random in range(0, 20):
        key = get_key(date, bss_va, random)
        decrypted_bss = decrypt(bss_data, key)
        if b"NTDLL" in decrypted_bss:
            print("Correct Key: " + hex(key))
            break
    decrypted_dll = sample_data[:bss_addr] + \
        decrypted_bss + sample_data[bss_addr + bss_size:]
    with open(".\\decripted_gozi.dll", 'wb') as dest_file:
        dest_file.write(decrypted_dll)
