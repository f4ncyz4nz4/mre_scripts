import pyghidra
import base64


def key_scheduling(key):
    sched = [i for i in range(0, 256)]

    i = 0
    for j in range(0, 256):
        i = (i + sched[j] + key[j % len(key)]) % 256

        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp

    return sched


def stream_generation(sched):
    stream = []
    i = 0
    j = 0
    while True:
        i = (1 + i) % 256
        j = (sched[i] + j) % 256

        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp

        yield sched[(sched[i] + sched[j]) % 256]


def decrypt(ciphertext, key):
    key = [ord(char) for char in key]

    sched = key_scheduling(key)
    key_stream = stream_generation(sched)

    plaintext = ''
    for char in ciphertext:
        dec = str(chr(char ^ next(key_stream)))
        plaintext += dec

    return plaintext


if __name__ == '__main__':
    pyghidra.start(verbose=True)

    if not pyghidra.started():
        print("Not Started")
        exit(0)

    binary_path = r"C:\\Users\\mre\\Desktop\\oski\\unpacked_oski.exe"
    project_location = r"C:\\Users\\mre\\Desktop\\oski"
    project_name = r"oski"
    key = "056139954853430408"
    addr = 0x422f70

    with pyghidra.open_program(binary_path=binary_path, project_location=project_location, project_name=project_name) as flat_api:

        program = flat_api.getCurrentProgram()
        reference_manager = program.getReferenceManager()

        decrypt_func_addr = flat_api.toAddr(addr)

        for ref in reference_manager.getReferencesTo(decrypt_func_addr):
            from_ref = ref.getFromAddress()

            push_instr = flat_api.getInstructionBefore(from_ref)
            start_b64_str = flat_api.toAddr(
                push_instr.getOpObjects(0)[0].toString())

            b64_str = ""
            i = 0
            b = flat_api.getByte(start_b64_str)

            while b != 0x0:
                b64_str += chr(b)
                i += 1
                b64_str_addr = start_b64_str.add(i)
                b = flat_api.getByte(b64_str_addr)

            encrypted_str = base64.b64decode(b64_str)

            decrypted_str = decrypt(encrypted_str, key)

            flat_api.setBytes(start_b64_str, list(
                decrypted_str.encode("utf-8")) + [0])
